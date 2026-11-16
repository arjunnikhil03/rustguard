//! Software Composition Analysis (SCA) for Maven projects — dependency
//! parsing + known-vulnerability lookup via the [OSV.dev](https://osv.dev)
//! API.
//!
//! This is the "Maven dependency scanner" piece of the revised Phase 4
//! scope (GitLab CI compatibility + dependency scanning, in place of IDE
//! integration). It's intentionally separate from `rustguard-taint` and
//! `rustguard-rules`: SCA answers "are any of your *dependencies* known-
//! vulnerable," which is a completely different question from "does your
//! *own code* have a bug."
//!
//! ## What this does
//! 1. Parses a `pom.xml`'s `<dependencies>` block (direct dependencies
//!    only — see limitations below), resolving simple `${property}`
//!    placeholders against the same file's `<properties>` block.
//! 2. Queries OSV.dev's `/v1/query` endpoint once per dependency
//!    (`{"package": {"name": "groupId:artifactId", "ecosystem": "Maven"},
//!    "version": "..."}`) and turns any returned vulnerabilities into
//!    `Finding`s.
//!
//! ## Known limitations (documented, not silent)
//! - **Direct dependencies only.** This parses the `<dependencies>` block
//!   literally present in the given `pom.xml` — it does not resolve the
//!   full transitive dependency tree the way `mvn dependency:tree` would.
//!   A vulnerable *transitive* dependency pulled in by a direct one will
//!   not be found. Wiring up an actual `mvn dependency:tree` invocation
//!   (shelling out, requiring Maven + network access to resolve the repo)
//!   is the natural next step if transitive coverage matters to you —
//!   deliberately not done here to avoid requiring a Maven installation
//!   just to run a security scan.
//! - **Single-module only.** Multi-module Maven projects (parent POM +
//!   child modules with `<relativePath>`) are not walked — point this at
//!   each module's `pom.xml` individually for now.
//! - **Property resolution is shallow**: only `${x}` references resolved
//!   against the *same file's* `<properties>` block are handled. A version
//!   inherited from a parent POM in a different file, or a property
//!   defined in a parent, will not resolve and that dependency's version
//!   check will be skipped (with a warning), not silently wrong.
//! - **Per-dependency HTTP calls, no retries/backoff.** A network failure
//!   for one dependency logs a warning and skips just that dependency —
//!   it does not abort the whole scan. This has been *implemented* but
//!   **not live-tested against the real OSV.dev API** in the environment
//!   this was built in (its outbound network is restricted to a small
//!   allowlist that doesn't include `api.osv.dev`). The request/response
//!   shape matches OSV's documented API; verify it against the real
//!   endpoint in your own environment (e.g. your GitLab CI runner, which
//!   will have normal outbound internet access) before relying on it.
//! - **Severity mapping is best-effort.** OSV entries vary in how they
//!   report severity (some have `database_specific.severity` as a plain
//!   string like `"HIGH"`; others only have a CVSS vector string). This
//!   maps the plain-string form when present and otherwise defaults to
//!   `Medium` rather than guessing from a CVSS vector — a documented
//!   under/over-approximation, not silent misclassification.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rustguard_ir::{Finding, Severity};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MavenDependency {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    /// Best-effort 1-indexed line of the `<dependency>` block's opening tag.
    pub line: usize,
}

impl MavenDependency {
    pub fn coordinate(&self) -> String {
        format!("{}:{}", self.group_id, self.artifact_id)
    }
}

/// Parse the `<dependencies>` block of a single `pom.xml`, resolving
/// same-file `${property}` placeholders. See module docs for what this
/// does *not* do (transitive deps, multi-module, cross-file properties).
pub fn parse_pom_dependencies(pom_path: &Path) -> anyhow::Result<Vec<MavenDependency>> {
    let content = std::fs::read_to_string(pom_path)?;
    let properties = parse_properties(&content);

    let mut reader = Reader::from_str(&content);
    reader.trim_text(true);
    let mut buf = Vec::new();

    let mut path: Vec<String> = Vec::new();
    let mut deps = Vec::new();

    let mut cur_group = String::new();
    let mut cur_artifact = String::new();
    let mut cur_version = String::new();
    let mut cur_line = 1usize;
    let mut in_dependency = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                path.push(name.clone());

                if name == "dependency" && path == ["project", "dependencies", "dependency"] {
                    in_dependency = true;
                    cur_group.clear();
                    cur_artifact.clear();
                    cur_version.clear();
                    cur_line = byte_offset_to_line(&content, reader.buffer_position());
                }
            }
            Ok(Event::Text(t)) => {
                if in_dependency {
                    let text = t.unescape().unwrap_or_default().to_string();
                    match path.last().map(|s| s.as_str()) {
                        Some("groupId") => cur_group = text,
                        Some("artifactId") => cur_artifact = text,
                        Some("version") => cur_version = text,
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "dependency" && in_dependency {
                    in_dependency = false;
                    if !cur_group.is_empty() && !cur_artifact.is_empty() {
                        let resolved_version = resolve_property(&cur_version, &properties);
                        deps.push(MavenDependency {
                            group_id: cur_group.clone(),
                            artifact_id: cur_artifact.clone(),
                            version: resolved_version,
                            line: cur_line,
                        });
                    }
                }
                path.pop();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("error parsing {}: {e}", pom_path.display())),
            _ => {}
        }
        buf.clear();
    }

    Ok(deps)
}

fn parse_properties(content: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(content);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut properties = HashMap::new();
    let mut cur_prop_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                path.push(name.clone());
                if path.len() == 3 && path[0] == "project" && path[1] == "properties" {
                    cur_prop_name = Some(name);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(prop) = &cur_prop_name {
                    let text = t.unescape().unwrap_or_default().to_string();
                    properties.insert(prop.clone(), text);
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
                cur_prop_name = None;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    properties
}

/// Resolve a single `${property}` reference against the given map.
/// Anything else (a literal version, or a property we can't resolve) is
/// returned unchanged — the caller treats an unresolved `${...}` as a
/// signal to skip the vulnerability check for that dependency rather than
/// querying OSV with a garbage "version".
fn resolve_property(version: &str, properties: &HashMap<String, String>) -> String {
    if let Some(key) = version.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        if let Some(resolved) = properties.get(key) {
            return resolved.clone();
        }
    }
    version.to_string()
}

fn byte_offset_to_line(content: &str, byte_offset: usize) -> usize {
    content
        .as_bytes()
        .iter()
        .take(byte_offset.min(content.len()))
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
struct OsvDatabaseSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    url: String,
}

/// Query OSV.dev for each dependency and return a `Finding` per known
/// vulnerability found. A network failure for one dependency is logged to
/// stderr and skipped — it does not abort the batch. See module docs for
/// the important caveat that this hasn't been live-tested against the real
/// API from the sandbox this was built in.
pub fn check_vulnerabilities(pom_path: &Path, deps: &[MavenDependency]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for dep in deps {
        if dep.version.starts_with("${") {
            eprintln!(
                "rustguard-external: skipping {} — unresolved version placeholder '{}' \
                 (likely inherited from a parent POM not parsed here)",
                dep.coordinate(),
                dep.version
            );
            continue;
        }

        match query_osv(&dep.coordinate(), &dep.version) {
            Ok(vulns) => {
                for vuln in vulns {
                    findings.push(vuln_to_finding(pom_path, dep, &vuln));
                }
            }
            Err(e) => {
                eprintln!(
                    "rustguard-external: OSV lookup failed for {} {} — skipping ({e})",
                    dep.coordinate(),
                    dep.version
                );
            }
        }
    }

    findings
}

fn query_osv(coordinate: &str, version: &str) -> anyhow::Result<Vec<OsvVuln>> {
    let body = serde_json::json!({
        "version": version,
        "package": { "name": coordinate, "ecosystem": "Maven" }
    });

    let response = minreq::post("https://api.osv.dev/v1/query")
        .with_header("Content-Type", "application/json")
        .with_body(body.to_string())
        .with_timeout(15)
        .send()?;

    if response.status_code != 200 {
        anyhow::bail!("OSV API returned HTTP {}", response.status_code);
    }

    let parsed: OsvQueryResponse = serde_json::from_str(response.as_str()?)?;
    Ok(parsed.vulns)
}

fn vuln_to_finding(pom_path: &Path, dep: &MavenDependency, vuln: &OsvVuln) -> Finding {
    let severity = vuln
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(map_osv_severity_string)
        .unwrap_or(Severity::Medium);

    let summary = vuln
        .summary
        .clone()
        .or_else(|| vuln.details.clone())
        .unwrap_or_else(|| "No summary provided by OSV.".to_string());

    let fixed_versions = extract_fixed_versions(vuln);
    let fix_suggestion = if fixed_versions.is_empty() {
        format!(
            "No fixed version information available from OSV for {}. Check {} for guidance.",
            vuln.id,
            vuln.references.first().map(|r| r.url.as_str()).unwrap_or("the advisory")
        )
    } else {
        format!("Upgrade {} to version {} or later.", dep.coordinate(), fixed_versions.join(" / "))
    };

    Finding {
        rule_id: format!("sca-{}", vuln.id),
        severity,
        cwe: None, // OSV doesn't reliably provide CWE; documented gap, not a bug.
        message: format!("{} {} has a known vulnerability ({}): {summary}", dep.coordinate(), dep.version, vuln.id),
        file: pom_path.to_path_buf(),
        line: dep.line,
        snippet: format!("{}:{}:{}", dep.group_id, dep.artifact_id, dep.version),
        fix_suggestion: Some(fix_suggestion),
    }
}

fn extract_fixed_versions(vuln: &OsvVuln) -> Vec<String> {
    let mut fixed = Vec::new();
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(v) = event.get("fixed") {
                    fixed.push(v.clone());
                }
            }
        }
    }
    fixed
}

fn map_osv_severity_string(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_pom(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parses_direct_dependencies_with_literal_versions() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.2.2</version>
    </dependency>
  </dependencies>
</project>"#;
        let f = write_temp_pom(pom);
        let deps = parse_pom_dependencies(f.path()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].coordinate(), "com.fasterxml.jackson.core:jackson-databind");
        assert_eq!(deps[0].version, "2.13.2.2");
    }

    #[test]
    fn resolves_property_placeholder_versions() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>"#;
        let f = write_temp_pom(pom);
        let deps = parse_pom_dependencies(f.path()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "5.3.20", "property placeholder should resolve to literal value");
    }

    #[test]
    fn leaves_unresolvable_property_unchanged() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>example-lib</artifactId>
      <version>${parent.defined.elsewhere}</version>
    </dependency>
  </dependencies>
</project>"#;
        let f = write_temp_pom(pom);
        let deps = parse_pom_dependencies(f.path()).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(
            deps[0].version.starts_with("${"),
            "unresolvable property should be left as-is so check_vulnerabilities can skip it, not silently misqueried"
        );
    }

    #[test]
    fn records_a_plausible_line_number_per_dependency() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>c</groupId>
      <artifactId>d</artifactId>
      <version>2.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let f = write_temp_pom(pom);
        let deps = parse_pom_dependencies(f.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps[0].line < deps[1].line, "second dependency should be reported at a later line than the first");
    }

    #[test]
    fn severity_mapping_matches_osv_database_specific_strings() {
        assert_eq!(map_osv_severity_string("CRITICAL"), Severity::Critical);
        assert_eq!(map_osv_severity_string("HIGH"), Severity::High);
        assert_eq!(map_osv_severity_string("MODERATE"), Severity::Medium);
        assert_eq!(map_osv_severity_string("LOW"), Severity::Low);
        assert_eq!(map_osv_severity_string("something-unexpected"), Severity::Medium);
    }
}
