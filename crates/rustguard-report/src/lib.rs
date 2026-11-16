//! Report generation.
//!
//! NOTE (MVP scaffold): `to_sarif` below hand-writes a minimal
//! SARIF-2.1.0-shaped document with just enough fields to be ingestible by
//! GitHub code scanning. It is a placeholder for the `serde-sarif` crate
//! (see Cargo.toml TODO) which should replace this once the full schema
//! (rule metadata blocks, fingerprints, etc.) is needed.

use rustguard_ir::{Fact, Finding};
use serde_json::json;

pub fn to_json(findings: &[Finding]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(findings)?)
}

/// Render extracted facts as pretty JSON (one array entry per fact).
pub fn facts_to_json(facts: &[Fact]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(facts)?)
}

/// Render facts as a flat, greppable CLI listing: `kind file:line description`.
pub fn facts_to_cli_table(facts: &[Fact]) -> String {
    if facts.is_empty() {
        return "No facts extracted.".to_string();
    }
    let mut out = String::new();
    for f in facts {
        out.push_str(&format!(
            "{:<32} {}:{}  {}\n",
            f.kind,
            f.file.display(),
            f.line,
            f.description
        ));
    }
    out.push_str(&format!("\n{} fact(s)\n", facts.len()));
    out
}

/// Render a one-line-per-kind count, e.g. to quickly see the shape of a
/// codebase (how many endpoints, how many DI points, etc.) without scrolling
/// through hundreds of individual facts.
pub fn facts_summary(facts: &[Fact]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in facts {
        *counts.entry(f.kind.as_str()).or_insert(0) += 1;
    }
    let mut out = String::new();
    for (kind, count) in counts {
        out.push_str(&format!("{count:>5}  {kind}\n"));
    }
    out.push_str(&format!("\n{} fact(s) total\n", facts.len()));
    out
}

pub fn to_sarif(findings: &[Finding]) -> anyhow::Result<String> {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file.to_string_lossy() },
                        "region": { "startLine": f.line, "snippet": { "text": f.snippet } }
                    }
                }]
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RustGuard",
                    "informationUri": "https://example.com/rustguard",
                    "version": env!("CARGO_PKG_VERSION")
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&doc)?)
}

fn severity_to_sarif_level(s: rustguard_ir::Severity) -> &'static str {
    use rustguard_ir::Severity::*;
    match s {
        Critical | High => "error",
        Medium => "warning",
        Low | Info => "note",
    }
}

/// GitLab's "Code Quality" report format (the CodeClimate JSON schema).
///
/// **Why this format and not GitLab's native SAST/Dependency-Scanning
/// report schema:** as of this being written, GitLab's Security
/// Dashboard / merge-request vulnerability widget for native SAST and
/// Dependency Scanning reports is an Ultimate-tier feature. Code Quality
/// reports, by contrast, render inline annotations directly on merge
/// request diffs on **Free/Community Edition too** — which is what makes
/// this the practically useful format for a GitLab CE user, even though
/// "Code Quality" isn't semantically what these findings are. GitLab's
/// tier boundaries do shift over time, so double-check this against
/// current GitLab docs for your instance/version before relying on it.
///
/// Schema reference: https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
pub fn to_gitlab_codequality(findings: &[Finding]) -> anyhow::Result<String> {
    let issues: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "description": f.message,
                "check_name": f.rule_id,
                "fingerprint": codequality_fingerprint(f),
                "severity": severity_to_codequality(f.severity),
                "location": {
                    "path": f.file.to_string_lossy(),
                    "lines": { "begin": f.line }
                }
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&issues)?)
}

/// GitLab requires a stable per-issue fingerprint for deduplication across
/// runs. This doesn't need to be cryptographically strong — just stable
/// and distinct per (rule, file, line) — so a plain (non-cryptographic)
/// hash is fine here rather than pulling in an MD5 dependency.
fn codequality_fingerprint(f: &Finding) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    f.rule_id.hash(&mut hasher);
    f.file.hash(&mut hasher);
    f.line.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn severity_to_codequality(s: rustguard_ir::Severity) -> &'static str {
    use rustguard_ir::Severity::*;
    match s {
        Critical => "blocker",
        High => "critical",
        Medium => "major",
        Low => "minor",
        Info => "info",
    }
}

pub fn to_cli_table(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings. \u{2705}".to_string();
    }
    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "[{:>8}] {}:{}  {}\n    {}\n",
            format!("{:?}", f.severity).to_uppercase(),
            f.file.display(),
            f.line,
            f.rule_id,
            f.message
        ));
    }
    out.push_str(&format!("\n{} finding(s)\n", findings.len()));
    out
}
