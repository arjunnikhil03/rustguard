//! Redmine defect-tracker integration — files a Redmine issue per finding
//! (above a configurable severity threshold), skipping findings that
//! already have a matching **open** issue so re-running a scan doesn't
//! spam duplicate defects for the same underlying problem.
//!
//! ## How dedup works
//! Every issue RustGuard creates has a stable fingerprint tag embedded in
//! its subject line, e.g. `[rg:a1b2c3d4e5f6]`. The fingerprint is a hash of
//! `(rule_id, file, snippet)` — **deliberately not line number**, since a
//! one-line drift elsewhere in the file (someone adds a blank line above)
//! would otherwise break the match and file a spurious duplicate. Before
//! creating any issues, `sync_findings` fetches every *open* issue in the
//! target project once, extracts any `[rg:...]` tags from their subjects,
//! and skips creating a new issue for any finding whose fingerprint is
//! already present. **Closed/resolved issues are not checked** — if a
//! defect was fixed and closed and the same vulnerability reappears later
//! (a regression), that's treated as worth a fresh ticket, not silently
//! suppressed forever.
//!
//! ## What has and hasn't been verified
//! The fingerprinting, subject-tag parsing, and pagination-loop logic are
//! unit-tested and don't depend on a live server. **The actual HTTP calls
//! against a real Redmine instance have not been tested** — this was built
//! in a sandboxed environment with no network access to any Redmine
//! server (self-hosted instances obviously aren't on any public
//! allowlist). The request/response shapes follow Redmine's documented
//! REST API (https://www.redmine.org/projects/redmine/wiki/Rest_api), but
//! **verify against your specific Redmine version** before relying on this
//! in CI — REST API behavior (e.g. exactly which fields are required to
//! create an issue, whether a default tracker applies if omitted) can vary
//! by version and by how a given instance is configured.
//!
//! ## Known limitations
//! - Fingerprint collisions are astronomically unlikely but not
//!   cryptographically impossible (a 48-bit non-cryptographic hash) —
//!   fine for this use case, not suitable for anything security-critical
//!   in its own right.
//! - The open-issues fetch is capped at `MAX_PAGES` (50 pages of 100 =
//!   5,000 issues) to bound worst-case run time on a very large tracker;
//!   beyond that, dedup coverage degrades (older open issues won't be
//!   checked) rather than the scan hanging indefinitely. A warning is
//!   printed when the cap is hit.
//! - No rate-limiting/backoff on the Redmine API calls. Fine for the
//!   scan-then-file-a-few-tickets use case this is built for; not
//!   designed for filing thousands of issues in one run.
//! - Only one tracker/priority is supported per run — a whole scan uses
//!   the same `tracker_id`/`priority_id` for every issue it creates. Fine
//!   for a single SAST-defects tracker; if you want per-severity trackers,
//!   run this multiple times with different filters.

use regex::Regex;
use rustguard_ir::{Finding, Severity};
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;

const MAX_PAGES: usize = 50;
const PAGE_SIZE: usize = 100;

pub struct RedmineConfig {
    /// e.g. "https://redmine.example.com" (no trailing slash).
    pub base_url: String,
    pub api_key: String,
    /// Redmine project identifier (the URL-slug one, e.g. "my-project"), not
    /// the numeric ID — Redmine's API accepts either, the identifier is
    /// just less likely to silently point at the wrong project if IDs
    /// ever get renumbered.
    pub project: String,
    pub tracker_id: Option<u32>,
    pub priority_id: Option<u32>,
    /// Only findings at or above this severity get filed as defects.
    pub min_severity: Severity,
    /// If set, issue descriptions are enriched with the project name and
    /// per-line git blame info (last commit hash/message/author/date for
    /// the specific flagged line — see rustguard-git's module docs for
    /// exactly what "who implemented the code" means here and its
    /// limitations, e.g. shallow clones). `None` disables enrichment
    /// entirely (e.g. scanning a non-git checkout).
    pub repo_root: Option<PathBuf>,
    /// If true, runs the full fetch-and-dedup logic and prints what would
    /// be created/skipped, but never actually POSTs a new issue. Use this
    /// to verify fingerprint/dedup behavior against your real Redmine
    /// project before letting RustGuard file real tickets.
    pub dry_run: bool,
}

#[derive(Debug, Default)]
pub struct SyncSummary {
    pub created: usize,
    pub skipped_existing: usize,
    pub failed: usize,
    /// Number of issues that would have been created, had `dry_run` been
    /// false. Always 0 when `dry_run` is false (real creations count
    /// toward `created` instead).
    pub would_create: usize,
}

/// File a Redmine issue for every qualifying finding that doesn't already
/// have a matching open issue. Errors creating any single issue are logged
/// and counted in `failed`, not propagated — one bad issue shouldn't abort
/// the whole batch. A hard error is only returned if the initial "fetch
/// existing open issues" call itself fails, since without that we can't
/// safely dedupe at all.
pub fn sync_findings(config: &RedmineConfig, findings: &[Finding]) -> anyhow::Result<SyncSummary> {
    let mut existing = fetch_existing_fingerprints(config)?;
    let mut summary = SyncSummary::default();

    for finding in findings {
        if finding.severity < config.min_severity {
            continue;
        }

        let fp = fingerprint(finding);
        if existing.contains(&fp) {
            summary.skipped_existing += 1;
            if config.dry_run {
                eprintln!(
                    "rustguard-redmine [dry-run]: SKIP (already tracked, fingerprint {fp}) — {} at {}:{}",
                    finding.rule_id,
                    finding.file.display(),
                    finding.line
                );
            }
            continue;
        }

        if config.dry_run {
            eprintln!(
                "rustguard-redmine [dry-run]: WOULD CREATE (fingerprint {fp}) — [{:?}] {} at {}:{}\n    subject would be: [SAST][{:?}] {} — {}:{} [rg:{fp}]",
                finding.severity, finding.rule_id, finding.file.display(), finding.line,
                finding.severity, finding.rule_id, finding.file.display(), finding.line
            );
            summary.would_create += 1;
            existing.insert(fp); // mirror real-run behavior: don't "double count" within one dry-run pass
            continue;
        }

        match create_issue(config, finding, &fp) {
            Ok(_issue_id) => {
                summary.created += 1;
                existing.insert(fp); // avoid a duplicate within this same run
            }
            Err(e) => {
                eprintln!(
                    "rustguard-redmine: failed to create issue for {} at {}:{} — {e}",
                    finding.rule_id,
                    finding.file.display(),
                    finding.line
                );
                summary.failed += 1;
            }
        }
    }

    Ok(summary)
}

/// Stable 48-bit fingerprint of (rule_id, file, snippet) — deliberately
/// excludes line number. See module docs for why.
pub fn fingerprint(finding: &Finding) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    finding.rule_id.hash(&mut hasher);
    finding.file.hash(&mut hasher);
    finding.snippet.hash(&mut hasher);
    format!("{:012x}", hasher.finish() & 0xFFFF_FFFF_FFFF)
}

fn fingerprint_tag(fp: &str) -> String {
    format!("[rg:{fp}]")
}

fn fingerprint_regex() -> Regex {
    Regex::new(r"\[rg:([0-9a-f]{12})\]").expect("static regex is valid")
}

/// Fetch every *open* issue's subject in the target project (paginated),
/// extract any `[rg:xxxxxxxxxxxx]` fingerprint tags, and return the set.
/// One network round-trip per `PAGE_SIZE` issues, capped at `MAX_PAGES`.
fn fetch_existing_fingerprints(config: &RedmineConfig) -> anyhow::Result<HashSet<String>> {
    let tag_re = fingerprint_regex();
    let mut fingerprints = HashSet::new();
    let mut offset = 0usize;

    for page in 0..MAX_PAGES {
        let url = format!(
            "{}/issues.json?project_id={}&status_id=open&limit={PAGE_SIZE}&offset={offset}",
            config.base_url, config.project
        );

        let response = minreq::get(&url)
            .with_header("X-Redmine-API-Key", &config.api_key)
            .with_timeout(15)
            .send()?;

        if response.status_code != 200 {
            anyhow::bail!(
                "Redmine returned HTTP {} fetching open issues (check base_url/api_key/project): {}",
                response.status_code,
                response.as_str().unwrap_or("<non-UTF8 response body>")
            );
        }

        let body: RedmineIssueList = serde_json::from_str(response.as_str()?)?;
        let got = body.issues.len();

        for issue in &body.issues {
            for cap in tag_re.captures_iter(&issue.subject) {
                fingerprints.insert(cap[1].to_string());
            }
        }

        offset += got;
        if got < PAGE_SIZE || offset >= body.total_count {
            break;
        }
        if page == MAX_PAGES - 1 {
            eprintln!(
                "rustguard-redmine: hit the {MAX_PAGES}-page cap fetching open issues \
                 ({offset} of {} total) — dedup coverage may be incomplete for older issues",
                body.total_count
            );
        }
    }

    Ok(fingerprints)
}

fn build_subject(finding: &Finding, fp: &str) -> String {
    format!(
        "[SAST][{:?}] {} — {}:{} {}",
        finding.severity,
        finding.rule_id,
        finding.file.display(),
        finding.line,
        fingerprint_tag(fp)
    )
}

/// Builds the full Redmine issue description (Textile-formatted, which
/// Redmine's default markup renders; degrades to readable-enough plain
/// text if an instance is configured for Markdown instead). Pure function
/// — no network I/O of its own, though it does shell out to `git` via
/// `rustguard_git` when `config.repo_root` is set. Split out from
/// `create_issue` specifically so this can be unit-tested without a live
/// Redmine server.
fn build_description(config: &RedmineConfig, finding: &Finding, fp: &str) -> String {
    let mut description = String::new();

    if let Some(repo_root) = &config.repo_root {
        description.push_str(&format!("*Project:* {}\n", rustguard_git::project_name(repo_root)));

        match rustguard_git::blame_line(repo_root, &finding.file, finding.line) {
            Ok(Some(blame)) if blame.is_uncommitted => {
                description.push_str(&format!(
                    "*Last change:* uncommitted local change by {} <{}>\n",
                    blame.author_name, blame.author_email
                ));
            }
            Ok(Some(blame)) => {
                description.push_str(&format!(
                    "*Last commit:* {} — \"{}\"\n*Committed by:* {} <{}>\n*Commit date:* {}\n",
                    blame.commit_hash, blame.commit_summary, blame.author_name, blame.author_email, blame.commit_date
                ));
            }
            Ok(None) => {
                // No blame info available (untracked file, shallow clone
                // edge case, etc.) — omit the section rather than showing
                // misleading placeholder text.
            }
            Err(e) => {
                eprintln!("rustguard-redmine: git blame lookup failed for {}:{} — {e}", finding.file.display(), finding.line);
            }
        }
        description.push('\n');
    }

    description.push_str(&format!(
        "{}\n\n*File:* {}:{}\n*Rule:* {}\n",
        finding.message,
        finding.file.display(),
        finding.line,
        finding.rule_id
    ));
    if let Some(cwe) = &finding.cwe {
        description.push_str(&format!("*CWE:* {cwe}\n"));
    }
    if !finding.snippet.is_empty() {
        description.push_str(&format!("\n*Code:*\n<pre>{}</pre>\n", finding.snippet));
    }
    if let Some(fix) = &finding.fix_suggestion {
        description.push_str(&format!("\n*Suggested fix:*\n{fix}\n"));
    }
    description.push_str(&format!(
        "\n---\n_Filed automatically by RustGuard. Fingerprint: {}_",
        fingerprint_tag(fp)
    ));

    description
}

fn create_issue(config: &RedmineConfig, finding: &Finding, fp: &str) -> anyhow::Result<u64> {
    let subject = build_subject(finding, fp);
    let description = build_description(config, finding, fp);

    let mut issue = json!({
        "project_id": config.project,
        "subject": subject,
        "description": description,
    });
    if let Some(tracker_id) = config.tracker_id {
        issue["tracker_id"] = json!(tracker_id);
    }
    if let Some(priority_id) = config.priority_id {
        issue["priority_id"] = json!(priority_id);
    }

    let url = format!("{}/issues.json", config.base_url);
    let response = minreq::post(&url)
        .with_header("Content-Type", "application/json")
        .with_header("X-Redmine-API-Key", &config.api_key)
        .with_body(json!({ "issue": issue }).to_string())
        .with_timeout(15)
        .send()?;

    if response.status_code != 201 {
        anyhow::bail!("Redmine returned HTTP {}: {}", response.status_code, response.as_str().unwrap_or(""));
    }

    let created: RedmineCreatedIssue = serde_json::from_str(response.as_str()?)?;
    Ok(created.issue.id)
}

#[derive(Debug, serde::Deserialize)]
struct RedmineIssueList {
    issues: Vec<RedmineIssueSummary>,
    #[serde(default)]
    total_count: usize,
}

#[derive(Debug, serde::Deserialize)]
struct RedmineIssueSummary {
    subject: String,
}

#[derive(Debug, serde::Deserialize)]
struct RedmineCreatedIssue {
    issue: RedmineIssueId,
}

#[derive(Debug, serde::Deserialize)]
struct RedmineIssueId {
    id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_finding(rule_id: &str, file: &str, line: usize, snippet: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            message: "test message".to_string(),
            file: PathBuf::from(file),
            line,
            snippet: snippet.to_string(),
            fix_suggestion: Some("fix it".to_string()),
        }
    }

    #[test]
    fn fingerprint_is_stable_across_repeated_calls() {
        let f = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        assert_eq!(fingerprint(&f), fingerprint(&f));
    }

    #[test]
    fn fingerprint_is_unaffected_by_line_number_drift() {
        let f1 = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        let f2 = sample_finding("taint-sql-injection", "Foo.java", 15, "jdbcTemplate.query(sql)");
        assert_eq!(fingerprint(&f1), fingerprint(&f2), "line number must not affect the fingerprint");
    }

    #[test]
    fn fingerprint_differs_for_different_rule_or_file_or_snippet() {
        let base = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        let diff_rule = sample_finding("taint-command-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        let diff_file = sample_finding("taint-sql-injection", "Bar.java", 10, "jdbcTemplate.query(sql)");
        let diff_snippet = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(other)");

        assert_ne!(fingerprint(&base), fingerprint(&diff_rule));
        assert_ne!(fingerprint(&base), fingerprint(&diff_file));
        assert_ne!(fingerprint(&base), fingerprint(&diff_snippet));
    }

    #[test]
    fn fingerprint_tag_round_trips_through_the_parsing_regex() {
        let f = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        let fp = fingerprint(&f);
        let subject = format!("[SAST][High] taint-sql-injection — Foo.java:10 {}", fingerprint_tag(&fp));

        let re = fingerprint_regex();
        let found: Vec<String> = re.captures_iter(&subject).map(|c| c[1].to_string()).collect();
        assert_eq!(found, vec![fp]);
    }

    #[test]
    fn fingerprint_regex_ignores_unrelated_bracketed_text() {
        let re = fingerprint_regex();
        let subject = "[SAST][High] some rule — File.java:1 [rg:abcdef123456] [unrelated:tag]";
        let found: Vec<String> = re.captures_iter(subject).map(|c| c[1].to_string()).collect();
        assert_eq!(found, vec!["abcdef123456".to_string()]);
    }

    fn base_config(repo_root: Option<PathBuf>) -> RedmineConfig {
        RedmineConfig {
            base_url: "https://redmine.example.com".to_string(),
            api_key: "unused-in-these-tests".to_string(),
            project: "test-project".to_string(),
            tracker_id: None,
            priority_id: None,
            min_severity: Severity::High,
            repo_root,
            dry_run: false,
        }
    }

    #[test]
    fn description_omits_git_section_when_repo_root_not_set() {
        let f = sample_finding("taint-sql-injection", "Foo.java", 10, "jdbcTemplate.query(sql)");
        let config = base_config(None);
        let desc = build_description(&config, &f, "abc123");
        assert!(!desc.contains("*Project:*"));
        assert!(!desc.contains("*Last commit:*"));
        assert!(desc.contains(&f.message));
    }

    #[test]
    fn description_includes_project_name_and_blame_info_for_a_real_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        std::process::Command::new("git").arg("init").arg("-q").current_dir(path).status().unwrap();
        std::process::Command::new("git").args(["config", "user.email", "jane@example.com"]).current_dir(path).status().unwrap();
        std::process::Command::new("git").args(["config", "user.name", "Jane Developer"]).current_dir(path).status().unwrap();
        std::fs::write(path.join("Foo.java"), "line one\nline two\nline three\n").unwrap();
        std::process::Command::new("git").args(["add", "Foo.java"]).current_dir(path).status().unwrap();
        std::process::Command::new("git")
            .args(["commit", "-q", "-m", "Introduce the vulnerable line"])
            .current_dir(path)
            .status()
            .unwrap();

        let f = sample_finding("taint-sql-injection", "Foo.java", 2, "line two");
        let config = base_config(Some(path.to_path_buf()));
        let desc = build_description(&config, &f, "abc123");

        assert!(desc.contains("*Project:*"), "description:\n{desc}");
        assert!(desc.contains("*Last commit:*"), "description:\n{desc}");
        assert!(desc.contains("Jane Developer"), "description:\n{desc}");
        assert!(desc.contains("jane@example.com"), "description:\n{desc}");
        assert!(desc.contains("Introduce the vulnerable line"), "description:\n{desc}");
    }

    #[test]
    fn description_shows_uncommitted_marker_for_local_only_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        std::process::Command::new("git").arg("init").arg("-q").current_dir(path).status().unwrap();
        std::process::Command::new("git").args(["config", "user.email", "jane@example.com"]).current_dir(path).status().unwrap();
        std::process::Command::new("git").args(["config", "user.name", "Jane Developer"]).current_dir(path).status().unwrap();
        std::fs::write(path.join("Foo.java"), "line one\nline two\nline three\n").unwrap();
        std::process::Command::new("git").args(["add", "Foo.java"]).current_dir(path).status().unwrap();
        std::process::Command::new("git").args(["commit", "-q", "-m", "initial"]).current_dir(path).status().unwrap();
        // Modify locally without committing.
        std::fs::write(path.join("Foo.java"), "line one\nCHANGED\nline three\n").unwrap();

        let f = sample_finding("taint-sql-injection", "Foo.java", 2, "CHANGED");
        let config = base_config(Some(path.to_path_buf()));
        let desc = build_description(&config, &f, "abc123");

        assert!(desc.contains("uncommitted local change"), "description:\n{desc}");
        assert!(!desc.contains("*Last commit:*"), "should not show commit info for an uncommitted line:\n{desc}");
    }
}

