//! Git enrichment (project name, per-line blame/commit info) for Redmine
//! issue descriptions.
//!
//! Deliberately implemented by shelling out to the `git` binary rather than
//! a Git library crate (e.g. `git2`, which pulls in `libgit2` and a C
//! build dependency). Any environment that could have checked out the
//! repository to scan in the first place already has `git` on `PATH` —
//! this is guaranteed true in GitLab CI (the checkout step uses it) and
//! for any local developer run. No new crate dependency needed.
//!
//! ## What "who implemented the code" means here
//! `blame_line` runs `git blame` on the **specific line** a finding is
//! reported at, not just "who last touched this file" — a file-level
//! last-commit lookup would often just show whoever's unrelated change
//! happened to touch the file most recently (e.g. a formatting pass),
//! not who actually wrote the vulnerable line. Line-level blame answers
//! the actual question asked.
//!
//! ## Known limitations (documented, not silent)
//! - **Uncommitted local changes**: if the line has been locally modified
//!   and not yet committed, `git blame` reports it as "Not Committed Yet"
//!   with an all-zero commit hash. `blame_line` detects this and returns
//!   `BlameInfo::is_uncommitted = true` with no real commit date — the
//!   caller should render this distinctly rather than treating it as a
//!   normal historical commit.
//! - **Untracked files, non-git directories, missing `git` binary**: all
//!   treated as "no blame info available" (`Ok(None)`), not a hard error —
//!   a SAST scan shouldn't fail just because git metadata isn't available
//!   for one file.
//! - **Shallow clones**: a shallow `git clone --depth 1` (common in CI to
//!   speed up checkout) can cause `git blame` to attribute a line to the
//!   shallow clone's boundary commit rather than its true origin, if the
//!   real introducing commit was truncated out of history. This is a
//!   `git` behavior, not something this module works around — if you see
//!   suspiciously identical "last commit" info across many old findings,
//!   check whether your CI checkout uses `GIT_DEPTH`/`--depth`.
//! - **Two subprocess calls per blamed line** (`git blame` then `git log`
//!   for a nicely formatted ISO date) — fine for the "enrich a handful of
//!   findings about to become Redmine tickets" use case this is built for,
//!   not designed for enriching thousands of findings per run.

use anyhow::Result;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct BlameInfo {
    /// Short (7-char) commit hash. Empty if `is_uncommitted`.
    pub commit_hash: String,
    pub author_name: String,
    pub author_email: String,
    /// ISO 8601 date string (via `git log --date=iso-strict`), e.g.
    /// "2026-05-14T10:22:03+00:00". Empty if `is_uncommitted`.
    pub commit_date: String,
    /// First line of the commit message. "(uncommitted local change)" if
    /// `is_uncommitted`.
    pub commit_summary: String,
    pub is_uncommitted: bool,
}

/// Run `git blame` on a single line of `file` (given relative to
/// `scan_root`, matching how RustGuard's `Finding.file` paths are stored)
/// and return who last touched it. Returns `Ok(None)` — not an error — for
/// any case where blame info genuinely isn't available (not a git repo,
/// file untracked, `git` missing).
pub fn blame_line(scan_root: &Path, file: &Path, line: usize) -> Result<Option<BlameInfo>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(scan_root)
        .arg("blame")
        .arg(format!("-L{line},{line}"))
        .arg("--line-porcelain")
        .arg("--")
        .arg(file)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Ok(None), // git binary not found
    };

    if !output.status.success() {
        return Ok(None); // not a git repo, file untracked, bad line number, etc.
    }

    let porcelain = String::from_utf8_lossy(&output.stdout);
    let mut lines = porcelain.lines();

    let Some(header) = lines.next() else { return Ok(None) };
    let full_sha = header.split_whitespace().next().unwrap_or("").to_string();
    let is_uncommitted = full_sha.chars().all(|c| c == '0') || full_sha.is_empty();

    let mut author_name = String::new();
    let mut author_email = String::new();
    let mut summary = String::new();

    for line in lines {
        if let Some(v) = line.strip_prefix("author ") {
            author_name = v.to_string();
        } else if let Some(v) = line.strip_prefix("author-mail ") {
            author_email = v.trim_start_matches('<').trim_end_matches('>').to_string();
        } else if let Some(v) = line.strip_prefix("summary ") {
            summary = v.to_string();
        }
        // The porcelain block ends at the line starting with a tab
        // (the actual source line content) — everything needed is
        // above that, so no need to specifically detect and stop there.
    }

    if is_uncommitted {
        return Ok(Some(BlameInfo {
            commit_hash: String::new(),
            author_name,
            author_email,
            commit_date: String::new(),
            commit_summary: "(uncommitted local change)".to_string(),
            is_uncommitted: true,
        }));
    }

    let commit_date = commit_date_iso(scan_root, &full_sha).unwrap_or_default();
    let short_sha = full_sha.chars().take(7).collect();

    Ok(Some(BlameInfo {
        commit_hash: short_sha,
        author_name,
        author_email,
        commit_date,
        commit_summary: summary,
        is_uncommitted: false,
    }))
}

fn commit_date_iso(scan_root: &Path, sha: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(scan_root)
        .arg("log")
        .arg("-1")
        .arg("--format=%ad")
        .arg("--date=iso-strict")
        .arg(sha)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let date = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if date.is_empty() { None } else { Some(date) }
}

/// Best-effort project name: GitLab CI's `CI_PROJECT_NAME` if set (most
/// reliable when actually running in GitLab CI), else parsed from the
/// git remote's URL, else the scan directory's name.
pub fn project_name(scan_root: &Path) -> String {
    if let Ok(name) = std::env::var("CI_PROJECT_NAME") {
        if !name.is_empty() {
            return name;
        }
    }

    if let Some(name) = remote_origin_repo_name(scan_root) {
        return name;
    }

    scan_root
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown-project".to_string())
}

fn remote_origin_repo_name(scan_root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(scan_root)
        .arg("config")
        .arg("--get")
        .arg("remote.origin.url")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    extract_repo_name_from_url(&url)
}

/// Handles both `git@gitlab.com:group/project.git` (SSH) and
/// `https://gitlab.com/group/project.git` (HTTPS) remote URL forms.
fn extract_repo_name_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches(".git");
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .rsplit(['/', ':'])
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as Cmd;

    fn run(cmd: &mut Cmd) {
        let status = cmd.status().expect("command should run");
        assert!(status.success(), "command failed: {cmd:?}");
    }

    /// Build a throwaway git repo with a known commit history so blame
    /// tests don't depend on this being run inside any particular repo.
    fn setup_test_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        run(Cmd::new("git").arg("init").arg("-q").current_dir(path));
        run(Cmd::new("git").args(["config", "user.email", "alice@example.com"]).current_dir(path));
        run(Cmd::new("git").args(["config", "user.name", "Alice Example"]).current_dir(path));

        std::fs::write(path.join("Foo.java"), "line one\nline two\nline three\n").unwrap();
        run(Cmd::new("git").args(["add", "Foo.java"]).current_dir(path));
        run(Cmd::new("git")
            .args(["commit", "-q", "-m", "Add Foo.java with a bug"])
            .current_dir(path));

        dir
    }

    #[test]
    fn blame_line_finds_the_committing_author() {
        let repo = setup_test_repo();
        let info = blame_line(repo.path(), Path::new("Foo.java"), 2).unwrap().unwrap();

        assert!(!info.is_uncommitted);
        assert_eq!(info.author_name, "Alice Example");
        assert_eq!(info.author_email, "alice@example.com");
        assert_eq!(info.commit_summary, "Add Foo.java with a bug");
        assert_eq!(info.commit_hash.len(), 7);
        assert!(info.commit_date.contains('T'), "expected ISO 8601 date, got {}", info.commit_date);
    }

    #[test]
    fn blame_line_detects_uncommitted_local_changes() {
        let repo = setup_test_repo();
        // Modify a line without committing.
        std::fs::write(repo.path().join("Foo.java"), "line one\nCHANGED LOCALLY\nline three\n").unwrap();

        let info = blame_line(repo.path(), Path::new("Foo.java"), 2).unwrap().unwrap();
        assert!(info.is_uncommitted);
        assert_eq!(info.commit_summary, "(uncommitted local change)");
    }

    #[test]
    fn blame_line_returns_none_for_untracked_file() {
        let repo = setup_test_repo();
        let result = blame_line(repo.path(), Path::new("DoesNotExist.java"), 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn blame_line_returns_none_outside_a_git_repo() {
        let non_repo = tempfile::tempdir().unwrap();
        std::fs::write(non_repo.path().join("Foo.java"), "content\n").unwrap();
        let result = blame_line(non_repo.path(), Path::new("Foo.java"), 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extracts_repo_name_from_ssh_and_https_urls() {
        assert_eq!(extract_repo_name_from_url("git@gitlab.com:group/my-project.git"), Some("my-project".to_string()));
        assert_eq!(extract_repo_name_from_url("https://gitlab.com/group/my-project.git"), Some("my-project".to_string()));
        assert_eq!(extract_repo_name_from_url("https://gitlab.com/group/subgroup/my-project"), Some("my-project".to_string()));
        assert_eq!(extract_repo_name_from_url(""), None);
    }

    #[test]
    fn project_name_falls_back_to_directory_name_outside_a_repo() {
        let non_repo = tempfile::tempdir().unwrap();
        // Ensure CI_PROJECT_NAME doesn't leak in from the test environment.
        std::env::remove_var("CI_PROJECT_NAME");
        let name = project_name(non_repo.path());
        let expected = non_repo.path().canonicalize().unwrap().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, expected);
    }
}
