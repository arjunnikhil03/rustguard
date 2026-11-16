//! Declarative rule loading & matching.
//!
//! **Schema note:** the YAML schema here is a deliberate subset of the real
//! [Semgrep rule format](https://semgrep.dev/docs/writing-rules/rule-syntax/) —
//! not a look-alike, an actual valid subset. Every field name and value
//! (`rules:` top-level list, `id`, `languages`, `severity: ERROR|WARNING|INFO`,
//! `message`, `metadata.cwe`/`metadata.references`, and Semgrep's own
//! `pattern-regex` operator for raw-regex matching) is something a real
//! Semgrep binary would also accept and run correctly. This means:
//!
//! - Rules ported from the Semgrep Registry that only use `pattern-regex`
//!   need little to no reformatting to drop into `rules/`.
//! - `rustguard scan` findings and `semgrep scan` findings for the same
//!   rule file should agree (for the `pattern-regex`-only subset).
//!
//! **What's intentionally NOT yet supported** (a real Semgrep/ast-grep rule
//! using these will fail to parse here — this is a known, documented gap,
//! not a silent one): structural `pattern`/`patterns`/`pattern-either`,
//! taint `mode: taint` with `pattern-sources`/`pattern-sinks`, and
//! `fix:` autofix. Structural matching is the planned `ast-grep-core`
//! upgrade (see architecture doc); until then, only `pattern-regex` rules
//! can be loaded.
//!
//! `metadata.fix_suggestion` is a RustGuard-specific extension (not part of
//! Semgrep's schema) for free-text remediation advice — deliberately a
//! different field from Semgrep's `fix:`, since that's reserved for
//! structural autofix in the real spec and we don't want to collide with
//! that meaning once structural rules land.

//! **Failure mode (current, deliberate):** if any rule file in the
//! directory uses an unsupported Semgrep feature (structural `pattern`/
//! `patterns`/`pattern-either`, `mode: taint`, etc.), `load_rules` returns
//! a hard error and the entire scan aborts — it does **not** skip the
//! offending rule and continue with the rest. This means dropping a
//! Semgrep Registry pack with mixed `pattern-regex` and structural rules
//! into `rules/` will currently fail the whole run rather than degrade
//! gracefully. This has been raised and intentionally left as-is for now;
//! revisit if/when ingesting larger third-party rule packs becomes routine.

use anyhow::{Context, Result};
use regex::Regex;
use rustguard_ir::{Finding, Severity, SourceFile};
use serde::Deserialize;
use std::path::Path;

/// Top-level file shape: `rules: [ ... ]`, matching Semgrep exactly.
#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RawRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawRule {
    id: String,
    languages: Vec<String>,
    severity: SemgrepSeverity,
    message: String,
    #[serde(default)]
    metadata: Metadata,
    /// Semgrep's built-in raw-regex matching operator. This is the one
    /// real Semgrep pattern operator RustGuard currently implements.
    #[serde(rename = "pattern-regex")]
    pattern_regex: String,
}

/// Semgrep's actual three-level severity enum. RustGuard's internal
/// `rustguard_ir::Severity` has five levels (used by the taint engine,
/// which isn't YAML-driven); see `to_internal_severity` for the mapping.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum SemgrepSeverity {
    Error,
    Warning,
    Info,
}

fn to_internal_severity(s: SemgrepSeverity) -> Severity {
    match s {
        SemgrepSeverity::Error => Severity::High,
        SemgrepSeverity::Warning => Severity::Medium,
        SemgrepSeverity::Info => Severity::Info,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Metadata {
    /// Semgrep convention: a list of CWE strings, e.g. `["CWE-89"]`. Also
    /// accepts a single bare string for convenience (some hand-written
    /// rules in the wild use that form).
    #[serde(default)]
    cwe: Option<OneOrMany<String>>,
    #[serde(default)]
    #[allow(dead_code)] // carried through for future SARIF/report enrichment
    category: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    references: Vec<String>,
    /// RustGuard extension — see module docs.
    #[serde(default)]
    fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    fn first(&self) -> T {
        match self {
            OneOrMany::One(t) => t.clone(),
            OneOrMany::Many(v) => v[0].clone(),
        }
    }
}

/// A rule with its regex pre-compiled and severity/CWE normalized to
/// RustGuard's internal types, ready for matching.
pub struct CompiledRule {
    id: String,
    languages: Vec<String>,
    severity: Severity,
    cwe: Option<String>,
    message: String,
    fix_suggestion: Option<String>,
    regex: Regex,
}

/// Load every `*.yml`/`*.yaml` rule file found recursively under
/// `rules_dir`. Each file must use the Semgrep-shaped `rules: [...]`
/// top-level list (one or more rules per file, exactly like Semgrep).
pub fn load_rules(rules_dir: &Path) -> Result<Vec<CompiledRule>> {
    let mut compiled = Vec::new();

    for entry in walkdir::WalkDir::new(rules_dir) {
        let entry = entry.context("walking rules directory")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yml") | Some("yaml")) {
            continue;
        }

        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rule file {}", path.display()))?;
        let file: RuleFile = serde_yaml::from_str(&text).with_context(|| {
            format!(
                "parsing rule file {} (expected Semgrep-style `rules:` list — see rustguard-rules docs)",
                path.display()
            )
        })?;

        for rule in file.rules {
            let regex = Regex::new(&rule.pattern_regex)
                .with_context(|| format!("compiling pattern-regex for rule {}", rule.id))?;

            compiled.push(CompiledRule {
                id: rule.id,
                languages: rule.languages,
                severity: to_internal_severity(rule.severity),
                cwe: rule.metadata.cwe.as_ref().map(|c| c.first()),
                message: rule.message,
                fix_suggestion: rule.metadata.fix_suggestion,
                regex,
            });
        }
    }

    Ok(compiled)
}

/// Evaluate all compiled rules against a single source file, returning any
/// findings.
pub fn evaluate(rules: &[CompiledRule], file: &SourceFile) -> Vec<Finding> {
    let lang_str = match file.language {
        rustguard_ir::Language::Java => "java",
        rustguard_ir::Language::Kotlin => "kotlin",
    };

    let mut findings = Vec::new();
    for rule in rules {
        if !rule.languages.iter().any(|l| l.eq_ignore_ascii_case(lang_str)) {
            continue;
        }

        for m in rule.regex.find_iter(&file.content) {
            let line = file.line_at(m.start());
            let snippet = file
                .content
                .lines()
                .nth(line.saturating_sub(1))
                .unwrap_or_default()
                .trim()
                .to_string();

            findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                cwe: rule.cwe.clone(),
                message: rule.message.clone(),
                file: file.path.clone(),
                line,
                snippet,
                fix_suggestion: rule.fix_suggestion.clone(),
            });
        }
    }
    findings
}
