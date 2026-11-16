//! RustGuard CLI — orchestrates discovery, Spring fact extraction, rule
//! evaluation, taint analysis, and report output.
//!
//! This implements Phase 1 + Phase 2 + Phase 3 of the roadmap: intra- and
//! now inter-procedural (cross-file) taint analysis for Java, via
//! `rustguard_taint::analyze_project`. Deferred: external scanner merging
//! and Kotlin AST/taint parity — see TODOs in `rustguard-external` and
//! `rustguard-parser`.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rustguard", version, about = "Fast, Spring-Boot-aware SAST scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Spring Boot project for security findings.
    Scan {
        /// Path to the project root to scan.
        path: PathBuf,

        /// Directory containing YAML rule packs.
        #[arg(long, default_value = "rules")]
        rules: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Cli)]
        format: OutputFormat,

        /// Write output to a file instead of stdout.
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Minimum severity that causes a non-zero exit code (CI gating).
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,

        /// Also write out every extracted Spring fact (endpoints, DI points,
        /// security config, etc.) to this path. Use "-" for stdout.
        /// Facts are the raw signal findings are derived from — useful for
        /// seeing what RustGuard "sees" in a codebase even before enough
        /// rules exist to turn it into a finding.
        #[arg(long)]
        dump_facts: Option<PathBuf>,

        /// Format for --dump-facts output: full listing, JSON, or a
        /// count-by-kind summary.
        #[arg(long, value_enum, default_value_t = FactsFormat::Table)]
        facts_format: FactsFormat,

        /// Also scan pom.xml direct dependencies for known vulnerabilities
        /// via the OSV.dev API (SCA). Off by default since it makes network
        /// calls and adds latency — opt in explicitly. Only checks the
        /// pom.xml at the scan root (single-module); see rustguard-external
        /// module docs for what this does and doesn't cover.
        #[arg(long)]
        scan_maven_deps: bool,

        /// File a Redmine defect for every finding at/above
        /// --redmine-min-severity that doesn't already have a matching
        /// open issue (deduped via a fingerprint embedded in the issue
        /// subject — see rustguard-redmine module docs). Requires
        /// --redmine-url and --redmine-project, plus the
        /// RUSTGUARD_REDMINE_API_KEY environment variable (never passed as
        /// a CLI flag, to avoid it leaking into CI job logs/process lists).
        #[arg(long)]
        report_to_redmine: bool,

        /// Base URL of the Redmine instance, e.g. https://redmine.example.com
        /// (no trailing slash). Required if --report-to-redmine is set.
        #[arg(long)]
        redmine_url: Option<String>,

        /// Redmine project identifier (the URL-slug one, not the numeric ID).
        /// Required if --report-to-redmine is set.
        #[arg(long)]
        redmine_project: Option<String>,

        /// Optional Redmine tracker_id to use for created issues (e.g. a
        /// "Defect" or "Security" tracker). If omitted, Redmine's default
        /// for the project applies — verify that's what you want.
        #[arg(long)]
        redmine_tracker_id: Option<u32>,

        /// Optional Redmine priority_id for created issues.
        #[arg(long)]
        redmine_priority_id: Option<u32>,

        /// Minimum severity that gets filed as a Redmine defect (separate
        /// from --fail-on, which controls CI exit code).
        #[arg(long, value_enum, default_value_t = SeverityArg::High)]
        redmine_min_severity: SeverityArg,

        /// Run the full Redmine fetch-and-dedup logic and print what would
        /// be created/skipped, without actually creating any issues. Use
        /// this to verify connectivity and dedup behavior against your
        /// real Redmine project before letting RustGuard file real
        /// tickets. See docs/debugging-redmine.md.
        #[arg(long)]
        redmine_dry_run: bool,

        /// Disable enriching Redmine issue descriptions with the project
        /// name and per-line git blame info (last commit/author/date for
        /// the flagged line). On by default when --report-to-redmine is
        /// set and the scan path is a git repo; set this if you're
        /// scanning a non-git checkout or don't want that info included.
        #[arg(long)]
        redmine_no_git_info: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for rustguard_ir::Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Critical => rustguard_ir::Severity::Critical,
            SeverityArg::High => rustguard_ir::Severity::High,
            SeverityArg::Medium => rustguard_ir::Severity::Medium,
            SeverityArg::Low => rustguard_ir::Severity::Low,
            SeverityArg::Info => rustguard_ir::Severity::Info,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FactsFormat {
    Table,
    Json,
    Summary,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Cli,
    Json,
    Sarif,
    /// GitLab's "Code Quality" (CodeClimate) report schema — the format
    /// that actually renders inline on merge request diffs in GitLab
    /// Community Edition. See rustguard-report::to_gitlab_codequality docs
    /// for why this (and not GitLab's native SAST schema) is the
    /// recommended choice for CE users.
    #[value(name = "gitlab-codequality")]
    GitlabCodequality,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Never,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            rules,
            format,
            output,
            fail_on,
            dump_facts,
            facts_format,
            scan_maven_deps,
            report_to_redmine,
            redmine_url,
            redmine_project,
            redmine_tracker_id,
            redmine_priority_id,
            redmine_min_severity,
            redmine_dry_run,
            redmine_no_git_info,
        } => run_scan(
            &path,
            &rules,
            format,
            output,
            fail_on,
            dump_facts,
            facts_format,
            scan_maven_deps,
            RedmineOptions {
                enabled: report_to_redmine,
                url: redmine_url,
                project: redmine_project,
                tracker_id: redmine_tracker_id,
                priority_id: redmine_priority_id,
                min_severity: redmine_min_severity,
                dry_run: redmine_dry_run,
                git_info: !redmine_no_git_info,
            },
        ),
    }
}

struct RedmineOptions {
    enabled: bool,
    url: Option<String>,
    project: Option<String>,
    tracker_id: Option<u32>,
    priority_id: Option<u32>,
    min_severity: SeverityArg,
    dry_run: bool,
    git_info: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    path: &std::path::Path,
    rules_dir: &std::path::Path,
    format: OutputFormat,
    output: Option<PathBuf>,
    fail_on: FailOn,
    dump_facts: Option<PathBuf>,
    facts_format: FactsFormat,
    scan_maven_deps: bool,
    redmine: RedmineOptions,
) -> Result<()> {
    eprintln!("RustGuard: discovering source files in {}...", path.display());
    let files = rustguard_parser::discover_and_load(path)?;
    eprintln!("RustGuard: loaded {} source file(s)", files.len());

    eprintln!("RustGuard: loading rules from {}...", rules_dir.display());
    let rules = rustguard_rules::load_rules(rules_dir)?;
    eprintln!("RustGuard: loaded {} rule(s)", rules.len());

    let mut all_findings = Vec::new();
    let mut all_facts = Vec::new();

    for pf in &files {
        all_facts.extend(rustguard_spring::extract_facts(&pf.source));
        all_findings.extend(rustguard_rules::evaluate(&rules, &pf.source));
    }

    // Phase 3: taint analysis now runs once over the whole project (not
    // per-file) so it can follow a tainted value across class/file
    // boundaries — e.g. a controller calling a service method whose sink
    // lives in a different file. Only files with a real AST (Java, for
    // now — see rustguard-parser) contribute; Kotlin files are silently
    // excluded until a Kotlin grammar is wired in.
    let taint_units: Vec<rustguard_taint::FileUnit> = files
        .iter()
        .filter_map(|pf| pf.tree.as_ref().map(|tree| rustguard_taint::FileUnit { tree, source: &pf.source }))
        .collect();
    let taint_findings = rustguard_taint::analyze_project(&taint_units);
    let taint_findings_count = taint_findings.len();
    all_findings.extend(taint_findings);

    // Config-based facts (application.yml / .properties) aren't part of
    // discover_and_load (which only handles .java/.kt), so scan separately.
    for entry in walkdir::WalkDir::new(path) {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy();
        if fname == "application.yml" || fname == "application.yaml" || fname == "application.properties" {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                all_facts.extend(rustguard_spring::extract_config_facts(entry.path(), &content));
            }
        }
    }

    // Surface security-relevant config facts as findings (MVP: just
    // actuator exposure for now; more config facts can be promoted the
    // same way as the rule set grows).
    for fact in &all_facts {
        if fact.kind == "spring.config.actuator_exposure" {
            all_findings.push(rustguard_ir::Finding {
                rule_id: "spring-actuator-exposure".to_string(),
                severity: rustguard_ir::Severity::High,
                cwe: Some("CWE-200".to_string()),
                message: fact.description.clone(),
                file: fact.file.clone(),
                line: fact.line,
                snippet: String::new(),
                fix_suggestion: Some(
                    "Restrict management.endpoints.web.exposure.include to only the \
                     endpoints you need (e.g. health,info), and secure the actuator \
                     endpoints behind authentication."
                        .to_string(),
                ),
            });
        }
    }

    // Maven SCA (opt-in): check pom.xml direct dependencies against OSV.dev
    // for known vulnerabilities. Separate from everything above — this
    // finds vulnerable *dependencies*, not bugs in your own code.
    if scan_maven_deps {
        let pom_path = path.join("pom.xml");
        if pom_path.is_file() {
            eprintln!("RustGuard: parsing Maven dependencies from {}...", pom_path.display());
            match rustguard_external::parse_pom_dependencies(&pom_path) {
                Ok(deps) => {
                    eprintln!("RustGuard: checking {} dependencies against OSV.dev...", deps.len());
                    let sca_findings = rustguard_external::check_vulnerabilities(&pom_path, &deps);
                    eprintln!("RustGuard: found {} known-vulnerable dependency issue(s)", sca_findings.len());
                    all_findings.extend(sca_findings);
                }
                Err(e) => eprintln!("RustGuard: failed to parse {}: {e}", pom_path.display()),
            }
        } else {
            eprintln!(
                "RustGuard: --scan-maven-deps set but no pom.xml found at {} (multi-module projects: point --rules/path at the module directly, see README)",
                pom_path.display()
            );
        }
    }

    // The Phase 1 regex rules and the Phase 2 taint engine can both fire on
    // the same same-line concatenation pattern (e.g. spring-sql-injection-
    // string-concat vs taint-sql-injection). Rather than silently double-
    // reporting the same underlying issue, collapse findings that land on
    // the exact same (file, line) into one, preferring the taint-engine
    // finding when both exist (it has a fuller message/fix_suggestion).
    all_findings = dedupe_same_location(all_findings);

    // Redmine defect filing (opt-in): runs after dedup so we don't file two
    // tickets for what the dedup step above already collapsed into one
    // finding.
    if redmine.enabled {
        match build_redmine_config(&redmine, path) {
            Ok(config) => {
                if config.dry_run {
                    eprintln!("RustGuard: Redmine DRY RUN against {} (no issues will be created)...", config.base_url);
                } else {
                    eprintln!("RustGuard: syncing findings to Redmine at {}...", config.base_url);
                }
                match rustguard_redmine::sync_findings(&config, &all_findings) {
                    Ok(summary) => {
                        if config.dry_run {
                            eprintln!(
                                "RustGuard: Redmine dry run — {} would be created, {} already tracked",
                                summary.would_create, summary.skipped_existing
                            );
                        } else {
                            eprintln!(
                                "RustGuard: Redmine sync — {} created, {} already tracked (skipped), {} failed",
                                summary.created, summary.skipped_existing, summary.failed
                            );
                        }
                    }
                    Err(e) => eprintln!("RustGuard: Redmine sync failed — {e}"),
                }
            }
            Err(e) => eprintln!("RustGuard: --report-to-redmine set but {e}"),
        }
    }

    eprintln!(
        "RustGuard: extracted {} Spring fact(s), {} finding(s) ({} from taint analysis)",
        all_facts.len(),
        all_findings.len(),
        taint_findings_count
    );

    if let Some(facts_path) = dump_facts {
        let rendered_facts = match facts_format {
            FactsFormat::Table => rustguard_report::facts_to_cli_table(&all_facts),
            FactsFormat::Json => rustguard_report::facts_to_json(&all_facts)?,
            FactsFormat::Summary => rustguard_report::facts_summary(&all_facts),
        };
        if facts_path.as_os_str() == "-" {
            println!("{rendered_facts}");
        } else {
            std::fs::write(&facts_path, rendered_facts)?;
            eprintln!("RustGuard: facts written to {}", facts_path.display());
        }
    }

    let rendered = match format {
        OutputFormat::Cli => rustguard_report::to_cli_table(&all_findings),
        OutputFormat::Json => rustguard_report::to_json(&all_findings)?,
        OutputFormat::Sarif => rustguard_report::to_sarif(&all_findings)?,
        OutputFormat::GitlabCodequality => rustguard_report::to_gitlab_codequality(&all_findings)?,
    };

    match output {
        Some(path) => {
            std::fs::write(&path, rendered)?;
            eprintln!("RustGuard: report written to {}", path.display());
        }
        None => println!("{rendered}"),
    }

    let threshold = match fail_on {
        FailOn::Critical => Some(rustguard_ir::Severity::Critical),
        FailOn::High => Some(rustguard_ir::Severity::High),
        FailOn::Medium => Some(rustguard_ir::Severity::Medium),
        FailOn::Never => None,
    };

    if let Some(threshold) = threshold {
        if all_findings.iter().any(|f| f.severity >= threshold) {
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Validate --report-to-redmine's required options and read the API key
/// from the environment (never accepted as a CLI flag — see the flag's
/// help text for why).
fn build_redmine_config(opts: &RedmineOptions, scan_path: &std::path::Path) -> Result<rustguard_redmine::RedmineConfig> {
    let url = opts
        .url
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--redmine-url is required"))?;
    let project = opts
        .project
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--redmine-project is required"))?;
    let api_key = std::env::var("RUSTGUARD_REDMINE_API_KEY").map_err(|_| {
        anyhow::anyhow!("RUSTGUARD_REDMINE_API_KEY environment variable is not set")
    })?;

    Ok(rustguard_redmine::RedmineConfig {
        base_url: url.trim_end_matches('/').to_string(),
        api_key,
        project,
        tracker_id: opts.tracker_id,
        priority_id: opts.priority_id,
        min_severity: opts.min_severity.into(),
        dry_run: opts.dry_run,
        repo_root: if opts.git_info { Some(scan_path.to_path_buf()) } else { None },
    })
}

/// Pairs of (regex rule id, taint rule id) that are known to detect the
/// exact same underlying pattern (same-line string concatenation into a
/// sink). Only these specific pairs get collapsed when they land on the
/// same (file, line) — we deliberately do NOT collapse arbitrary findings
/// that happen to share a line, since that could hide genuinely distinct
/// issues (e.g. a hardcoded secret and a weak-crypto call on the same line).
const KNOWN_OVERLAPPING_RULE_PAIRS: &[(&str, &str)] =
    &[("spring-sql-injection-string-concat", "taint-sql-injection")];

/// Collapse findings from a known-overlapping regex+taint rule pair that
/// land on the same (file, line), keeping the taint-engine finding (it
/// carries a fuller cross-statement-aware message).
fn dedupe_same_location(findings: Vec<rustguard_ir::Finding>) -> Vec<rustguard_ir::Finding> {
    use std::collections::HashSet;

    let mut seen: HashSet<(std::path::PathBuf, usize, String)> = HashSet::new();
    let mut out = Vec::with_capacity(findings.len());

    // First pass: record every (file, line) where a taint finding from an
    // overlapping pair exists, so we can drop the matching regex finding.
    for f in &findings {
        for (regex_id, taint_id) in KNOWN_OVERLAPPING_RULE_PAIRS {
            if f.rule_id == *taint_id {
                seen.insert((f.file.clone(), f.line, regex_id.to_string()));
            }
        }
    }

    for f in findings {
        let is_superseded = seen.contains(&(f.file.clone(), f.line, f.rule_id.clone()));
        if !is_superseded {
            out.push(f);
        }
    }

    out
}
