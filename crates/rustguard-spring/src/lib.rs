//! Spring Framework fact extraction — the component that makes this a
//! *Spring-aware* SAST tool rather than a generic Java linter.
//!
//! See architecture doc section 4.4. This crate's job is to recognize
//! Spring-specific idioms (annotations, bean wiring, security config) and
//! turn them into structured `Fact`s that the rule engine and (later) the
//! taint engine can reason about.
//!
//! NOTE (MVP scaffold): extraction is regex-based against raw source text
//! for now. This is a *known, temporary* simplification — see the TODO in
//! Cargo.toml. It is still useful today because most of the highest-value
//! Phase 1 rules (actuator exposure, CSRF disabled, missing auth
//! annotations) are annotation/call-shape checks that don't yet need a full
//! CFG or type resolver.

use once_cell_lite::OnceLexicon;
use regex::Regex;
use rustguard_ir::{Fact, SourceFile};

mod once_cell_lite {
    //! Tiny lazy-static-once helper so we don't need the `once_cell` /
    //! `lazy_static` crates for a handful of compiled regexes.
    use std::sync::OnceLock;

    pub struct OnceLexicon<T>(OnceLock<T>);

    impl<T> OnceLexicon<T> {
        pub const fn new() -> Self {
            Self(OnceLock::new())
        }

        pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
            self.0.get_or_init(f)
        }
    }
}

struct Patterns {
    endpoint_annotation: Regex,
    request_input_annotation: Regex,
    bean_annotation: Regex,
    csrf_disabled: Regex,
    permit_all: Regex,
    actuator_exposure_dotted: Regex,
    // TODO (Phase 1.x): `missing_auth_check` (endpoint without @PreAuthorize
    // nearby) needs a real AST-based proximity check rather than a lookahead
    // regex to avoid false positives/negatives; re-add once rustguard-parser
    // produces a real IR.
}

static PATTERNS: OnceLexicon<Patterns> = OnceLexicon::new();

fn patterns() -> &'static Patterns {
    PATTERNS.get_or_init(|| Patterns {
        endpoint_annotation: Regex::new(
            r"@(RestController|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b",
        )
        .unwrap(),
        request_input_annotation: Regex::new(
            r"@(RequestParam|PathVariable|RequestBody|RequestHeader)\b",
        )
        .unwrap(),
        bean_annotation: Regex::new(
            r"@(Autowired|Bean|Component|Service|Repository)\b",
        )
        .unwrap(),
        csrf_disabled: Regex::new(r"\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)").unwrap(),
        permit_all: Regex::new(r"\.permitAll\s*\(\s*\)").unwrap(),
        actuator_exposure_dotted: Regex::new(
            r"management\.endpoints\.web\.exposure\.include\s*=\s*.*(\*|env|heapdump|shutdown)",
        )
        .unwrap(),
    })
}

/// Extract Spring-specific facts from a single source file.
pub fn extract_facts(file: &SourceFile) -> Vec<Fact> {
    let p = patterns();
    let mut facts = Vec::new();

    push_all(&mut facts, file, &p.endpoint_annotation, "spring.endpoint", "REST endpoint annotation found");
    push_all(&mut facts, file, &p.request_input_annotation, "spring.request_input", "Untrusted request input binding (potential taint source)");
    push_all(&mut facts, file, &p.bean_annotation, "spring.bean", "Bean wiring / DI annotation found");
    push_all(&mut facts, file, &p.csrf_disabled, "spring.security.csrf_disabled", "CSRF protection explicitly disabled");
    push_all(&mut facts, file, &p.permit_all, "spring.security.permit_all", "Security rule permits all requests unauthenticated");

    facts
}

/// Extract facts from an `application.yml` / `application.properties` file's
/// raw text (config-based rules, e.g. actuator exposure).
///
/// YAML files are parsed structurally (nested `management.endpoints.web.
/// exposure.include` key) since that config is almost always written in
/// nested block form, not dotted notation. `.properties` files use dotted
/// keys natively, so those are still matched with the flat regex fallback.
pub fn extract_config_facts(path: &std::path::Path, content: &str) -> Vec<Fact> {
    let mut facts = Vec::new();

    let is_yaml = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
        .unwrap_or(false);

    if is_yaml {
        facts.extend(extract_actuator_exposure_from_yaml(path, content));
    } else {
        facts.extend(extract_actuator_exposure_from_properties(path, content));
    }

    facts
}

fn extract_actuator_exposure_from_yaml(path: &std::path::Path, content: &str) -> Vec<Fact> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };

    let include_value = doc
        .get("management")
        .and_then(|v| v.get("endpoints"))
        .and_then(|v| v.get("web"))
        .and_then(|v| v.get("exposure"))
        .and_then(|v| v.get("include"));

    let Some(value) = include_value else {
        return Vec::new();
    };

    if is_broad_actuator_exposure(value) {
        // Best-effort line lookup: find the "include" line for reporting.
        let line = content
            .lines()
            .position(|l| l.trim_start().starts_with("include"))
            .map(|idx| idx + 1)
            .unwrap_or(1);

        vec![Fact {
            kind: "spring.config.actuator_exposure".into(),
            description: "Actuator endpoints exposed broadly in configuration".into(),
            file: path.to_path_buf(),
            line,
        }]
    } else {
        Vec::new()
    }
}

fn is_broad_actuator_exposure(value: &serde_yaml::Value) -> bool {
    let is_sensitive = |s: &str| {
        s.trim() == "*" || ["env", "heapdump", "shutdown", "beans", "configprops"].contains(&s.trim())
    };
    match value {
        serde_yaml::Value::String(s) => s.split(',').any(is_sensitive),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str())
            .any(is_sensitive),
        _ => false,
    }
}

fn extract_actuator_exposure_from_properties(path: &std::path::Path, content: &str) -> Vec<Fact> {
    let p = patterns();
    let mut facts = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if p.actuator_exposure_dotted.is_match(line) {
            facts.push(Fact {
                kind: "spring.config.actuator_exposure".into(),
                description: "Actuator endpoints exposed broadly in configuration".into(),
                file: path.to_path_buf(),
                line: idx + 1,
            });
        }
    }
    facts
}

fn push_all(
    facts: &mut Vec<Fact>,
    file: &SourceFile,
    re: &Regex,
    kind: &str,
    description: &str,
) {
    for m in re.find_iter(&file.content) {
        facts.push(Fact {
            kind: kind.to_string(),
            description: description.to_string(),
            file: file.path.clone(),
            line: file.line_at(m.start()),
        });
    }
}
