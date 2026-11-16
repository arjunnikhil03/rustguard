//! Taint / data-flow engine — **Phase 2 (intra-procedural) + Phase 3
//! (cross-file / inter-procedural)**.
//!
//! ## Phase 2 recap
//! Tracks values flowing from Spring request-input annotations
//! (`@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`) on a
//! method's parameters, through local assignments *within that same
//! method*, into a small table of known injection sinks.
//!
//! ## Phase 3: following taint across files
//! Before walking any method body, `analyze_project` builds a whole-project
//! **symbol index** (`ProjectIndex`): every class's fields (name -> declared
//! type, used to resolve `@Autowired`/constructor-injected bean receivers)
//! and every method's parameter list (used to match call-site arguments to
//! callee parameters).
//!
//! When the walker hits a method call whose receiver resolves to a
//! project-indexed class (a bean field, or an implicit/explicit `this` call
//! to a sibling method) and at least one argument is currently tainted, it
//! doesn't stop at "no local sink" — it recurses *into the callee's body*,
//! seeding a fresh tainted set from just the parameter(s) that received a
//! tainted argument, and keeps walking. This is how a value can be flagged
//! even when the controller only calls `service.search(id)` and the actual
//! SQL execution lives three files away in a repository class.
//!
//! Cross-file findings are tagged with a `-crossfile` rule-id suffix and a
//! message that names the true origin (the original annotated parameter),
//! since the flagged line itself often has no visible connection to
//! untrusted input without that context.
//!
//! **Known limitations (documented, not silent):**
//! - Straight-line, "may-taint" analysis, same as Phase 2 — no real CFG yet.
//! - **Resolution is name-based, not type-checked**: a field's declared
//!   type name is matched against class names by simple string equality
//!   (no package-qualified resolution), so two unrelated classes sharing a
//!   simple name in different packages could be confused. Call targets are
//!   matched by (method name, exact argument count) — no overload
//!   resolution by argument type, and no support for varargs.
//! - Call resolution only follows `receiver.method(...)` where `receiver`
//!   is a plain identifier (a field) or omitted/`this` (sibling method in
//!   the same class). Chained/nested calls as a receiver
//!   (`getService().method()`) and `field_access` receivers
//!   (`this.service.method()`) are not resolved — documented gap, not
//!   silent under-reporting of a case we claim to handle.
//! - Recursion is bounded to `MAX_DEPTH` hops and guarded against cycles
//!   via a per-path visited stack (not a global memoized cache), so a
//!   deeply layered call chain beyond the bound, or a call reached only via
//!   a cycle, won't be explored. No caching means repeated sub-chains may
//!   be re-walked from different call sites — a documented performance
//!   trade favoring correctness/simplicity for now (see architecture doc's
//!   "per-method summarization/memoization" note for the intended future
//!   optimization at scale).
//! - **Java only.** `analyze_project` silently skips any `FileUnit` with no
//!   tree (Kotlin — no grammar wired in yet). Kotlin parity is still
//!   outstanding.

use rustguard_ir::{Finding, Severity, SourceFile};
use std::collections::HashMap;
use std::collections::HashSet;
use tree_sitter::{Node, Tree};

/// Maximum number of cross-file call hops to follow from an original
/// annotated source parameter. Keeps analysis time bounded on large
/// call graphs (see architecture doc, "Key Design Risks").
const MAX_DEPTH: usize = 3;

const SOURCE_ANNOTATIONS: &[&str] =
    &["RequestParam", "PathVariable", "RequestBody", "RequestHeader"];

struct SinkRule {
    method_names: &'static [&'static str],
    receiver_hint: Option<&'static [&'static str]>,
    arg_indices: Option<&'static [usize]>,
    rule_id: &'static str,
    cwe: &'static str,
    severity: Severity,
    message: &'static str,
    fix_suggestion: &'static str,
}

const SINKS: &[SinkRule] = &[
    SinkRule {
        method_names: &["query", "queryForObject", "queryForList", "queryForMap", "update", "execute"],
        receiver_hint: Some(&["jdbctemplate", "jdbc", "statement", "stmt"]),
        arg_indices: Some(&[0]),
        rule_id: "taint-sql-injection",
        cwe: "CWE-89",
        severity: Severity::High,
        message: "Tainted request input flows into a SQL execution call (taint-tracked across statements)",
        fix_suggestion: "Use a parameterized query (`?` placeholders with a params array/PreparedStatement) instead of building the SQL string from tainted input.",
    },
    SinkRule {
        method_names: &["exec"],
        receiver_hint: Some(&["runtime"]),
        arg_indices: None,
        rule_id: "taint-command-injection",
        cwe: "CWE-78",
        severity: Severity::Critical,
        message: "Tainted request input flows into Runtime.exec() (OS command injection)",
        fix_suggestion: "Avoid building shell commands from user input. If unavoidable, use a fixed argument array (no shell interpretation) and an allowlist of permitted values.",
    },
    SinkRule {
        method_names: &["parseExpression"],
        receiver_hint: None,
        arg_indices: Some(&[0]),
        rule_id: "taint-spel-injection",
        cwe: "CWE-917",
        severity: Severity::High,
        message: "Tainted request input flows into a SpEL ExpressionParser.parseExpression() call",
        fix_suggestion: "Never evaluate a Spring Expression Language string built from user input. Use a fixed, developer-authored expression, or avoid SpEL entirely for this value.",
    },
    SinkRule {
        method_names: &["write"],
        receiver_hint: Some(&["files"]),
        arg_indices: Some(&[0]),
        rule_id: "taint-path-traversal",
        cwe: "CWE-22",
        severity: Severity::High,
        message: "Tainted request input flows into a file path used for Files.write()",
        fix_suggestion: "Validate/normalize the path and confirm it resolves within an intended base directory before writing (reject `..` segments, use Path::normalize + startsWith check).",
    },
];

const CONSTRUCTOR_SINKS: &[(&str, &str, &str, Severity, &str, &str)] = &[(
    "ProcessBuilder",
    "taint-command-injection-processbuilder",
    "CWE-78",
    Severity::Critical,
    "Tainted request input flows into a ProcessBuilder constructor (OS command injection)",
    "Avoid building process arguments from user input. If unavoidable, use a fixed argument array and an allowlist of permitted values.",
)];

/// A single parsed Java file, as needed by the project-wide taint analysis.
/// Decoupled from `rustguard_parser::ParsedFile` on purpose so this crate
/// doesn't need a dependency on the parser crate's exact struct shape.
pub struct FileUnit<'a> {
    pub tree: &'a Tree,
    pub source: &'a SourceFile,
}

struct MethodEntry<'a> {
    name: String,
    /// (parameter name, declared type simple name) in declaration order.
    params: Vec<(String, String)>,
    node: Node<'a>,
    file_idx: usize,
}

#[derive(Default)]
struct ClassInfo<'a> {
    /// field name -> declared type simple name (covers both field and
    /// constructor injection, since we only care about the declared type).
    fields: HashMap<String, String>,
    methods: Vec<MethodEntry<'a>>,
}

struct ProjectIndex<'a> {
    classes: HashMap<String, ClassInfo<'a>>,
}

/// Run intra-procedural + cross-file taint analysis over an entire project.
/// `FileUnit`s with no Java grammar available (Kotlin) contribute nothing
/// but are otherwise ignored, not an error.
pub fn analyze_project<'a>(files: &[FileUnit<'a>]) -> Vec<Finding> {
    let project = build_project_index(files);
    let mut findings = Vec::new();

    for (class_name, class_info) in &project.classes {
        for method in &class_info.methods {
            let Some(body) = method.node.child_by_field_name("body") else {
                continue;
            };
            let bytes = files[method.file_idx].source.content.as_bytes();
            let mut tainted = extract_tainted_params(method.node, bytes);
            if tainted.is_empty() {
                continue;
            }

            let origin = describe_origin(class_name, &method.name, &tainted);
            let source = files[method.file_idx].source;
            let mut call_stack = Vec::new();

            walk(
                body,
                bytes,
                &mut tainted,
                &mut findings,
                source,
                &project,
                files,
                class_name,
                0,
                &mut call_stack,
                &origin,
            );
        }
    }

    findings
}

fn describe_origin(class_name: &str, method_name: &str, tainted_params: &HashSet<String>) -> String {
    let mut params: Vec<&String> = tainted_params.iter().collect();
    params.sort();
    let param_list = params
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{class_name}.{method_name}({param_list})")
}

/// Walk the whole project's ASTs once, recording every class's fields and
/// methods. Nested/inner classes are collected too (keyed by their own
/// simple name), matching the same "name-based, not fully-qualified"
/// simplification used throughout this module.
fn build_project_index<'a>(files: &[FileUnit<'a>]) -> ProjectIndex<'a> {
    let mut classes: HashMap<String, ClassInfo<'a>> = HashMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        let bytes = file.source.content.as_bytes();
        for class_node in find_class_like_nodes(file.tree.root_node()) {
            let Some(name_node) = class_node.child_by_field_name("name") else {
                continue;
            };
            let class_name = node_text(name_node, bytes).to_string();
            let Some(body) = class_node.child_by_field_name("body") else {
                continue;
            };

            let entry = classes.entry(class_name).or_default();

            let mut cursor = body.walk();
            for member in body.children(&mut cursor) {
                match member.kind() {
                    "field_declaration" => index_field_declaration(member, bytes, entry),
                    "method_declaration" | "constructor_declaration" => {
                        index_method_declaration(member, bytes, file_idx, entry);
                    }
                    _ => {}
                }
            }
        }
    }

    ProjectIndex { classes }
}

fn index_field_declaration<'a>(node: Node<'a>, bytes: &[u8], class: &mut ClassInfo<'a>) {
    let Some(type_node) = node.child_by_field_name("type") else { return };
    let type_name = node_text(type_node, bytes).to_string();

    let mut cursor = node.walk();
    for declarator in node.children(&mut cursor).filter(|c| c.kind() == "variable_declarator") {
        if let Some(name_node) = declarator.child_by_field_name("name") {
            class.fields.insert(node_text(name_node, bytes).to_string(), type_name.clone());
        }
    }
}

fn index_method_declaration<'a>(node: Node<'a>, bytes: &[u8], file_idx: usize, class: &mut ClassInfo<'a>) {
    let Some(name_node) = node.child_by_field_name("name") else { return };
    let name = node_text(name_node, bytes).to_string();

    let mut params = Vec::new();
    if let Some(formal_params) = node.child_by_field_name("parameters") {
        let mut cursor = formal_params.walk();
        for param in formal_params.children(&mut cursor).filter(|c| c.kind() == "formal_parameter") {
            let param_name = param.child_by_field_name("name").map(|n| node_text(n, bytes).to_string());
            let param_type = param.child_by_field_name("type").map(|n| node_text(n, bytes).to_string());
            if let (Some(n), Some(t)) = (param_name, param_type) {
                params.push((n, t));
            }
        }
    }

    class.methods.push(MethodEntry { name, params, node, file_idx });
}

fn find_class_like_nodes(node: Node) -> Vec<Node> {
    let mut out = Vec::new();
    collect_class_like(node, &mut out);
    out
}

fn collect_class_like<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "class_declaration" || node.kind() == "interface_declaration" {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_class_like(child, out);
    }
}

fn extract_tainted_params(method: Node, bytes: &[u8]) -> HashSet<String> {
    let mut tainted = HashSet::new();
    let Some(params) = method.child_by_field_name("parameters") else {
        return tainted;
    };
    let mut cursor = params.walk();
    for param in params.children(&mut cursor) {
        if param.kind() != "formal_parameter" {
            continue;
        }
        let mut mod_cursor = param.walk();
        let has_source_annotation = param.children(&mut mod_cursor).any(|c| {
            if c.kind() != "modifiers" {
                return false;
            }
            let mut ann_cursor = c.walk();
            let anns: Vec<Node> = c.children(&mut ann_cursor).collect();
            anns.into_iter()
                .any(|ann| annotation_name_matches(ann, bytes, SOURCE_ANNOTATIONS))
        });

        if has_source_annotation {
            if let Some(name_node) = param.child_by_field_name("name") {
                tainted.insert(node_text(name_node, bytes).to_string());
            }
        }
    }
    tainted
}

fn annotation_name_matches(node: Node, bytes: &[u8], names: &[&str]) -> bool {
    if node.kind() != "marker_annotation" && node.kind() != "annotation" {
        return false;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return false;
    };
    let text = node_text(name_node, bytes);
    names.iter().any(|n| *n == text)
}

/// Pre-order walk over a method body, propagating taint through local
/// variable declarations and assignments, checking every method
/// invocation / object creation against the sink table, and — new in
/// Phase 3 — following resolvable calls into other classes/methods when a
/// tainted argument is passed.
#[allow(clippy::too_many_arguments)]
fn walk<'a>(
    node: Node<'a>,
    bytes: &[u8],
    tainted: &mut HashSet<String>,
    out: &mut Vec<Finding>,
    source: &SourceFile,
    project: &ProjectIndex<'a>,
    files: &[FileUnit<'a>],
    current_class: &str,
    depth: usize,
    call_stack: &mut Vec<(String, String)>,
    origin: &str,
) {
    match node.kind() {
        "local_variable_declaration" => {
            let mut cursor = node.walk();
            let declarators: Vec<Node> = node
                .children(&mut cursor)
                .filter(|c| c.kind() == "variable_declarator")
                .collect();
            for declarator in declarators {
                if let Some(value) = declarator.child_by_field_name("value") {
                    walk(value, bytes, tainted, out, source, project, files, current_class, depth, call_stack, origin);
                    if contains_taint(value, bytes, tainted) {
                        if let Some(name_node) = declarator.child_by_field_name("name") {
                            tainted.insert(node_text(name_node, bytes).to_string());
                        }
                    }
                }
            }
            return;
        }
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let Some(right) = right {
                walk(right, bytes, tainted, out, source, project, files, current_class, depth, call_stack, origin);
                if contains_taint(right, bytes, tainted) {
                    if let Some(left) = left {
                        if left.kind() == "identifier" {
                            tainted.insert(node_text(left, bytes).to_string());
                        }
                    }
                }
            }
            return;
        }
        "method_invocation" => {
            check_method_invocation_sink(node, bytes, tainted, out, source, depth, origin);
            try_cross_file_call(node, bytes, tainted, out, source, project, files, current_class, depth, call_stack, origin);
        }
        "object_creation_expression" => {
            check_constructor_sink(node, bytes, tainted, out, source, depth, origin);
        }
        _ => {}
    }

    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for child in children {
        walk(child, bytes, tainted, out, source, project, files, current_class, depth, call_stack, origin);
    }
}

/// Phase 3 core: if this call's receiver resolves to a project-indexed
/// class (a bean field, or an implicit/explicit `this` sibling-method
/// call) and at least one argument is currently tainted, recurse into the
/// callee's body with a fresh tainted set seeded from the matching
/// parameter(s).
#[allow(clippy::too_many_arguments)]
fn try_cross_file_call<'a>(
    node: Node<'a>,
    bytes: &[u8],
    tainted: &HashSet<String>,
    out: &mut Vec<Finding>,
    _source: &SourceFile,
    project: &ProjectIndex<'a>,
    files: &[FileUnit<'a>],
    current_class: &str,
    depth: usize,
    call_stack: &mut Vec<(String, String)>,
    origin: &str,
) {
    if depth >= MAX_DEPTH {
        return;
    }

    let Some(name_node) = node.child_by_field_name("name") else { return };
    let method_name = node_text(name_node, bytes).to_string();

    let target_class_name: Option<String> = match node.child_by_field_name("object") {
        None => Some(current_class.to_string()), // implicit `this`
        Some(obj) if obj.kind() == "this" => Some(current_class.to_string()),
        Some(obj) if obj.kind() == "identifier" => {
            let receiver_name = node_text(obj, bytes);
            project
                .classes
                .get(current_class)
                .and_then(|c| c.fields.get(receiver_name))
                .cloned()
        }
        _ => None, // nested/chained receiver — documented gap, not resolved
    };

    let Some(target_class_name) = target_class_name else { return };
    let Some(target_class) = project.classes.get(&target_class_name) else { return };

    let Some(args) = node.child_by_field_name("arguments") else { return };
    let mut args_cursor = args.walk();
    let arg_nodes: Vec<Node> = args.children(&mut args_cursor).filter(|c| c.is_named()).collect();

    // Exact-arity match only — no overload resolution by type.
    let Some(target_method) = target_class
        .methods
        .iter()
        .find(|m| m.name == method_name && m.params.len() == arg_nodes.len())
    else {
        return;
    };

    let call_key = (target_class_name.clone(), method_name.clone());
    if call_stack.contains(&call_key) {
        return; // cycle guard
    }

    // Which of the callee's parameters actually received a tainted argument?
    let mut callee_tainted = HashSet::new();
    for (i, arg) in arg_nodes.iter().enumerate() {
        if contains_taint(*arg, bytes, tainted) {
            if let Some((param_name, _param_type)) = target_method.params.get(i) {
                callee_tainted.insert(param_name.clone());
            }
        }
    }

    if callee_tainted.is_empty() {
        return; // call happens, but nothing tainted flows into it
    }

    let Some(callee_body) = target_method.node.child_by_field_name("body") else {
        return; // abstract/interface method
    };

    let callee_source = files[target_method.file_idx].source;
    let callee_bytes = callee_source.content.as_bytes();

    call_stack.push(call_key);
    walk(
        callee_body,
        callee_bytes,
        &mut callee_tainted,
        out,
        callee_source,
        project,
        files,
        &target_class_name,
        depth + 1,
        call_stack,
        origin,
    );
    call_stack.pop();
}

fn check_method_invocation_sink(
    node: Node,
    bytes: &[u8],
    tainted: &HashSet<String>,
    out: &mut Vec<Finding>,
    source: &SourceFile,
    depth: usize,
    origin: &str,
) {
    let Some(name_node) = node.child_by_field_name("name") else { return };
    let method_name = node_text(name_node, bytes);

    for sink in SINKS {
        if !sink.method_names.contains(&method_name) {
            continue;
        }
        if let Some(hints) = sink.receiver_hint {
            let Some(object) = node.child_by_field_name("object") else { continue };
            let receiver_text = node_text(object, bytes).to_lowercase();
            if !hints.iter().any(|h| receiver_text.contains(h)) {
                continue;
            }
        }

        let Some(args) = node.child_by_field_name("arguments") else { continue };
        let mut args_cursor = args.walk();
        let arg_nodes: Vec<Node> = args.children(&mut args_cursor).filter(|c| c.is_named()).collect();

        let indices_to_check: Vec<usize> = match sink.arg_indices {
            Some(idxs) => idxs.to_vec(),
            None => (0..arg_nodes.len()).collect(),
        };

        let hit = indices_to_check
            .iter()
            .filter_map(|&i| arg_nodes.get(i))
            .any(|arg| contains_taint(*arg, bytes, tainted));

        if hit {
            emit(out, source, node, sink.rule_id, sink.severity, sink.cwe, sink.message, sink.fix_suggestion, depth, origin);
        }
    }
}

fn check_constructor_sink(
    node: Node,
    bytes: &[u8],
    tainted: &HashSet<String>,
    out: &mut Vec<Finding>,
    source: &SourceFile,
    depth: usize,
    origin: &str,
) {
    let Some(type_node) = node.child_by_field_name("type") else { return };
    let type_name = node_text(type_node, bytes);

    for (ctor_type, rule_id, cwe, severity, message, fix) in CONSTRUCTOR_SINKS {
        if *ctor_type != type_name {
            continue;
        }
        let Some(args) = node.child_by_field_name("arguments") else { continue };
        let mut args_cursor = args.walk();
        let hit = args
            .children(&mut args_cursor)
            .filter(|c| c.is_named())
            .any(|arg| contains_taint(arg, bytes, tainted));

        if hit {
            emit(out, source, node, rule_id, *severity, cwe, message, fix, depth, origin);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    out: &mut Vec<Finding>,
    source: &SourceFile,
    node: Node,
    rule_id: &str,
    severity: Severity,
    cwe: &str,
    message: &str,
    fix_suggestion: &str,
    depth: usize,
    origin: &str,
) {
    let line = source.line_at(node.start_byte());
    let snippet = source
        .content
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_string();

    // Phase 2 (depth 0) findings keep their original rule_id/message
    // unchanged, so existing fixtures/CI configs referencing e.g.
    // "taint-sql-injection" aren't broken by Phase 3. Cross-file findings
    // (depth > 0) get a distinct rule_id and a message that names the true
    // origin, since the flagged line alone often looks unremarkable.
    let (final_rule_id, final_message) = if depth == 0 {
        (rule_id.to_string(), message.to_string())
    } else {
        (
            format!("{rule_id}-crossfile"),
            format!("{message} (originates from {origin}, reaches this sink after {depth} cross-file call hop(s))"),
        )
    };

    out.push(Finding {
        rule_id: final_rule_id,
        severity,
        cwe: Some(cwe.to_string()),
        message: final_message,
        file: source.path.clone(),
        line,
        snippet,
        fix_suggestion: Some(fix_suggestion.to_string()),
    });
}

fn contains_taint(node: Node, bytes: &[u8], tainted: &HashSet<String>) -> bool {
    if node.kind() == "identifier" {
        let is_name_field_of_invocation = node
            .parent()
            .map(|p| {
                (p.kind() == "method_invocation" || p.kind() == "field_access")
                    && p.child_by_field_name("name") == Some(node)
            })
            .unwrap_or(false);

        if !is_name_field_of_invocation && tainted.contains(node_text(node, bytes)) {
            return true;
        }
    }

    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    children.into_iter().any(|c| contains_taint(c, bytes, tainted))
}

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}
