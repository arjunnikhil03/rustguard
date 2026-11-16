//! Unified Intermediate Representation (IR) shared across the RustGuard workspace.
//!
//! NOTE (MVP scaffold): This currently models only what's needed for Phase 1
//! (annotation/text-pattern rules). As `rustguard-parser` grows a real
//! tree-sitter-backed AST -> IR pass (Phase 1.x), `IrNode` will be expanded
//! into the full node enum described in the architecture doc (MethodDecl,
//! ClassDecl, Call, FieldAccess, etc.) and `SourceFile` will carry a real
//! parsed tree instead of just raw text + line index.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Supported source languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Java,
    Kotlin,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "java" => Some(Language::Java),
            "kt" | "kts" => Some(Language::Kotlin),
            _ => None,
        }
    }
}

/// A single loaded & (eventually) parsed source file.
///
/// MVP: holds raw text + precomputed line offsets so rule matches can be
/// reported with accurate line/column numbers even before a full AST exists.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: Language,
    pub content: String,
    line_offsets: Vec<usize>,
}

impl SourceFile {
    pub fn new(path: PathBuf, language: Language, content: String) -> Self {
        let mut line_offsets = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_offsets.push(i + 1);
            }
        }
        Self {
            path,
            language,
            content,
            line_offsets,
        }
    }

    /// 1-indexed line number for a given byte offset into `content`.
    pub fn line_at(&self, byte_offset: usize) -> usize {
        match self.line_offsets.binary_search(&byte_offset) {
            Ok(idx) => idx + 1,
            Err(idx) => idx,
        }
    }
}

/// A fact extracted by a framework-aware extractor (e.g. `rustguard-spring`).
/// Facts are attached to findings' context and can also be matched on
/// directly by rules (e.g. "flag any endpoint fact with no auth annotation").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub kind: String,
    pub description: String,
    pub file: PathBuf,
    pub line: usize,
}

/// Severity levels used consistently across rules, findings, and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single finding produced by the rule engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub snippet: String,
    pub fix_suggestion: Option<String>,
}
