//! Source discovery & loading.
//!
//! **Phase 2 update:** Java files are now parsed into a real `tree-sitter`
//! AST (`ParsedFile::tree`), which `rustguard-taint` walks for intra-
//! procedural taint analysis. Kotlin files still only get the raw-text
//! `SourceFile` (see the TODO in Cargo.toml) — `tree` is `None` for them,
//! and taint analysis silently skips those files until a Kotlin grammar is
//! wired in.
//!
//! `rustguard-spring` and `rustguard-rules` are unaffected by this change:
//! they only ever needed `SourceFile` (raw text), which is still available
//! via `ParsedFile::source`.

use anyhow::{Context, Result};
use rustguard_ir::{Language, SourceFile};
use std::path::Path;
use tree_sitter::Tree;
use walkdir::WalkDir;

/// A loaded source file, with a real AST attached when a grammar is
/// available for its language (currently: Java only).
pub struct ParsedFile {
    pub source: SourceFile,
    pub tree: Option<Tree>,
}

/// Walk `root`, respecting common noise directories, and return every
/// discovered Java/Kotlin source file, parsed where a grammar exists.
///
/// TODO: replace the manual directory skip-list with the `ignore` crate so
/// `.gitignore` is honored automatically (see architecture doc section 6).
pub fn discover_and_load(root: &Path) -> Result<Vec<ParsedFile>> {
    let mut files = Vec::new();
    let mut java_parser = new_java_parser()?;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_noise_dir(e.path()))
    {
        let entry = entry.context("walking project directory")?;
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Some(language) = Language::from_extension(ext) else {
            continue;
        };

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;

        let tree = match language {
            Language::Java => java_parser.parse(&content, None),
            Language::Kotlin => None, // no grammar wired in yet
        };

        let source = SourceFile::new(path.to_path_buf(), language, content);
        files.push(ParsedFile { source, tree });
    }

    Ok(files)
}

fn new_java_parser() -> Result<tree_sitter::Parser> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_java::language())
        .context("loading tree-sitter-java grammar")?;
    Ok(parser)
}

fn is_noise_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("target") | Some("build") | Some(".git") | Some("node_modules")
    )
}
