//! Incremental scan cache — **Phase 4** (not yet implemented).
//!
//! See architecture doc section 5 (Performance Design Choices). Planned:
//! content-hash-keyed cache of parsed ASTs / rule results, stored via
//! `sled` or a flat content-addressed directory, so CI re-scans only
//! touch changed files (and their downstream-affected symbols once
//! cross-file resolution exists).
//!
//! Left unimplemented intentionally in this scaffold.

pub struct NotYetImplemented;
