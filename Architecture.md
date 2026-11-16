# RustGuard: A High-Performance SAST Tool for Spring Boot

## 1. Goals & Constraints

| Requirement | Design Implication |
|---|---|
| Scan Spring Boot (Java/Kotlin) source | Need a real Java/Kotlin parser, not regex |
| Fast (Rust) | Parallel parsing, incremental caching, zero-copy where possible |
| Low false positives on Spring idioms | Framework-aware semantic rules, not just generic patterns |
| Extensible rule set | Declarative rule DSL (YAML/Rego-like), not hardcoded logic |
| CI/CD friendly | Single static binary, SARIF/JSON output, exit codes |

---

## 2. Build vs. Reuse Strategy

To ship faster and avoid reinventing well-solved problems, this design deliberately reuses proven open-source components wherever they don't compromise the Spring-specific value-add. Only the components that make this a *Spring Boot*-aware tool (rather than a generic Java linter) are custom-built.

| Component | Reuse instead of building | Why |
|---|---|---|
| Parsing | `tree-sitter-java`, `tree-sitter-kotlin` grammars | Mature, maintained grammars — no reason to hand-write a parser |
| Structural pattern matching engine | **`ast-grep-core`** (Rust crate) | Already implements a tree-sitter-based YAML pattern DSL; used as a library instead of hand-rolling a matcher |
| Taint-mode rule semantics | Semgrep's taint-mode DSL as reference (`pattern-sources`/`pattern-sinks`/`pattern-sanitizers`), optionally shell out to `semgrep` itself | Years of false-positive tuning already exist; port the semantics or hybrid-delegate rather than starting from zero |
| Prebuilt Java/Spring vulnerability rules | Semgrep Registry (`p/java`, `p/spring`), Find Security Bugs rule catalog | Don't re-derive SQLi/SSRF/crypto rule logic from scratch (check licenses: mostly LGPL/Apache — attribute accordingly) |
| Secrets detection | **Gitleaks** or **TruffleHog** rule sets | Well-tuned entropy/regex patterns for API keys, tokens, credentials |
| Dependency (SCA) vulnerability scanning | **OSV-Scanner** or **OWASP Dependency-Check** | CVE-database matching against `pom.xml`/`build.gradle` is a separate, already-solved problem |
| Maven/Gradle dependency resolution | Direct parsing (`quick-xml` for POM) or shelling out to `mvn dependency:tree` | Full classpath resolution is a rabbit hole; heuristic import-based resolution is enough for v1 |
| SARIF output | `serde-sarif` crate | Correctly models the fiddly SARIF schema for GitHub/GitLab code scanning ingestion |
| Graph structures (CFG, call graph, bean graph) | `petgraph` crate | Well-tested; no reason to hand-roll graph traversal |
| `.gitignore`-aware file discovery | `ignore` crate (same one ripgrep uses) | Fast and correct out of the box |
| Config parsing (`application.yml`/`.properties`) | `serde_yaml`, `java-properties` crate | Standard, no custom work needed |

**What stays custom** (the real engineering investment):
1. **Spring Fact Extractor** — annotation semantics, bean wiring, Spring Security filter chain analysis. No off-the-shelf tool understands Spring idioms.
2. **Spring-specific taint source/sink definitions** — knowledge encoded as rule data (`@RequestParam` as source, `JdbcTemplate.query()` as sink, etc.), not infrastructure.
3. **Orchestration, caching, CI integration, unified reporting** — gluing reused components into one fast, coherent binary.

**Pragmatic delivery path:**
- **v1**: Rust CLI orchestrator + `ast-grep-core` for pattern matching + hand-written Spring fact extractor (annotation-based, no taint) + ported Find-Security-Bugs/Semgrep rule logic + `serde-sarif` output. Ships in weeks.
- **v2**: Add taint mode — either self-built using `ast-grep`'s CFG utilities, or hybrid-delegated to `semgrep` for complex flows while the Rust tool remains the fast CI entry point.
- **Ongoing**: Shell out to OSV-Scanner and Gitleaks as complementary scanners, merging their JSON/SARIF output into one unified report — SAST + secrets + SCA in a single CI step without owning three detection engines.

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI / CI Entry Point                     │
│              (clap-based: rustguard scan ./src --format sarif)   │
└───────────────────────────┬───────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Project Loader  │  (walk dir, detect build tool:
                    │                  │   maven/gradle, resolve deps)
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Parser Layer    │  tree-sitter-java /
                    │  (AST Builder)   │  tree-sitter-kotlin
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  IR Normalizer   │  Convert AST → unified
                    │                  │  Intermediate Representation
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
      ┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼───────────┐
      │ Semantic      │ │ Data-flow  │ │ Spring Framework │
      │ Model Builder │ │ / Taint    │ │ Fact Extractor   │
      │ (symbols,     │ │ Engine     │ │ (annotations,    │
      │ types, CFG)   │ │            │ │ bean graph)      │
      └───────┬──────┘ └─────┬──────┘ └─────┬───────────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │  Rule Engine     │  Loads YAML/DSL rules,
                    │                  │  matches against IR + facts
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Findings /       │  Dedup, severity scoring,
                    │ Report Generator │  suppression handling
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
        ┌─────▼────┐   ┌─────▼─────┐  ┌─────▼─────┐
        │  SARIF   │   │   JSON    │  │  HTML/CLI │
        └──────────┘   └───────────┘  └───────────┘
```

---

## 3. Core Components (Detailed)

### 3.1 Parser Layer — `tree-sitter`

Use **tree-sitter** (Rust bindings) with `tree-sitter-java` and `tree-sitter-kotlin` grammars.

- Incremental, error-tolerant parsing (handles partial/broken code during editing).
- Produces a concrete syntax tree (CST) fast — this is the single biggest speed advantage over JVM-based tools (Semgrep/SpotBugs/Checkmarx use JVM startup + heavier ASTs).
- Cache parsed ASTs keyed by file hash for incremental re-scans.

```rust
pub struct ParsedFile {
    pub path: PathBuf,
    pub language: Language, // Java | Kotlin
    pub tree: tree_sitter::Tree,
    pub source: Rope,       // ropey for efficient large-file handling
    pub content_hash: u64,
}
```

### 3.2 IR Normalizer

Java and Kotlin ASTs differ structurally. Normalize both into a single **Unified IR** so rules and taint analysis only need to be written once.

```rust
enum IrNode {
    MethodDecl { name: String, params: Vec<Param>, annotations: Vec<Annotation>, body: Block, modifiers: Modifiers },
    ClassDecl { name: String, annotations: Vec<Annotation>, extends: Option<String>, implements: Vec<String>, fields: Vec<FieldDecl>, methods: Vec<MethodDecl> },
    Call { target: Box<IrNode>, method: String, args: Vec<IrNode>, resolved_symbol: Option<SymbolId> },
    FieldAccess { .. },
    StringLiteral(String),
    BinaryOp { .. },
    Assignment { .. },
    // ...
}
```

### 3.3 Semantic Model Builder

- Symbol table: class → fields, methods, inheritance chain
- Best-effort type resolution (no full JVM classpath needed for MVP — can be enhanced later using `.class`/jar indexing for cross-file resolution)
- Control Flow Graph (CFG) per method — required for taint propagation and dead-code / unreachable-code rules

### 3.4 Spring Framework Fact Extractor

This is what differentiates a **Spring-aware** SAST tool from a generic one. Extract framework-level facts:

| Fact | Detected From |
|---|---|
| REST endpoints | `@RestController`, `@RequestMapping`, `@GetMapping`, etc. |
| Request parameter sources | `@RequestParam`, `@PathVariable`, `@RequestBody` |
| Bean wiring | `@Autowired`, `@Bean`, `@Component`, `@Service`, `@Repository` |
| Security config | `@EnableWebSecurity`, `SecurityFilterChain`, `.permitAll()`, `.csrf().disable()` |
| Data access | `@Query`, `JdbcTemplate`, `EntityManager`, `Repository` interfaces |
| Serialization | `@JsonIgnore`, Jackson config |
| Actuator exposure | `management.endpoints.web.exposure.include` in `application.yml` |

This lets rules reason like: *"a `@RequestParam` value flows into a `JdbcTemplate.query()` string concatenation → SQL injection sink reachable from untrusted input."*

### 3.5 Taint / Data-Flow Engine

A lightweight intra-procedural + limited inter-procedural taint tracker:

- **Sources**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `HttpServletRequest.getParameter()`, external file/env reads
- **Sinks**: SQL execution, `ProcessBuilder`/`Runtime.exec`, `ObjectInputStream.readObject`, `Files.write` with unsanitized path, SpEL `ExpressionParser.parseExpression`, XML parsers without disabled external entities, `Class.forName` with dynamic string, log statements with unsanitized input (log injection)
- **Sanitizers**: recognized escaping/validation calls (`HtmlUtils.htmlEscape`, parameterized `PreparedStatement.setString`, validated `@Valid`/`@Pattern`-bound DTOs)

Implementation approach: worklist algorithm over the CFG, propagating a `TaintState` bitset per variable. Keep it configurable in depth (e.g., max call-graph depth = 3) to bound analysis time — this is where Rust's performance really pays off versus JVM-based equivalents.

### 3.6 Rule Engine (Declarative DSL)

Rules should NOT be hardcoded in Rust — they should be data, so security teams can add/tune rules without recompiling.

Example rule format (YAML, Semgrep-inspired but Spring-native):

```yaml
id: spring-sql-injection-jdbctemplate
severity: HIGH
cwe: CWE-89
languages: [java, kotlin]
message: "Untrusted input flows into JdbcTemplate query without parameterization"
pattern:
  source:
    any:
      - annotation: "@RequestParam"
      - annotation: "@PathVariable"
      - annotation: "@RequestBody"
  sink:
    method_call:
      receiver_type: "org.springframework.jdbc.core.JdbcTemplate"
      method: ["query", "update", "execute"]
      arg_index: 0
      arg_kind: "string_concat_or_format"
  sanitizers:
    - method_call: { method: "setString" }
fix_suggestion: |
  Use parameterized queries:
  jdbcTemplate.query("SELECT * FROM users WHERE id = ?", new Object[]{id}, rowMapper);
```

Other rule categories to ship out-of-the-box:

- **Injection**: SQL, OS command, LDAP, XPath, SpEL injection
- **Deserialization**: unsafe `ObjectInputStream`, Jackson polymorphic deserialization without type whitelisting
- **Auth/AuthZ**: `.permitAll()` on sensitive paths, missing `@PreAuthorize`, CSRF disabled, weak CORS (`allowedOrigins("*")` with credentials)
- **Crypto**: hardcoded secrets/keys, weak algorithms (`DES`, `MD5` for passwords), `SecureRandom` misuse
- **Config**: Actuator endpoints exposed without auth, debug/trace enabled in prod profile, `spring.h2.console.enabled=true`
- **SSRF**: `RestTemplate`/`WebClient` calls with unsanitized URL input
- **Logging**: sensitive data (passwords, tokens) logged; log injection via unsanitized newlines

**Implementation note:** rather than hand-rolling this matcher, use **`ast-grep-core`** (Rust crate) as the structural matching engine — it already compiles tree-sitter-based YAML patterns into an efficient query plan. `rustguard-rules` becomes a thin layer that: (1) extends `ast-grep`'s pattern vocabulary with Spring-aware constructs (`annotation:`, `receiver_type:`, taint `source`/`sink`/`sanitizer` blocks), and (2) feeds `ast-grep` match results into the taint engine for flow-sensitive rules. This avoids reimplementing pattern compilation from scratch.

### 3.7 Findings & Reporting

- Deduplicate by (rule_id, file, line, taint-path signature)
- Support inline suppression: `// rustguard:ignore spring-sql-injection-jdbctemplate`
- Output formats: **SARIF** (for GitHub/GitLab code scanning), JSON (machine), HTML (human), plain CLI table (local dev)
- Exit code strategy for CI gating: configurable severity threshold (e.g., fail build on HIGH/CRITICAL only)

---

## 4. Performance Design Choices

| Technique | Benefit |
|---|---|
| `rayon` for parallel per-file parsing & analysis | Near-linear scaling with CPU cores |
| `tree-sitter` incremental parsing + AST cache (content-hash keyed, stored in `sled` or flat files) | Re-scans only changed files in CI/PR mode |
| Arena allocation for IR nodes (`bumpalo`) | Avoids allocator overhead across thousands of AST nodes |
| Bounded inter-procedural taint depth | Predictable analysis time on large monorepos |
| Single static binary (`musl` target) | No JVM startup cost, trivial CI install (`curl` + run) |
| Streaming SARIF writer | Avoids holding entire report in memory on huge codebases |

---

## 6. Suggested Crate Stack

- `tree-sitter`, `tree-sitter-java`, `tree-sitter-kotlin` — parsing
- **`ast-grep-core`** — structural pattern matching / rule matcher engine (reused, not hand-built)
- `rayon` — parallelism
- `clap` — CLI
- `serde` / `serde_yaml` / `serde_json` — rule + config + report serialization
- **`serde-sarif`** — SARIF schema modeling for report output (reused)
- **`petgraph`** — CFG, call graph, and bean-dependency graph structures (reused)
- `ropey` — efficient text buffers for large files
- **`ignore`** — `.gitignore`-aware file discovery (same crate ripgrep uses, reused)
- `bumpalo` — arena allocation for IR
- `sled` or plain content-addressed cache dir — incremental scan cache
- `quick-xml` — Maven `pom.xml` parsing
- **`java-properties`** — `.properties` config file parsing (reused)
- `anyhow` / `thiserror` — error handling
- `tracing` — structured logging/diagnostics

**External tools invoked/merged (not vendored as crates):**
- **OSV-Scanner** — dependency (SCA) vulnerability scanning against `pom.xml`/`build.gradle`, output merged into unified report
- **Gitleaks** — secrets detection, output merged into unified report
- **Semgrep** (optional, v2+) — hybrid taint-mode delegation for complex inter-procedural flows

**Reference-only (rule logic ported, not linked as a dependency):**
- Semgrep Registry rules (`p/java`, `p/spring`) and Find Security Bugs rule catalog — study/port detection logic into native rule YAML (verify LGPL/Apache license terms for attribution)

---

## 7. Project Layout (Rust workspace)

```
rustguard/
├── crates/
│   ├── rustguard-cli/         # entry point, arg parsing, orchestration
│   ├── rustguard-parser/      # tree-sitter wrappers, AST → IR
│   ├── rustguard-ir/          # unified IR types, CFG builder (petgraph)
│   ├── rustguard-taint/       # data-flow / taint engine
│   ├── rustguard-spring/      # Spring-specific fact extraction (custom, core value-add)
│   ├── rustguard-rules/       # rule DSL, wraps ast-grep-core for matching
│   ├── rustguard-report/      # SARIF (serde-sarif) / JSON / HTML writers
│   ├── rustguard-cache/       # incremental scan cache
│   └── rustguard-external/    # OSV-Scanner / Gitleaks invocation + result merging
├── rules/                     # built-in YAML rule packs
│   ├── injection/
│   ├── authn-authz/
│   ├── crypto/
│   └── config/
└── tests/
    └── fixtures/               # sample vulnerable Spring Boot apps per rule
```

---

## 7. Roadmap (Phased Delivery)

**Phase 1 — MVP ✅ done**
- Java parsing, IR, basic annotation/pattern rules (no taint yet)
- Rules: hardcoded secrets, disabled CSRF, actuator exposure, weak crypto
- JSON + CLI output

**Phase 2 — Taint Engine ✅ done (intra-procedural)**
- Real `tree-sitter` AST parsing for Java (`rustguard-parser`)
- Intra-procedural taint tracking across statements within a method
  (`rustguard-taint`): `@RequestParam`/`@PathVariable`/`@RequestBody`/
  `@RequestHeader` sources → SQL execution, `Runtime.exec`/`ProcessBuilder`,
  SpEL `parseExpression`, `Files.write` sinks
- JSON + SARIF output
- **Not yet done from the original Phase 2 scope**: SSRF-specific sink rule,
  and the CFG-based (vs. straight-line) propagation described below in
  "Key Design Risks" — currently a documented simplification, not a gap in
  the taint engine's existence

**Phase 3 — Cross-file / Inter-procedural ✅ done (Java; Kotlin still outstanding)**
- Whole-project symbol index (class fields → declared type, for
  `@Autowired`/constructor-injected bean resolution; method parameter
  lists, for call-site-to-callee argument matching)
- Cross-file taint following: a tainted argument passed into
  `bean.method(x)` is tracked into the callee (any class, any file), up to
  3 hops deep, with cycle protection
- **Not yet done from the original Phase 3 scope**: Kotlin support parity
  (still Java-only), type-qualified (package-aware) symbol resolution
  (current matching is by simple name only — documented limitation), and
  memoized method-summary caching (currently bounded-depth + cycle-guarded
  but recomputed per call site, not cached — a documented performance
  trade, not a correctness gap)

**Phase 4 — Scale, CI Integration & Dependency Scanning (scope revised — IDE integration dropped)**
- ✅ done: GitLab CI compatibility via a Code Quality (CodeClimate) report
  format — chosen over GitLab's native SAST schema specifically because
  it renders on GitLab Community Edition (native SAST/Dependency-Scanning
  dashboard integration is Ultimate-tier); a ready-to-use pipeline
  template ships in `ci/rustguard.gitlab-ci.yml`
- ✅ done: Maven dependency (SCA) scanning — parses `pom.xml` direct
  dependencies and checks them against OSV.dev; known gaps are direct-only
  (no transitive resolution) and single-module only, both documented in
  `rustguard-external`
- ✅ done (enhancement): Redmine defect auto-filing — `rustguard-redmine`
  files a defect per finding above a configurable severity threshold,
  deduplicated against existing **open** Redmine issues via a fingerprint
  (hash of rule + file + code snippet, not line number) embedded in each
  issue's subject. A closed/resolved issue matching the fingerprint does
  NOT suppress a new defect — a regression is treated as worth a fresh
  ticket. Fingerprinting/dedup logic is unit-tested; the live Redmine API
  calls are not (no route to a Redmine instance from the sandbox this was
  built in) — verify against your specific instance before relying on it.
- Not yet done: incremental caching for CI (only re-scan changed files +
  downstream affected symbols), custom rule authoring docs + rule testing
  framework, transitive/multi-module Maven resolution, generalizing the
  Redmine integration into a pluggable issue-tracker interface (Jira,
  GitHub Issues) if that becomes useful beyond Redmine
- **Dropped from original scope**: IDE integration (LSP-like diagnostics) —
  deprioritized in favor of the CI/dependency-scanning/defect-filing work
  above, which is more immediately useful for a GitLab CE-based workflow

---

## 8. Key Design Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Full type resolution without JVM classpath is hard | Start with heuristic/best-effort type inference from imports + local declarations; add optional classpath indexing (parse `.jar`/`.class` files) as an enhancement, not a blocker |
| False positives on Spring's dependency-injection indirection | Build the Spring fact extractor early — treat DI-resolved types as first-class in the semantic model, not just literal calls |
| Rule sprawl / maintenance burden | Rule DSL + fixture-based test suite (each rule ships with a "should flag" and "should not flag" sample) enforced in CI |
| Taint engine performance blowup on large codebases | Bounded depth, per-method summarization/memoization (compute a method's taint "summary" once, reuse at call sites) |

---

## 9. Example End-to-End Flow

1. `rustguard scan ./my-spring-app --format sarif -o results.sarif`
2. Discover `.java`/`.kt` files (respecting `.gitignore`), also parse `application.yml`/`.properties` for config-based rules.
3. Parallel parse all files with tree-sitter → build IR per file.
4. Build project-wide symbol table (single pass merge).
5. Spring fact extractor tags controllers, beans, security config.
6. Taint engine computes per-method summaries, then propagates across call graph for endpoints identified as entry points.
7. Rule engine evaluates all loaded rules against IR + taint facts + Spring facts.
8. Findings deduplicated, severity-scored, written to SARIF.
9. CI step fails build if any `HIGH`/`CRITICAL` findings exist.

---

This design gives you a tool that is **Spring-semantics-aware** (not just generic Java linting), **fast** due to Rust + tree-sitter + parallelism, and **extensible** via a declarative rule system that your security team can grow without touching the Rust core.