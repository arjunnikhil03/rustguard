# RustGuard

A fast, Spring-Boot-aware SAST scanner, written in Rust.

This repository is the **v1 MVP scaffold** for the design described in
[`spring-boot-sast-architecture.md`](../spring-boot-sast-architecture.md).
It implements Phase 1 of the roadmap end-to-end (see that doc, section 8):
file discovery, Spring annotation/config fact extraction, a declarative
YAML rule engine, and JSON/SARIF/CLI reporting with CI-friendly exit codes.

## Status

**Working today (Phase 1 + Phase 2 + Phase 3):**
- Recursive discovery of `.java` / `.kt` source files, with real
  `tree-sitter` AST parsing for Java (`.kt` still raw-text only, see below)
- Spring fact extraction (endpoints, request-input bindings, bean wiring,
  CSRF/permitAll security config, actuator exposure in `application.yml`)
- Rule schema is a genuine subset of the **Semgrep rule format** — verified
  by running the real `semgrep` binary against `rules/` (`--validate` and a
  full `semgrep scan`, matching RustGuard's findings line-for-line for the
  `pattern-regex` subset). 5 built-in rules across injection, authn/authz,
  and crypto categories.
- **Taint analysis (Java), now whole-project (`rustguard_taint::analyze_project`)**:
  - *Intra-procedural* (Phase 2): tracks values from `@RequestParam`/
    `@PathVariable`/`@RequestBody`/`@RequestHeader` through local
    assignments **across statements** within a method, into SQL execution,
    `Runtime.exec`/`ProcessBuilder`, SpEL `parseExpression`, and
    `Files.write` sinks.
  - *Cross-file / inter-procedural* (Phase 3): builds a whole-project
    symbol index (every class's fields — resolving `@Autowired`/
    constructor-injected bean types — and every method's parameter list),
    then follows a tainted argument through `service.method(x)` calls into
    other classes, up to 3 hops deep, with cycle protection. A controller
    that just calls `service.search(name)` with no visible sink will now
    correctly get flagged if `search()` (in a different file) eventually
    reaches one — see `taint-sql-injection-crossfile` and friends. Fully
    tested end-to-end with a 3-file controller → service → repository
    fixture (`CustomerController` → `CustomerService` →
    `CustomerRepository`) and a matching false-positive fixture (a
    cross-file delegation that never reaches a sink).
  - See `crates/rustguard-taint/src/lib.rs` for the full documented design
    and known limitations (no real CFG yet, name-based type resolution —
    no package qualification, no overload resolution, bounded/uncached
    recursion).
- Basic dedup for the (rare, expected) cases where a Phase 1 regex rule and
  the taint engine both catch the exact same same-line pattern
- JSON, SARIF, and human-readable CLI output, plus a `--dump-facts` mode to
  inspect every extracted Spring fact directly
- Configurable severity threshold for CI gating (`--fail-on`)
- Fixture-based regression tests: a deliberately vulnerable app (including
  cross-statement-taint and cross-file-taint fixtures) and a clean app with
  zero expected findings (including a safe cross-file delegation case)

**Intentionally deferred (see TODOs in each crate):**
- Structural rule matching via `ast-grep-core` for the Phase 1 rules
  (currently: single `pattern-regex` per rule — the taint engine already
  uses the real AST, but the declarative YAML rules only support Semgrep's
  regex operator, not its structural `pattern`/`patterns` operators; a rule
  using those will fail to load — **deliberately a hard error, not a
  skip-and-continue**, see module docs in `rustguard-rules`)
- Kotlin AST parsing and taint analysis (Kotlin still gets fact/regex-rule
  coverage only — `tree` is `None` for `.kt` files, so `analyze_project`
  silently excludes them)
- Type-qualified symbol resolution (current cross-file resolution matches
  class/field/method names as plain strings, not fully-qualified types —
  documented in `rustguard-taint`'s module docs)
- Memoized method-summary caching for taint analysis at scale (currently
  bounded-depth + cycle-guarded but not cached — fine at current fixture
  scale, a documented future optimization for very large codebases)
- External scanner integration: OSV-Scanner, Gitleaks (`rustguard-external`)
- Incremental scan caching (`rustguard-cache`)

Every deferred item has a `// TODO` or module-doc note at its intended
integration point, with a pointer back to the relevant architecture doc
section.

## Usage

```bash
# Build
cargo build --release

# Scan a project, human-readable output, fail CI build on HIGH+ findings
./target/release/rustguard scan ./path/to/spring-app --rules ./rules

# JSON output to a file, never fail the build
./target/release/rustguard scan ./path/to/spring-app \
    --rules ./rules --format json -o results.json --fail-on never

# SARIF output for GitHub/GitLab code scanning
./target/release/rustguard scan ./path/to/spring-app \
    --rules ./rules --format sarif -o results.sarif

# See every extracted Spring fact (endpoints, DI points, security config,
# etc.) - useful for understanding what RustGuard "sees" even before there's
# a rule for it. --dump-facts - prints to stdout; a path writes to a file.
./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --dump-facts - --facts-format summary   # count by fact kind
./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --dump-facts - --facts-format table     # one line per fact
./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --dump-facts facts.json --facts-format json

# GitLab Code Quality output — renders inline on merge request diffs on
# GitLab Community Edition too (see "GitLab CI" section below).
./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --format gitlab-codequality -o gl-code-quality-report.json

# Maven dependency vulnerability scan (SCA), opt-in via --scan-maven-deps.
# Checks the pom.xml at the scan root against OSV.dev.
./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --scan-maven-deps --format gitlab-codequality -o gl-dependency-report.json

# File a Redmine defect for every HIGH+ finding that doesn't already have
# a matching OPEN issue (deduped automatically — see "Redmine integration"
# below). API key comes from an env var, never a CLI flag.
RUSTGUARD_REDMINE_API_KEY=your-api-key \
  ./target/release/rustguard scan ./path/to/spring-app --rules ./rules \
    --report-to-redmine \
    --redmine-url https://redmine.example.com \
    --redmine-project your-project-identifier
```

## GitLab CI (Community Edition)

A ready-to-use pipeline template is at
[`ci/rustguard.gitlab-ci.yml`](ci/rustguard.gitlab-ci.yml) — copy it in or
`include:` it. It runs two jobs: SAST (source code findings) and Maven SCA
(dependency vulnerabilities), both emitting GitLab's **Code Quality**
report format rather than GitLab's native SAST schema.

**Why Code Quality and not GitLab's native SAST report format:** as of this
being written, GitLab's Security Dashboard / MR vulnerability widget for
native SAST/Dependency-Scanning reports is an Ultimate-tier feature, while
Code Quality reports render inline on merge request diffs on **Free/CE
too**. GitLab's tier boundaries shift over time — verify this against your
instance's current docs before relying on it. The template itself hasn't
been run against a live GitLab pipeline (this was built in a sandboxed
environment without GitLab CI access); the JSON output format has been
verified against the documented CodeClimate schema, but validate the
pipeline YAML in your own instance first.

## Redmine integration (defect auto-filing)

`--report-to-redmine` files a Redmine defect for every finding at/above
`--redmine-min-severity` (default: HIGH), **skipping findings that already
have a matching open issue** so re-running a scan doesn't create duplicate
tickets for the same underlying problem on every CI run.

**How dedup works:** every issue RustGuard creates has a fingerprint tag
embedded in its subject, e.g. `[rg:a1b2c3d4e5f6]` — a hash of
`(rule_id, file, code snippet)`, **deliberately not line number** (a
one-line drift elsewhere in the file shouldn't file a spurious duplicate).
Before creating anything, it fetches every *open* issue in the target
project once and checks for a matching tag. A defect that was fixed and
closed does **not** suppress a new one if the same issue reappears later —
that's treated as a regression worth a fresh ticket.

**Issue descriptions include git context automatically** (on by default
when the scan path is a git repo — disable with `--redmine-no-git-info`):
project name, and per-*line* `git blame` info for the exact flagged line
— commit hash, commit message, author name/email, and commit date. This
answers "who actually wrote this line" (via `git blame` on that specific
line), not just "who last touched this file for some unrelated reason."
Uncommitted local changes are detected and shown distinctly rather than
attributed to a fake commit. This part **was fully tested** in the
environment this was built in (unlike the Redmine API calls themselves) —
`git` is available in any environment that checked out the repo, so this
was verified end-to-end against a real git history, not just unit-tested
in isolation. See `rustguard-git`'s module docs for the one real caveat:
shallow clones (`git clone --depth 1`, common in CI) can cause blame to
misattribute a line to the shallow boundary commit if the true introducing
commit was truncated out of history.

```bash
RUSTGUARD_REDMINE_API_KEY=your-api-key \
  rustguard scan . --rules ./rules \
    --report-to-redmine \
    --redmine-url https://redmine.example.com \
    --redmine-project your-project-identifier \
    --redmine-min-severity high
```

Required: `--redmine-url`, `--redmine-project`, and the
`RUSTGUARD_REDMINE_API_KEY` environment variable (never a CLI flag — CI job
logs and process listings can leak flag values). Optional:
`--redmine-tracker-id`, `--redmine-priority-id`.

**Important — not live-tested.** The fingerprinting and dedup logic are
unit-tested and don't touch the network, but the actual HTTP calls against
a real Redmine instance could not be tested from the sandboxed environment
this was built in (no route to any Redmine server, unsurprisingly, since
these are typically self-hosted). The request/response shapes follow
Redmine's documented REST API, but **verify against your specific Redmine
version** — required fields for issue creation and default-tracker
behavior can vary by version/configuration — before relying on this in CI.
See `rustguard-redmine`'s module docs for full details and other
limitations (pagination cap on very large trackers, single tracker/priority
per run, etc.).

**Debugging a connection that isn't working:** use `--redmine-dry-run` to
run the full fetch-and-dedup logic and see exactly what RustGuard would
create/skip, without actually filing anything — good for confirming
fingerprint/dedup behavior against your real project before it files real
tickets. For anything below that (auth failures, permission errors, field
validation errors), see
[`docs/debugging-redmine.md`](docs/debugging-redmine.md) — a step-by-step
`curl`-based checklist that isolates whether a failure is a Redmine
config/permissions problem or something in RustGuard itself, plus what
each HTTP status code from Redmine's API actually means.

`--scan-maven-deps` parses the `pom.xml` at the scan root and checks each
**direct** dependency against [OSV.dev](https://osv.dev)'s API. Known
limitations (see full docs in `rustguard-external`'s module docs):
- Direct dependencies only — no transitive dependency tree resolution
  (that would require shelling out to `mvn dependency:tree`, deliberately
  not done to avoid requiring a Maven install just to run a scan)
- Single-module only — point it at each module's `pom.xml` for multi-module projects
- A dependency whose version is a property inherited from a *different*
  file (e.g. a parent POM) can't be resolved and is skipped with a warning,
  not silently mis-queried
- The OSV API integration has been code-reviewed and unit-tested for the
  parsing/mapping logic, but the live API call itself could not be tested
  from the sandboxed environment this was built in (no outbound access to
  `api.osv.dev`) — verify it works against the real API in your environment
  before relying on it in CI
- **Redmine defect auto-filing** (`--report-to-redmine`) — files a defect
  per finding at/above a configurable severity, deduped against existing
  *open* Redmine issues via a fingerprint embedded in the issue subject
  (hash of rule + file + code snippet, deliberately excluding line number
  so minor line drift doesn't spam duplicates). Same caveat as OSV above:
  fingerprinting/dedup logic is unit-tested, the live Redmine API calls are
  not (no route to any Redmine instance from this sandbox) — verify against
  your specific Redmine version before relying on it in CI. See
  `rustguard-redmine`'s module docs for full details.

Try it against the bundled fixtures:

```bash
# Should report 13 findings, including one cross-file finding
# (taint-sql-injection-crossfile in CustomerRepository.java, originating
# from CustomerController.search — 2 hops away)
cargo run -- scan tests/fixtures/vulnerable-app --rules rules

# Should report 0 findings — including a cross-file delegation
# (AccountController -> GreetingService) that never reaches a sink
cargo run -- scan tests/fixtures/clean-app --rules rules
```

## Project layout

```
rustguard/
├── crates/
│   ├── rustguard-cli/        # CLI entry point & orchestration
│   ├── rustguard-parser/     # tree-sitter AST parsing (Java) + file discovery
│   ├── rustguard-ir/         # shared types: SourceFile, Fact, Finding, Severity
│   ├── rustguard-spring/     # Spring Framework fact extraction (core value-add)
│   ├── rustguard-rules/      # Semgrep-schema-subset YAML rule loading + regex matching
│   ├── rustguard-taint/      # intra + inter-procedural (cross-file) taint engine, Java
│   ├── rustguard-report/     # JSON / SARIF / CLI table output
│   ├── rustguard-cache/      # [stub] Phase 4 incremental cache
│   ├── rustguard-external/   # Maven SCA (pom.xml + OSV.dev)
│   ├── rustguard-redmine/    # Redmine defect auto-filing, with dedup
│   └── rustguard-git/        # project name + per-line git blame enrichment
├── rules/                    # built-in YAML rule packs
│   ├── injection/
│   ├── authn-authz/
│   └── crypto/
└── tests/fixtures/
    ├── vulnerable-app/       # vulnerable sample, incl. cross-statement AND cross-file taint cases
    └── clean-app/            # false-positive regression fixture, incl. a safe cross-file case
```

## Adding a rule

Drop a new YAML file anywhere under `rules/`:

```yaml
id: my-new-rule
severity: HIGH          # INFO | LOW | MEDIUM | HIGH | CRITICAL
cwe: CWE-000
languages: [java, kotlin]
message: "Human-readable description of the finding"
pattern:
  text_match: 'some\.regex\(here\)'
fix_suggestion: |
  How to fix it.
```

No rebuild required — rules are loaded at scan time from the `--rules`
directory.

**Note:** if any rule file in the directory uses a Semgrep feature RustGuard
doesn't support yet (structural `pattern`/`patterns`, `mode: taint`, etc.),
loading fails hard and the whole scan aborts — it does not skip just that
rule. This is deliberate for now (fail loud rather than silently drop a
rule someone expected to run); keep that in mind before dropping a full
third-party rule pack straight into `rules/`.

## Next implementation steps

**Phase 4 scope note:** the original roadmap's "IDE integration (LSP-like
diagnostics)" item has been dropped in favor of GitLab CI compatibility and
Maven dependency scanning (done — see above), since that's the more
immediately useful direction for a GitLab CE shop. Remaining Phase 4 items:

1. Transitive Maven dependency resolution — currently only direct
   dependencies in the scanned `pom.xml` are checked (see
   `rustguard-external` limitations above). Shelling out to
   `mvn dependency:tree` would close this gap at the cost of requiring a
   Maven installation in the scanning environment.
2. Multi-module Maven support — walk parent/child POMs instead of
   requiring one invocation per module.
3. Incremental scan caching for CI (only re-scan changed files).
4. Custom rule authoring docs + a rule-testing framework (a "does this rule
   correctly flag X and correctly not flag Y" fixture harness, similar to
   how `tests/fixtures/` is used today but formalized for third-party rule
   authors).

**Earlier deferred items still outstanding:**

5. Bring in `ast-grep-core` for structural Semgrep rules (`pattern`,
   `patterns`, `pattern-either`) in `rustguard-rules`, now that
   `rustguard-parser` already produces a real Java AST the taint engine
   already relies on.
6. Add `tree-sitter-kotlin` so Kotlin files get the same AST-based taint
   coverage (both intra- and inter-procedural) that Java has today.
7. Type-qualify symbol resolution in `rustguard-taint` (package-aware class
   names, real overload resolution by argument type) to reduce the
   documented name-collision risk in the current cross-file resolver.
8. Add memoized per-method taint summaries so cross-file resolution doesn't
   re-walk the same callee repeatedly on large call graphs.
9. Replace the straight-line "may-taint" traversal with a real CFG (via
   `petgraph`) so branches/loops are modeled precisely instead of
   approximated by textual order.
10. Add `serde-sarif` to `rustguard-report` for full SARIF schema fidelity.
11. Wire Gitleaks subprocess invocation into `rustguard-external` for
    secrets detection, merging its output into the unified `Finding` model
    (OSV-based dependency scanning is now done; Gitleaks was the other
    external scanner originally planned alongside it).
