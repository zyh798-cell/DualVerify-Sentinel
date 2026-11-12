# Changelog

All notable changes to DualVerify-Sentinel are recorded in this file.

This file describes the state of the code and documentation in this repository.
It separates **implemented code paths** from **verified behaviour**: the presence
of an adapter, a schema or a status field is not evidence that the corresponding
real tool has been run end to end.

## [0.2.0-rc.1] - 2026-11-12

The date records when these changes were written into the changelog. It does not
indicate that a Git tag, a push, or a GitHub Release has been created.

### Changes

#### Unified Finding Schema and validation

- Added `vuln_hunter/findings.py`, the unified Finding Schema (`Finding`,
  `FindingError`, `to_dict()`). It defines
  `ALLOWED_SEVERITY = ("info", "low", "medium", "high", "critical")` and
  validates severity strictly through `_norm_severity_strict()`; unknown or
  malformed records raise `FindingError` so invalid records fail closed instead
  of silently entering the unified structure.
- Provides deterministic `finding_id` derivation, capped and validated fields,
  reference validation and `redact_evidence()` for secret-shaped content.
- The `gitleaks` and `semgrep` adapters convert raw records into `Finding`
  objects through `_to_finding()` and emit `to_dict()` output. The module is a
  pure addition: the frozen core adapters (`nuclei`, `bandit`, HTTP probe) and
  the frozen `report.py` retain their original dict shapes.

#### Gitleaks adapter

- Added `vuln_hunter/adapters_ext/gitleaks.py` and registered it with
  `register_gitleaks()` at CLI start-up (`vuln_hunter/__main__.py`).
- `planner.py` emits step `s4-gitleaks` for filesystem-scoped source trees when
  the `gitleaks` binary resolves. When the binary is absent the step is not
  planned, so the report shows exactly what ran.
- Findings are **metadata-only**: a fixed `_WHITELIST_FIELDS` whitelist extracts
  `RuleID`, `File`, `StartLine`, `EndLine`, `Description`, `Tags` and `Link`
  from the untrusted JSON report; `Secret` and `Match` are never read.
  `--redact` is defence in depth, not the boundary.
- `GITLEAKS_DEFAULT_SEVERITY = "high"` is a documented system policy default,
  not a value reported by the tool, because gitleaks JSON carries no severity.
- Failure paths (non-zero exit, invalid JSON, timeout, malformed record) return
  explicit non-success statuses; a timeout retains no partial output. The
  adapter requires its own local binary and never fetches rules over the
  network.

#### Semgrep adapter

- Added `vuln_hunter/adapters_ext/semgrep.py` and registered it with
  `register_semgrep()` at CLI start-up.
- `planner.py` emits step `s5-semgrep` only when a source tree is supplied, the
  `semgrep` binary resolves **and** a local rules source is configured.
  `--config` accepts a local rule file or directory only; registry/auto config
  and implicit network rule fetching are never used. A hand-written step
  without rules fails explicitly rather than being silently skipped.
- `SEMGREP_SEVERITY_MAP` documents the nine-value translation into the unified
  schema: `ERROR` to `high`, `WARNING` to `medium`, `INFO` to `info`,
  `CRITICAL` to `critical`, `HIGH` to `high`, `MEDIUM` to `medium`, `LOW` to
  `low`, `EXPERIMENT` to `info`, `INVENTORY` to `info`. It is a system mapping,
  not a value semgrep reported. Unknown or non-string severity values still
  raise `FindingError`.

#### Planner and adapter integration

- The Gen-1 static plan template remains deterministic and non-adaptive; it
  gained two optional, conditionally planned steps (`s4-gitleaks` and
  `s5-semgrep`) with `target_kind` set to `fs_path`.
- Both new steps carry no dependencies on each other or on `bandit`, so one
  scanner's failure does not cascade-skip another.
- `pyproject.toml` lists `vuln_hunter.adapters_ext` among the packaged
  distributions. Both registrations are idempotent and happen at CLI start-up,
  not at module import.

#### Report and completeness status expression

- CR-02 remediation is implemented as a compatibility shim: no `PARTIAL` value
  was added to the frozen core status enum, and no frozen file was modified.
  Completeness is carried in `meta["completeness"]` and
  `meta["completeness_reasons"]`, and surfaced through a
  `[completeness=...]` detail prefix that the frozen `report.py` renders in its
  step table via `r['status']` and `r.get('reason') or r.get('detail','')`.
- `COMPLETE` harvests findings as `COMPLETED`; `PARTIAL` harvests findings as
  `COMPLETED` but is explicitly labelled as not a complete scan; `INCOMPLETE`
  returns `FAILED` and harvests nothing (fail-closed). A non-zero exit with
  partial results is never presented as success.
- A report lacking the `errors` field is classified `completeness unverified`;
  one lacking the `paths` object is classified `coverage unverified`.
- The append-only hash-chained JSONL evidence journal (`journal.py`, with
  `seq` / `prev` / `h` and `verify()`) and the Markdown report renderer
  continue to record honest limitations on every run.

#### Documentation and internationalisation (partial delivery)

- English `README.md` is the single source of technical fact; the zh-CN, ja,
  ko, es and fr translations under `docs/i18n/` were brought into line with it.
  All six retain the 12-section structure, the language switcher, localised
  navigation anchors and the existing `assets/logo.svg` / `assets/banner.gif`
  image paths.
- Sections 2 and 4 now describe the Gitleaks and Semgrep adapters and the
  unified Finding Schema with their optional / unverified boundary; section 11
  now separates implemented, not-verified and not-implemented items and states
  that packaging must be judged by a build of this version.
- Removed the stale passing-check badge, the pre-asserted offline test-suite
  and check-count claim, and the obsolete packaging smoke-test claim. The
  section 8 authorisation warning, the section 9 "API hardening is not a
  sandbox" statement and the six section 10 limitations are retained.
- `Gitleaks` and `Semgrep` are kept as English proper names with no new
  localised coinages; the five translations use neutral section 11 wording
  semantically aligned with the English master.
- `CONTRIBUTING.md`: the project layout now lists `adapters_ext/` and
  `findings.py`; the assets line lists `logo.svg / banner.gif / banner.svg`;
  the testing section uses neutral wording with no hard-coded suite count and
  no pre-asserted results. The existing `nuclei`/`bandit` SKIPPED note is
  preserved unchanged.
- The brand assets `assets/logo.svg`, `assets/banner.svg` and
  `assets/banner.gif` were not modified; their original bytes are unchanged.

### Verification Status

- The items above are **code and documentation facts established by reading the
  repository**, not by executing the tools.
- A read-only final audit of the documentation changes compared the seven
  document diffs with the frozen specification and checked section 11 semantics
  across six languages, Markdown structure, links, anchors and image paths, the
  CONTRIBUTING change scope, and the unchanged assets, frozen core files,
  backup baseline and Git state. No failing check was found; items without
  evidence were explicitly recorded as NOT VERIFIED rather than as passing.
- No test suite, build, packaging step, security scan or real-tool end-to-end
  run was executed for this changelog entry. Formal acceptance items F3-F9 and
  F11 remain NOT RUN; F1, F2 and F10 are N/A for this phase and are not marked
  PASS. No acceptance item has been pre-filled as PASS.
- No Git commit, tag, push or GitHub Release has been created for this entry.

### Known Limitations

**Not implemented (confirmed)**

- Gen-2 is not implemented in this repository. The Gen-1 planner is a static,
  deterministic template rather than a model-driven or adaptive planner.
- The fused-logo deliverable is not delivered. This release is a **documentation
  and internationalisation partial delivery**; the existing logo is unchanged
  and the brand upgrade is not complete.

**Verification not completed**

- Real-tool end-to-end verification has not been completed. Adapter code being
  present is not evidence of a verified tool run.
- Phase B has not been executed. The W1-03, W1-04, W1-06 and CR-06 items remain
  open, and the real Semgrep baseline has not been verified.
- Linux/macOS verification and CI are not in place; the implementation is
  Windows-first, and non-Windows process-tree cleanup is limited to a root
  kill.
- F3-F9 and F11 formal acceptance items have not been formally executed;
  F1/F2/F10 are N/A. No PASS value is recorded for any of them.
- Browser rendering, narrow-screen mobile layout and native-speaker review of
  the five non-English README files have not been verified.

**Actual constraints**

- API hardening is not an operating-system-level sandbox; tool output is
  recorded verbatim and unverified results are never marked as confirmed
  vulnerabilities.
- pyproject.toml and the runtime version constant identify this release
  candidate as 0.2.0rc1. This changelog entry records the release candidate
  state and does not imply that a package build, Git tag, push, or GitHub
  Release has been completed.
- Packaging must be judged by a build of this version; older build artifacts
  (`dist/`) are not evidence for the current release. The repository makes no
  pre-asserted "all green" or passing-check-count claim.
- Journal tail truncation is detectable only when an external head anchor was
  saved; in-report anchors serve consistency checks only.
- The `nuclei` path fallback assumes one local `~/Tools/nuclei/` layout, and
  the Windows process-tree cleanup drill does not constitute an absolute
  guarantee of residual-free termination.
