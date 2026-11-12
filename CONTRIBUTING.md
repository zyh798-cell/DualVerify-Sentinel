# Contributing to DualVerify-Sentinel

Thanks for your interest in improving DualVerify-Sentinel. This document
describes the project layout, how to run the test suites, and how to propose
changes. Keep it honest: this repository makes no pre-asserted claims — all
results come from actually running the code.

## Project layout

```
vuln_hunter/          Core package (import name: vuln_hunter; CLI: dvs)
  __main__.py         CLI entry point, exit codes 0/1/2/3
  policy.py           PolicyEngine, R0-R4 modes, RunTicket
  gate_check.py       Scope validation (runs in an isolated subprocess)
  planner.py          Gen-1 static plan template (deterministic, not model-driven)
  taskgraph.py        Task state machine with hard budgets
  decision.py         Explicit decision rules P0-P8 (NOT model-driven)
  loop.py             AutonomousLoop scheduling, cascade, P9 opt-in spawning
  runner.py           12-step per-step check chain
  adapters.py         Tool adapters (probe / nuclei / bandit), timeout + tree cleanup
  adapters_ext/       Optional adapters: gitleaks / semgrep (local rules only)
  findings.py         Unified Finding Schema (severity + record validation)
  journal.py          Append-only SHA-256 hash-chain evidence journal
  report.py           Run report with honest limitations
tests/                Plain-script test suites (no test framework required)
scripts/              example-scope.json (fictional example scope)
docs/i18n/            README translations (zh-CN, ja, ko, es, fr)
assets/               logo.svg / banner.gif / banner.svg
```

## Running the tests

No test runner is required — the test suites are standalone scripts located
under `tests/`. Run the suite relevant to your change and rely on its actual
output:

```bash
python tests/<suite>.py
```

This repository does not assert "all green" without evidence and makes no
pre-asserted passing-check-count claim. Some suites print a
`PASS=n FAIL=n SKIP=n` summary; a `SKIP` is a designed skip (e.g. an optional
external tool is not installed), never a hidden failure.

## Installation problems

| Symptom | Cause / fix |
|---|---|
| PowerShell refuses `Activate.ps1` | Windows execution policy blocks scripts for this session: run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, or use the CMD activation `.venv\Scripts\activate.bat`. |
| `dvs` is not found after install | The venv is not activated in the current shell, or `pip install .` was skipped. Re-activate the venv and reinstall. |
| `gate-check` exits 2 unexpectedly | The scope file is missing, corrupt, expired, or out of policy. Run `dvs gate-check <file>` alone for the reason. |
| `nuclei`/`bandit` steps show SKIPPED | Optional external tools are not on PATH. The run completes without them; this is by design. |

## Proposing changes

1. Open an issue describing the problem or proposal first, so scope can be
   agreed before code is written.
2. Keep changes minimal and consistent with the fail-closed design: new behavior
   must refuse rather than guess, and must not silently weaken scope, window,
   or ticket checks.
3. Add or extend a test suite for any behavior change, and include the actual
   run output (exit code and PASS/FAIL/SKIP counts) in the PR description.
4. Do not add autonomous execution capabilities, new scan targets, or changes to
   the R0-R4 risk ladder without prior design review and agreement.

## Security reports

Do not open public issues for security problems. Follow the guidance in
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT
License of this repository.
