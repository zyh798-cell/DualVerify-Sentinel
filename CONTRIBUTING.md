# Contributing to DualVerify-Sentinel

Thanks for your interest in improving DualVerify-Sentinel (DVS). This project is
an authorization-gated, deterministic security validation engine — contributions
that keep it honest, explicit and fail-closed are especially welcome.

> A star helps other people find the project. Trying DVS on your own lab targets,
> reporting what you see, and opening a pull request are all equally valuable.

## Where you can help

- **Platform adaptation and compatibility testing** — Linux/macOS behaviour,
  process-tree cleanup differences, packaging on your platform. Windows is the
  verified platform today; help expand coverage.
- **Security tool providers and adapters** — new integrations that respect the
  authorization gate, the R0–R4 risk ladder and the fail-closed design.
- **Test cases and regression baselines** — repeatable, evidence-producing checks.
- **Documentation and translations** — the six README languages
  (`README.md` plus `docs/i18n/README.{zh-CN,ja,ko,es,fr}.md`), examples, clarity.
- **Bug fixes and code quality** — small, focused changes with runnable evidence.
- **Security research and responsible disclosure** — see "Security reports" below.
- **Usage experience and feature ideas** — open an issue to agree scope first.

## Project layout

```
vuln_hunter/          Core package (import name: vuln_hunter; CLI: dvs)
  __main__.py         CLI entry point, exit codes 0/1/2/3
  policy.py           PolicyEngine, R0-R4 modes, RunTicket
  gate_check.py       Scope validation (runs in an isolated subprocess)
  planner.py          Gen-1 static plan template (deterministic, not model-driven)
  taskgraph.py        Task state machine with hard budgets
  decision.py         Explicit decision rules (NOT model-driven)
  loop.py             Loop scheduling and cascade
  runner.py           12-step per-step check chain
  adapters.py         Tool adapters (probe / nuclei / bandit), timeout + tree cleanup
  adapters_ext/       Optional adapters: gitleaks / semgrep (local rules only)
  findings.py         Unified Finding Schema (severity + record validation)
  journal.py          Append-only SHA-256 hash-chain evidence journal
  report.py           Run report with honest limitations
tests/                Plain-script test suites (no test framework required)
scripts/              example-scope.json (fictional example scope)
docs/i18n/            README translations (zh-CN, ja, ko, es, fr)
assets/               logo.svg / banner.svg / banner.gif
```

## Running the tests

No test runner is required — the suites are standalone scripts under `tests/`.
Run the suite relevant to your change and rely on its actual output:

```bash
python tests/<suite>.py
```

This repository makes no pre-asserted "all green" or passing-check-count claim.
Some suites print a `PASS=n FAIL=n SKIP=n` summary; a `SKIP` is a designed skip
(e.g. an optional external tool is not installed), never a hidden failure.

## Installation problems

| Symptom | Cause / fix |
|---|---|
| The Windows script host refuses `Activate.ps1` | The session execution policy blocks scripts: relax it for the current session only, or use the CMD activation `.venv\Scripts\activate.bat`. |
| `dvs` is not found after install | The venv is not activated in the current shell, or `pip install .` was skipped. Re-activate the venv and reinstall. |
| `gate-check` returns non-zero | The scope file is missing, corrupt, expired, or out of policy. Run `dvs gate-check <file>` alone for the reason. |
| `nuclei`/`bandit` steps show SKIPPED | Optional external tools are not on PATH. The run completes without them; this is by design. |

## Using Issues and Pull Requests

- **Issues** — bug reports, platform test results, documentation problems and
  feature proposals. Describe the environment and the actual output you observed.
- **Pull Requests** — code and documentation changes. Keep them minimal and
  consistent with the fail-closed design: new behaviour must refuse rather than
  guess, and must not silently weaken scope, window, or ticket checks. Add or
  extend a test suite for behaviour changes and include the actual run output
  (exit code and PASS/FAIL/SKIP counts) in the PR description.
- Do not add autonomous execution capabilities, new scan targets, or changes to
  the R0–R4 risk ladder without prior design review and agreement.
- Do not attach real target data, credentials, private authorization records,
  unauthorized scan output, or any sensitive information to an issue or PR. Use
  fictional or self-owned lab data only.

## Security reports

Do **not** open public issues for security problems. Follow the guidance in
[SECURITY.md](SECURITY.md) and prefer GitHub's private security advisory.

## License

By contributing you agree that your contributions are licensed under the MIT
License of this repository.
