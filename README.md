<div align="center">

<img src="assets/logo.svg" alt="DualVerify-Sentinel logo — deep navy shield with dual verification check, cyan orbit nodes and the DVS wordmark" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**A policy-driven security validation engine built around explicit authorization, deterministic execution, and verifiable evidence.**

Deterministic execution. Explicit authorization boundaries. Auditable security evidence.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="assets/banner.svg" alt="DualVerify-Sentinel banner — shield mark, project name, one-line description and authorized-testing-only notice" width="720">

[![Star on GitHub](https://img.shields.io/badge/Star_on-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Star](https://img.shields.io/badge/Star-grey?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#sec-7)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#sec-3)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#sec-5)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#sec-8)

**English** · [中文](docs/i18n/README.zh-CN.md) · [日本語](docs/i18n/README.ja.md) · [한국어](docs/i18n/README.ko.md) · [Español](docs/i18n/README.es.md) · [Français](docs/i18n/README.fr.md)

[Overview](#sec-1) · [Capabilities](#sec-2) · [Quick start](#sec-4) · [Safety](#sec-5) · [Platform testing](#sec-7) · [Contribute](#sec-9) · [Security](SECURITY.md)

> ⭐ **If this project is useful, please star the repository. Community testing and contributions are welcome.**

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY**

</div>

---

<a id="sec-1"></a>
## 1. What is DualVerify-Sentinel?

DualVerify-Sentinel (DVS) is a **policy-driven security validation engine**: every
execution step is checked against a machine-readable authorization scope, recorded
in a tamper-evident evidence journal, and **fail-closed** — missing, corrupted or
expired authorization produces a refusal, never a skipped check.

It is a security-engineering foundation layer: an authorization gate plus a
deterministic execution engine. Gen-1 planning is a **static, rule-based
template**, not a model-driven or adaptive planner.

**What DVS is not today:** a general-purpose agent platform, an LLM agent runtime,
a model-driven autonomous decision system, or an OS-level sandbox. These are
long-term directions, not current capabilities.

<a id="sec-2"></a>
## 2. What it does today

Every capability below is enforced by explicit code paths, not by model judgment.

| Capability | What is implemented |
|---|---|
| **Explicit Authorization** | Scope JSON validated in an **isolated subprocess**; scope hash, mode, target and window are re-verified independently at execution time. Missing, corrupt or expired scope → REFUSED. No bypass path exists. |
| **Policy-driven Execution** | Five modes with increasing risk ceilings: `passive` (R0), `safe_scan` (R1), `vuln_validation` (R2), `attack_simulation` (R3), `high_risk` (R4). Explicit decision rules stop the loop on refusal, abort or failure; targets are never expanded. |
| **Risk-aware Controls** | TaskGraph state machine with hard budgets (max 32 nodes, spawn depth 2, 8 spawns), dynamic spawns gated by parent COMPLETED status, and a 12-step check chain per step. No destructive techniques, no persistence, no payload building, no exfiltration of discovered data. |
| **Security Tool Integration** | Core adapters for `nuclei` and `bandit`; optional `gitleaks` and `semgrep` adapters in `vuln_hunter/adapters_ext/` (local rule files only, no network rule fetching). All adapter output is normalised through the unified Finding Schema (`findings.py`). Missing binaries are skipped gracefully with a preflight report. |
| **Verifiable Audit Evidence** | Append-only SHA-256 hash chain (`seq` / `prev` / `h`) with tamper and reorder detection. An audit failure exits with code 3 instead of presenting an uncertified result as normal. |
| **Honest, Structured Reporting** | Findings are recorded as-is; unverified tool output is never labelled a confirmed vulnerability; known limitations are listed in every report; no detection-correctness or accuracy claim is made. |

> Adapters are **implemented as code**. Their presence is not evidence of a
> verified real-tool run — real-tool end-to-end verification has not been
> completed (see section 8).

<a id="sec-3"></a>
## 3. Requirements

| Requirement | Detail |
|---|---|
| Python | >= 3.10 (verified on 3.13.14) |
| Dependencies | **Standard library only** — no third-party runtime dependencies |
| OS | Windows **verified**; Linux / macOS **not yet verified** — see section 7 |
| Optional external tools | `nuclei`, `bandit`, `gitleaks`, `semgrep` — skipped gracefully if absent |

<a id="sec-4"></a>
## 4. Install and quick start

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# Windows (CMD):        .venv\Scripts\activate.bat
# Linux/macOS:          source .venv/bin/activate

pip install .
```

`pip install -e .` is also supported for development.

**Step 1 — always validate the scope file first:**

```bash
dvs gate-check scripts/example-scope.json
# 0 = valid · 1 = refused · 2 = usage error
```

**Step 2 — run a validation:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# or: python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modes (increasing risk ceiling): `passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk` (R0–R4). `nuclei` is only invoked at R2+.

Exit codes: `0` all steps COMPLETED · `1` finished with failures/refusals ·
`2` gate/policy-level refusal (nothing executed) · `3` **audit failure** (the
journal is unwritable or unverifiable, so results are not certified).

`scripts/example-scope.json` is a fictional example — **not a real authorization**.

<a id="sec-5"></a>
## 5. Authorization and safety

> ⚠️ **Use DVS only against systems you own or operate, local lab targets, or
> hosts for which you hold explicit written authorization from the owner.**

Unauthorized, out-of-scope, expired-window or corrupted configurations are
refused. There is no code path that skips authorization.

- Entries are matched by **parsed hostname equality**; an entry without a port
  matches any port on that host. **CIDR ranges are not supported** — use `host`
  or `host:port` entries.
- The authorization window is re-checked **at every execution step**; expiry
  mid-run aborts further steps.
- Scope content is hash-bound into each run ticket; changing the scope
  invalidates outstanding tickets.
- Filesystem-scoped steps skip only the network-scope check; all other policy
  checks still apply.

Keep real authorization records outside this repository. The bundled example
scope is fictional.

**API hardening is not an OS-level sandbox.** `RunTicket`'s frozen dataclass and
private registry are Python-level hardening; hostile in-process code could bypass
them. Strong isolation requires process-level measures, which are not
implemented. The CLI is the only supported entry point.

<a id="sec-6"></a>
## 6. Evidence and honest reporting

The audit journal is append-only and hash-chained; tampering or reordering is
detected, and an audit failure is surfaced explicitly rather than hidden. Run
reports distinguish complete, partial and incomplete results; incomplete results
fail closed and do not contribute harvested findings.

Two boundaries are worth stating plainly: tool output is recorded verbatim and
unverified output is never promoted to a confirmed vulnerability; and a journal
tail truncation can only be detected when an external head anchor has been saved.

<a id="sec-7"></a>
## 7. Platform compatibility and community testing

**Community testing is welcome. Help expand platform compatibility.**

DVS is currently **Windows-first**. On Windows, the timeout path performs fielded
process-tree cleanup (`taskkill /T /F` runs before the root kill, with every
outcome recorded); the behaviour was exercised in a controlled drill but is not
an absolute guarantee of residual-free termination. On non-Windows platforms the
tree kill is skipped and only the root process is killed. The `nuclei` path
fallback also assumes one particular local installation layout.

Linux and macOS have **not** been verified, and CI does not yet cover them. If
you run DVS on another platform, please share what works and what does not via an
issue — adapter behaviour, process cleanup and packaging are especially useful.
Please do not include real target data, credentials or unauthorized scan output.

<a id="sec-8"></a>
## 8. Project status and direction

| | |
|---|---|
| **Delivered (Gen-1)** | Authorization gate, policy engine (R0–R4), TaskGraph, audit journal, structured reports, unified Finding Schema, and `nuclei` / `bandit` / `gitleaks` / `semgrep` adapters as code paths. |
| **Being built / verified** | Real-tool end-to-end verification, non-Windows verification and CI, and packaging verification for this exact version. Test suites live under `tests/` — run them and rely on their actual output; this repository makes no pre-asserted "all green" claim. |
| **Long-term direction** | Model-driven planning, stronger process-level isolation, and broader platform support. These are directions only and are **not implemented** in Gen-1. |

The current planning layer is a deterministic static template. Adapter code being
present is not evidence of a verified tool run, and API hardening is not an
OS-level sandbox. Packaging must be judged by a build of this version; older
build artifacts are not evidence for the current release. This is an engineering
foundation, not a production-ready assessment product.

<a id="sec-9"></a>
## 9. Contribute and get involved

A star helps other people find the project. Trying DVS against your own lab
targets, reporting what you see, and opening a pull request are all equally
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

Ways to help:

- **Platform adaptation and compatibility testing** — Linux/macOS behaviour,
  process-tree cleanup, packaging.
- **Security tool providers / adapters** — new integrations that respect the
  authorization gate and fail-closed design.
- **Test cases and regression baselines** — repeatable, evidence-producing checks.
- **Documentation and translations** — the six README languages, examples, clarity.
- **Bug fixes and code quality** — small, focused changes with runnable evidence.
- **Security research** — follow [SECURITY.md](SECURITY.md); never open a
  public issue for an undisclosed vulnerability.
- **Usage experience and feature ideas** — open an issue to agree scope first.

Use **Issues** for bugs, platform results and proposals; use **Pull Requests** for
code and documentation changes. Do not attach real target data, credentials,
private authorization records or unauthorized scan output to any issue or PR.

<a id="sec-10"></a>
## 10. License and links

- **License**: MIT — see [LICENSE](LICENSE).
- **Security policy**: [SECURITY.md](SECURITY.md).
- **Contributing guide**: [CONTRIBUTING.md](CONTRIBUTING.md).
- **Issues & PRs**: [open an issue](https://github.com/zyh798-cell/DualVerify-Sentinel/issues) · [open a pull request](https://github.com/zyh798-cell/DualVerify-Sentinel/pulls).
- **Translations**: 中文 · 日本語 · 한국어 · Español · Français (see the language switcher above).

---

<div align="center"><sub>DualVerify-Sentinel · Engineered for Trust. Built for Control. · MIT © 2026 zyh798-cell</sub></div>
