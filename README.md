<div align="center">

# DualVerify-Sentinel

**Deterministic, authorization-gated security validation engine.**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 Stable · MIT

<img src="assets/banner.gif" alt="DualVerify-Sentinel — pixel-style animated banner showing the project title with a scanline sweep and data-flow accents" width="720">

**DualVerify-Sentinel — Deterministic Security Validation Engine**
⚠️ **AUTHORIZED SECURITY TESTING ONLY**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](README.md#requirements)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](README.md#known-limitations)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#project-status)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#project-status)

**English** · [中文](docs/i18n/README.zh-CN.md) · [日本語](docs/i18n/README.ja.md) · [한국어](docs/i18n/README.ko.md) · [Español](docs/i18n/README.es.md) · [Français](docs/i18n/README.fr.md)

</div>

---

## 1. What is this?

DualVerify-Sentinel is a **rule-based security validation engine** (explicitly **NOT
model-driven**): every execution step is policy-checked against a machine-readable
authorization scope, journaled in a tamper-evident hash chain, and **fail-closed** —
missing, corrupted, or expired authorization means *refusal*, never a skipped check.

It is the security-engineering foundation layer (authorization gate + reliable
execution engine) of a planned next-generation verification architecture. The
planning/decision layer is intentionally deterministic in Gen-1.

## 2. What can it do?

| Capability | How it works |
|---|---|
| Authorization gate | Machine-readable scope JSON validated in an **isolated subprocess**; missing/corrupt/expired → REFUSED (exit 2). No bypass path exists. |
| Run tickets | Adapters accept only tickets issued by the policy engine; scope hash, mode, target, window re-verified **independently at execution time**. |
| Safe execution | 12-step check chain per step; no destructive techniques, no persistence, no payload building, no exfiltration of discovered data. |
| Audit journal | Append-only hash chain (`seq`/`prev`/`h`, SHA-256); tamper/reorder detection; audit failure exits with code 3 instead of masquerading as a normal result. |
| Deterministic decision loop | Explicit rules P0–P8: any refusal/abort/failure stops the loop; targets are **never** expanded. |
| Task graph | State machine with hard budgets (max 32 nodes, spawn depth 2, 8 spawns); dynamic spawns gated by parent COMPLETED status. |
| Optional tool adapters | `nuclei` (template scan) and `bandit` (static analysis) — gracefully SKIPPED with a preflight report if not installed. |
| Honest reporting | Findings recorded as-is; unverified output is never labeled a confirmed vulnerability; known limitations are listed in every report. |

## 3. Use cases

- Validating your own lab targets and explicitly authorized hosts.
- Running repeatable, evidence-producing security checks with a full audit trail.
- As a foundation layer for building higher-level verification pipelines.

## 4. Requirements

| Requirement | Detail |
|---|---|
| Python | >= 3.10 (tested on 3.13.14 only) |
| Third-party dependencies | **None** — standard library only |
| OS | Windows **Verified**; Linux/macOS **Not Yet Verified** |
| External tools (optional) | `nuclei`, `bandit` — skipped gracefully if absent |

## 5. Installation

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

pip install .
```

`pip install -e .` (editable install) is also supported for development.

## 6. Basic usage

**Step 1 — validate the scope file (always do this first):**

```bash
dvs gate-check scripts/example-scope.json
# exit 0 = scope valid · exit 1 = refused
```

**Step 2 — run a validation:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# or: python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modes (increasing risk ceiling): `passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk` (R0–R4). `nuclei` is only invoked at R2+.

Exit codes: `0` all steps COMPLETED · `1` finished with failures/refusals ·
`2` gate/policy-level refusal (nothing executed) · `3` **audit failure**
(journal unwritable/unverifiable — results are not certified).

`scripts/example-scope.json` is a fictional example — **not a real authorization**.

## 7. Scope semantics

- Entries are matched by **parsed hostname equality** (an entry without a port
  matches any port on that host). **CIDR ranges are NOT supported** — use
  `host` or `host:port` entries.
- The authorization window is re-checked **every execution step**; expiry mid-run
  aborts further steps.
- Scope content is hash-bound into each run ticket; changing the scope invalidates
  outstanding tickets.
- Filesystem-scoped steps skip only the network-scope check; all other policy
  checks still apply.

## 8. Authorization and safety

> ⚠️ **Use this tool ONLY against systems you own or operate, local lab targets,
> or hosts for which you hold explicit written authorization from the owner.**
> Unauthorized, out-of-scope, expired-window, or corrupted configurations are
> refused (fail-closed). There is no code path that skips authorization.

The bundled example scope is fictional. Real engagements require a real,
machine-readable authorization record — keep it outside this repository.

## 9. API hardening is NOT a sandbox

RunTicket's frozen dataclass and private registry are **API hardening**, not
sandboxing — hostile in-process code can bypass any Python-level check. Strong
isolation requires process-level measures (not implemented). The CLI is the only
supported entry point.

## 10. Known limitations

1. **No in-process sandbox** — see section 9.
2. **Windows-first** — the Windows timeout path performs fielded process-tree
   cleanup (`taskkill /T /F` runs before the root kill, with every outcome
   recorded); it is verified in a controlled three-layer drill but is **not an
   absolute guarantee** — no runtime residual check, `rc=0` does not prove the
   whole tree was cleaned, and real Nuclei descendant shapes are unverified. On
   non-Windows platforms the tree kill is skipped (root kill only). The nuclei
   path fallback assumes one local `~/Tools/nuclei/` layout.
3. **No detection-correctness promise** — tool output is recorded verbatim;
   unverified results are never marked as confirmed vulnerabilities.
4. **Linux/macOS unverified** — CI does not cover non-Windows platforms.
5. **Journal tail truncation** — detectable only if an external head anchor was
   saved; in-report anchors are for consistency checks only.
6. **Gen-1 planner is a static template** — planning is deterministic, not
   model-driven or adaptive.

## 11. Project status

- **Gen-1 is stable**: 18 offline test suites, 427+ checks passing locally
  (Windows, Python 3.13.14). Packaging smoke-tested via wheel/sdist builds.
- A **Gen-2 architecture** (a separate, future repository) is planned with
  proposal/adjudication separation. Gen-2 work will not happen in this repository.
- Full test commands are listed in the test suites under `tests/` — run them and
  trust the actual results; this repository makes no pre-asserted "all green" claim.

## 12. License & feedback

- **License**: MIT — see [LICENSE](LICENSE).
- **Security policy**: see [SECURITY.md](SECURITY.md).
- **Contributing**: see [CONTRIBUTING.md](CONTRIBUTING.md).
- Issues and pull requests are welcome. For security-relevant reports, please
  follow the guidance in SECURITY.md rather than opening a public issue.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
