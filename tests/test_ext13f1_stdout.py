"""EXT-1.3-F1 regression: stdout compatibility + raw-secret lifecycle.

EVIDENCE CLASS: MOCK / UNIT + OFFICIAL-CHAIN FAULT INJECTION.
No real gitleaks binary is required or called here; real-scan evidence lives
in the outside-project EXT-1.3-F1 e2e report. All fixtures are fictional and
assembled at runtime with `secrets` — no real credentials, no literals.

Coverage:
  A  command construction / binary resolution (unit)
  B  _run() parser paths: [], blank, malformed JSON, abnormal rc, timeout,
     spawn exception, FindingError skip  (MOCK UNIT TESTS)
  C  official Executor chain with fault-injected _spawn (NOT a real scan)
  D  secret-residue sweep incl. variants over every observable field
  E  unified Finding schema + severity-source alias
"""
import base64
import io
import json
import secrets
import string
import subprocess
import sys
import tempfile
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vuln_hunter.adapters_ext.gitleaks as gl_mod  # noqa: E402
from vuln_hunter.journal import EvidenceJournal  # noqa: E402
from vuln_hunter.policy import PolicyEngine  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402

failures = 0
checks_run = 0


def check(cid, cond, desc):
    global failures, checks_run
    checks_run += 1
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {cid}: {desc}")


def tok(n, alphabet=None):
    alphabet = alphabet or (string.ascii_letters + string.digits)
    return "".join(secrets.choice(alphabet) for _ in range(n))


SECRET_A = "AKIA" + tok(16, string.ascii_uppercase + string.digits)
SECRET_B = "ghp_" + tok(36)
SECRET_C = tok(32)
SECRETS = [SECRET_A, SECRET_B, SECRET_C]
VARIANTS = set()
for s in SECRETS:
    VARIANTS.update({s, s.lower(), s.upper(),
                     urllib.parse.quote(s, safe=""),
                     base64.b64encode(s.encode()).decode(),
                     s[:12], s[-12:]})
VARIANTS = sorted(VARIANTS, key=len)

NON_WHITELISTED_VALUES = [
    "fictional-author-" + tok(8), "fictional@example.invalid",
    "fictional-commit-message", "dead" + "beef" + tok(8),
    "fictional-fingerprint-" + tok(8),
]


def no_secret(*texts):
    blob = "\n".join(str(t) for t in texts)
    return not any(v and v in blob for v in VARIANTS)


def fake_record(secret=SECRET_A, rule="f1-generic-api-key", line=4,
                tags=None, malformed=None):
    rec = {
        "RuleID": rule,
        "File": "f1/password.txt",
        "StartLine": line, "EndLine": line,
        "Description": "Fictional credential-shaped field",
        "Tags": ["key", "lab"] if tags is None else tags,
        "Link": "https://example.invalid/rules/f1",
        "Secret": secret,
        "Match": 'db_password = "' + secret + '"',
        "Author": NON_WHITELISTED_VALUES[0],
        "Email": NON_WHITELISTED_VALUES[1],
        "Message": NON_WHITELISTED_VALUES[2],
        "Commit": NON_WHITELISTED_VALUES[3],
        "Fingerprint": NON_WHITELISTED_VALUES[4],
        "Entropy": 3.9, "StartColumn": 1, "EndColumn": 2,
        "SymlinkFile": "", "Date": "2026-01-01T00:00Z",
    }
    if malformed:
        rec.update(malformed)
    return rec


class FakeProc:
    def __init__(self, rc, stdout, stderr="fictional-stderr"):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


class Spawn:
    def __init__(self, rc=1, stdout="[]", exception=None):
        self.rc, self.stdout, self.exception = rc, stdout, exception
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((list(cmd), timeout))
        if self.exception is not None:
            raise self.exception
        return FakeProc(self.rc, self.stdout)


REAL_SPAWN = gl_mod._spawn
REAL_WHICH = gl_mod.shutil.which
REAL_FALLBACKS = gl_mod.GITLEAKS_FALLBACKS


def patched(spawn):
    gl_mod._spawn = spawn
    gl_mod.shutil.which = lambda n: "/fake/gitleaks" if n == "gitleaks" else None
    gl_mod.GITLEAKS_FALLBACKS = []

    def restore():
        gl_mod._spawn = REAL_SPAWN
        gl_mod.shutil.which = REAL_WHICH
        gl_mod.GITLEAKS_FALLBACKS = REAL_FALLBACKS
    return restore


TMP = tempfile.mkdtemp(prefix="dvs-ext13f1-test-")


def unit_run(spawn, timeout=30):
    log = io.StringIO()
    restore = patched(spawn)
    try:
        res = gl_mod.GitleaksAdapter()._run(TMP, timeout, log, None)
    finally:
        restore()
    return res, log.getvalue()


def observable(res, log):
    return "\n".join([res.status, str(res.detail), json.dumps(res.findings,
                     ensure_ascii=False), json.dumps(res.meta or {}, ensure_ascii=False), log])


# ==========================================================================
# A. command construction + binary resolution
# ==========================================================================
restore = patched(Spawn())
try:
    cmd = gl_mod.GitleaksAdapter().build_command(TMP)
finally:
    restore()
check("F1-A01", cmd == ["/fake/gitleaks", "dir", TMP,
                        "--report-format", "json", "--report-path", "-",
                        "--redact"],
      "real 8.30.1 command: dir + JSON + stdout report path + redact")
check("F1-A02", cmd[-2:] == ["-", "--redact"] and "--report-path" in cmd,
      "--report-path - present; no extra scan path in argv")
resolved = gl_mod.gitleaks_binary()
if resolved:
    p = Path(resolved)
    check("F1-A03", p.is_file() and p.stat().st_size > 0,
          "if a binary resolves it is a real non-empty executable "
          "(0-byte winget alias rejected)")
else:
    check("F1-A03", True,
          "no gitleaks on PATH in this environment (portable unit test skips)")

# ==========================================================================
# B. parser paths (MOCK UNIT TESTS)
# ==========================================================================
res, log = unit_run(Spawn(rc=0, stdout="[]"))
check("F1-B01", res.status == "COMPLETED" and res.findings == [],
      "rc=0 + JSON [] -> COMPLETED, 0 findings")

for cid, rc in (("F1-B02", 0), ("F1-B03", 1)):
    res, log = unit_run(Spawn(rc=rc, stdout=""))
    check(cid, res.status == "FAILED" and "empty report" in res.detail
          and res.findings == [],
          f"rc={rc} + BLANK stdout -> FAILED, NEVER a clean result")

res, log = unit_run(Spawn(rc=1, stdout=json.dumps([fake_record()])))
f0 = res.findings[0]
check("F1-B04", res.status == "COMPLETED" and len(res.findings) == 1
      and res.ok is True,
      "rc=1 (leaks found) + valid JSON -> COMPLETED with 1 real finding")
SCHEMA = {"schema_version", "finding_id", "tool", "finding_type", "title",
          "severity", "target", "location", "rule_id", "description",
          "evidence", "evidence_redacted", "references"}
check("F1-B05", set(f0) - {"name"} == SCHEMA,
      "unified Finding keeps exactly the 13 schema fields (+ additive alias)")
check("F1-B06", f0["severity"] == gl_mod.GITLEAKS_DEFAULT_SEVERITY
      and "为系统默认策略" in f0["name"]
      and "非 Gitleaks 原生判定" in f0["name"],
      "severity is a documented SYSTEM default, never a tool fact")
check("F1-B07", all(k not in f0 for k in
                    ("Secret", "Match", "Author", "Email", "Message",
                     "Commit", "Fingerprint", "Entropy")),
      "no non-whitelisted field copied into the Finding")
check("F1-B08", no_secret(observable(res, log))
      and not any(v in observable(res, log) for v in NON_WHITELISTED_VALUES),
      "normal path: no secrets / non-whitelisted metadata in any observable")

bad = "garbage {" + SECRET_A + " " + SECRET_B + "}"
res, log = unit_run(Spawn(rc=1, stdout=bad))
check("F1-B09", res.status == "FAILED" and "not valid JSON" in res.detail
      and no_secret(observable(res, log)),
      "JSON parse exception path: FAILED, fixed detail, no raw stdout echo")

res, log = unit_run(Spawn(rc=1, stdout=json.dumps(
    [fake_record(secret=SECRET_C, malformed={"Tags": "not-a-list"})])))
check("F1-B10", res.status == "COMPLETED" and res.findings == []
      and res.meta["records_skipped"] == 1
      and no_secret(observable(res, log)),
      "FindingError skip path: auditable count, no record values in output")

res, log = unit_run(Spawn(rc=7, stdout=json.dumps([fake_record()])))
check("F1-B11", res.status == "FAILED" and "exit 7" in res.detail
      and res.findings == [] and no_secret(observable(res, log)),
      "abnormal exit code: FAILED, findings never harvested, no raw output")

res, log = unit_run(Spawn(exception=subprocess.TimeoutExpired(
    cmd="gitleaks", timeout=1, output="partial " + SECRET_A)))
check("F1-B12", res.status == "TIMEOUT" and "exceeded" in res.detail
      and no_secret(observable(res, log)),
      "timeout path: no partial secret-bearing output retained")

res, log = unit_run(Spawn(exception=RuntimeError("boom " + SECRET_B)))
check("F1-B13", res.status == "FAILED" and "RuntimeError" in res.detail
      and no_secret(observable(res, log)),
      "spawn exception path: exception TYPE only, no raw stdout/stderr")

# ==========================================================================
# C. OFFICIAL Executor chain with fault-injected spawn (NOT a real scan)
# ==========================================================================
ALL_CALLS = []


def chain(spawn, mode="safe_scan", target=TMP):
    d = Path(tempfile.mkdtemp(prefix="dvs-ext13f1-chain-"))
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    scope = {"client": "f1-test", "in_scope": ["127.0.0.1"],
             "out_of_scope": ["everything else"],
             "window": (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
                        f"{(now + timedelta(hours=2)).strftime(fmt)}"),
             "confirmed_by": "f1-test"}
    journal = EvidenceJournal(d / "journal.jsonl")
    ex = Executor(PolicyEngine(scope, mode), journal, d / "ev",
                  sleep_fn=lambda s: None, max_attempts=1)
    step = {"id": "s4-gitleaks", "adapter": "gitleaks", "target": target,
            "timeout": 30, "target_kind": "fs_path"}
    restore = patched(spawn)
    try:
        rec = ex.run_step(step)
    finally:
        restore()
    ALL_CALLS.extend(spawn.calls)
    texts = [json.dumps(rec, ensure_ascii=False),
             json.dumps(ex.findings(), ensure_ascii=False),
             (d / "journal.jsonl").read_text(encoding="utf-8")]
    texts += [p.read_text(encoding="utf-8") for p in
              sorted((d / "ev").glob("*.log"))]
    return rec, ex, "\n".join(texts)


# registration is explicit; import side effects remain absent
from vuln_hunter.adapters_ext import register_gitleaks  # noqa: E402
register_gitleaks()
rec, ex, blob = chain(Spawn(rc=0, stdout="[]"))
check("F1-C01", rec["status"] == "COMPLETED" and ex.findings() == []
      and no_secret(blob),
      "official chain + [] -> COMPLETED, 0 findings, no residue")
rec, ex, blob = chain(Spawn(rc=1, stdout=json.dumps([fake_record()])))
check("F1-C02", rec["status"] == "COMPLETED" and len(ex.findings()) == 1
      and no_secret(blob),
      "official chain + valid JSON -> COMPLETED with 1 finding, no residue")
rec, ex, blob = chain(Spawn(rc=0, stdout=""))
check("F1-C03", rec["status"] == "FAILED" and ex.findings() == []
      and no_secret(blob),
      "official chain + BLANK stdout -> FAILED (never a clean result)")
rec, ex, blob = chain(Spawn(rc=1, stdout=bad))
check("F1-C04", rec["status"] == "FAILED" and no_secret(blob),
      "official chain + malformed JSON -> FAILED, no residue")
rec, ex, blob = chain(Spawn(rc=7, stdout=json.dumps([fake_record()])))
check("F1-C05", rec["status"] == "FAILED" and ex.findings() == []
      and no_secret(blob),
      "official chain + abnormal exit -> FAILED, no findings harvested")

# ==========================================================================
# D. aggregate residue sweep over ALL collected observables
# ==========================================================================
check("F1-D01", no_secret(blob) and not any(
      v in blob for v in NON_WHITELISTED_VALUES),
      "all official-chain observables free of secrets and unapproved metadata")
check("F1-D02", len(ALL_CALLS) >= 5
      and all("--report-path" in c[0] and "-" in c[0]
              and "--redact" in c[0] and no_secret(json.dumps(c[0]))
              for c in ALL_CALLS),
      f"all {len(ALL_CALLS)} official-chain spawn calls use the fixed "
      "command and contain no secret")
check("F1-D03", len(VARIANTS) >= 15,
      f"residue sweep covers {len(VARIANTS)} variants of 3 fictional secrets")

print("-" * 78)
print(f"EXT-1.3-F1 STDOUT TESTS: {checks_run - failures}/{checks_run} checks passed")
sys.exit(1 if failures else 0)
