"""EXT-1: Gitleaks adapter tests (mocked execution — no real tool call).

The gitleaks binary is NOT required: every test replaces the single
subprocess seam (gitleaks._spawn) with a scripted fake, so exit codes,
timeouts, invalid JSON and malformed records are all exercised without
installing or running anything.

SECURITY: all secret-shaped fixtures are fictional and assembled at
runtime. Nothing in this file prints secret material; checks only ever
print check ids and descriptions.

Coverage map (task book -> section):
  A  registration / identity / gate
  B  normal conversion + whitelist discipline + no secret residue
  C  multiple findings
  D  empty scan
  E  invalid JSON
  F  abnormal exit codes
  G  timeout
  H  file/line mapping
  I  finding_id stability
  J  unauthorized directory refusal (no spawn)
  K  malformed records
  L  cross-scenario secret-residue sweep

Run:  python tests/test_gitleaks_adapter.py
"""
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vuln_hunter.adapters as adapters_mod  # noqa: E402
import vuln_hunter.adapters_ext  # noqa: E402  (import has NO registration side effect)
import vuln_hunter.adapters_ext.gitleaks as gl_mod  # noqa: E402
from vuln_hunter.adapters import GateRequired  # noqa: E402
from vuln_hunter.adapters_ext import register_gitleaks  # noqa: E402
from vuln_hunter.adapters_ext.gitleaks import GitleaksAdapter  # noqa: E402

# EXT-1.2: registration is explicit; importing any module never registers.
register_gitleaks()

failures = 0
checks_run = 0


def check(cid, cond, desc):
    global failures, checks_run
    checks_run += 1
    status = "PASS" if cond else "FAIL"
    if not cond:
        failures += 1
    print(f"[{status}] {cid}: {desc}")


def raises_gate(fn):
    try:
        fn()
    except GateRequired:
        return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Fictional fixtures — secret shapes assembled at runtime, never real.
# ---------------------------------------------------------------------------
FAKE_SECRET_A = "AKIA" + "X" * 4 + "1234" * 3       # AWS-shaped, fictional
FAKE_SECRET_B = "ghp_" + "a" * 36                    # GitHub-shaped, fictional
FAKE_SECRET_C = "Pa55w0rd" + "-LIKE-FAKE-STRING"     # password-shaped, fictional
FAKE_BEARER_TOKEN = "T" * 20                         # bearer-shaped, fictional
ALL_SECRETS = [FAKE_SECRET_A, FAKE_SECRET_B, FAKE_SECRET_C, FAKE_BEARER_TOKEN]
FAKE_COMMIT = "dead" + "beefcafe1234"                # non-whitelisted metadata
FAKE_AUTHOR = "fictional-author"                     # non-whitelisted metadata
FAKE_EMAIL = "fictional@example.invalid"             # non-whitelisted metadata
NON_WHITELISTED = [FAKE_COMMIT, FAKE_AUTHOR, FAKE_EMAIL]


def fake_record(rule="faketool-aws-key", file="faketool/config.py", line=12,
                secret=FAKE_SECRET_A, end_line=None, tags=("key", "aws"),
                entropy=3.7):
    """One realistic gitleaks report record. Secret-bearing and
    non-whitelisted fields are populated ON PURPOSE so tests can prove
    they never leak into the unified Finding."""
    return {
        "Description": "Fictional AWS-shaped access key",
        "StartLine": line,
        "EndLine": line if end_line is None else end_line,
        "StartColumn": 5,
        "EndColumn": 40,
        "Match": f'aws_key = "{secret}"',          # secret-bearing: never read
        "Secret": secret,                           # secret-bearing: never read
        "File": file,
        "SymlinkFile": "",
        "Commit": FAKE_COMMIT,                      # non-whitelisted
        "Entropy": entropy,
        "Author": FAKE_AUTHOR,                      # non-whitelisted
        "Message": "fictional commit message",      # non-whitelisted
        "Date": "2026-01-01T00:00:00Z",             # non-whitelisted
        "Email": FAKE_EMAIL,                        # non-whitelisted
        "Fingerprint": f"{file}:{rule}:{line}",
        "Tags": list(tags) if isinstance(tags, (list, tuple)) else tags,
        "RuleID": rule,
        "Link": "https://example.invalid/rules/faketool-aws-key",
    }


class FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = "fictional-stderr"


class FakeRunner:
    """Replaces gl_mod._spawn. Scriptable result or exception; records calls."""

    def __init__(self, returncode=0, stdout="[]", exception=None):
        self.returncode = returncode
        self.stdout = stdout
        self.exception = exception
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((list(cmd), timeout))
        if self.exception is not None:
            raise self.exception
        return FakeProc(self.returncode, self.stdout)


REAL_SPAWN = gl_mod._spawn
OBSERVED = []  # (result, log_text) pairs for the final residue sweep


def run_adapter(target, fake, timeout=60, binary="/fake/gitleaks"):
    """Install the fake, run the adapter, capture the log, restore _spawn."""
    gl_mod._spawn = fake
    old_which = gl_mod.shutil.which
    gl_mod.shutil.which = lambda name: binary if name == "gitleaks" else None
    try:
        log = io.StringIO()
        result = GitleaksAdapter()._run(target, timeout, log)
        OBSERVED.append((result, log.getvalue()))
        return result, log.getvalue()
    finally:
        gl_mod._spawn = REAL_SPAWN
        gl_mod.shutil.which = old_which


def observable_blob(result, log_text):
    """Everything a downstream layer could observe from one run."""
    parts = [result.detail, log_text,
             json.dumps(result.meta, ensure_ascii=False, default=str)]
    for f in result.findings:
        parts.append(json.dumps(f, ensure_ascii=False, default=str))
    return "\n".join(parts)


def no_secret(blob):
    return not any(s in blob for s in ALL_SECRETS)


tmp = tempfile.TemporaryDirectory(prefix="dvs-gitleaks-test-")
TMP_DIR = tmp.name
tmp_file = Path(TMP_DIR) / "not-a-dir.txt"
tmp_file.write_text("fictional file content\n", encoding="utf-8")

print("=" * 78)
print("EXT-1 GITLEAKS ADAPTER TESTS (mocked execution)")
print("=" * 78)

# ==========================================================================
# A. registration / identity / gate
# ==========================================================================
check("A-01", adapters_mod._REGISTRY.get("gitleaks") is not None
      and isinstance(adapters_mod._REGISTRY["gitleaks"], GitleaksAdapter),
      "explicit register_gitleaks() registers the adapter in _REGISTRY")
check("A-02", adapters_mod.adapter_risk("gitleaks") == "R1",
      "adapter_risk('gitleaks') == R1 (local scan, no network)")
check("A-03", adapters_mod.get_adapter("gitleaks", object()) is not None,
      "get_adapter returns the adapter with a live policy object")
a = GitleaksAdapter()
check("A-04", a.id == "gitleaks" and a.risk == "R1"
      and "metadata-only" in a.description,
      "adapter identity: id/risk/description")
check("A-05", raises_gate(lambda: a.execute(None, policy=None, timeout=5,
                                            log=io.StringIO())),
      "execute() without ticket/policy raises GateRequired (inherited gate)")

# preflight with no binary anywhere
gl_mod.shutil.which = lambda name: None
gl_mod.GITLEAKS_FALLBACKS = []
check("A-06", a.preflight() is not None and "gitleaks" in a.preflight(),
      "preflight reports the missing binary (no auto-install)")
check("A-07", a.binary() is None, "binary() returns None when not installed")

gl_mod.shutil.which = lambda name: "/fake/gitleaks" if name == "gitleaks" else None
check("A-08", a.preflight() is None and a.binary() == "/fake/gitleaks",
      "preflight passes once a binary is resolvable")
cmd = a.build_command(TMP_DIR)
check("A-09", cmd == ["/fake/gitleaks", "dir", TMP_DIR,
                      "--report-format", "json",
                      "--report-path", "-", "--redact"],
      "build_command (EXT-1.3-F1): dir + JSON + stdout report path + redact")

# ==========================================================================
# B. normal conversion (single finding) — whitelist + no secret residue
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=1,
                                                stdout=json.dumps([fake_record()])))
check("B-01", res.status == "COMPLETED" and res.ok is True and len(res.findings) == 1,
      "rc=1 (leaks found) with valid JSON -> COMPLETED with 1 finding")
f0 = res.findings[0]
check("B-02", f0["tool"] == "gitleaks" and f0["finding_type"] == "gitleaks_finding",
      "finding_type/tool set from the adapter contract")
check("B-03", f0["rule_id"] == "faketool-aws-key"
      and f0["location"] == "faketool/config.py:12",
      "RuleID -> rule_id; File:StartLine -> location")
check("B-04", f0["severity"] == "high" and f0["title"] == "gitleaks: faketool-aws-key",
      "fixed documented severity default; title carries rule id only")
check("B-05", f0["description"] ==
      "gitleaks rule faketool-aws-key matched at faketool/config.py:12 "
      "(Fictional AWS-shaped access key)",
      "description = rule + location + rule metadata (no file content)")
check("B-06", f0["references"] == ["https://example.invalid/rules/faketool-aws-key"],
      "Link -> references")
check("B-07", f0["evidence"] == "rule tags: key, aws" and f0["evidence_redacted"] is False,
      "evidence = rule TAGS metadata only; nothing to redact")
check("B-08", f0["target"] == TMP_DIR and f0["finding_id"].startswith("fnd_"),
      "target = scanned dir; finding_id computed")
blob = observable_blob(res, log_text)
check("B-09", no_secret(blob),
      "NO fictional secret in detail/log/meta/findings (evidence included)")
check("B-10", all(k not in f0 for k in ("Secret", "Match", "Commit", "Author",
                                        "Email", "Fingerprint", "Entropy")),
      "non-whitelisted keys absent from the finding dict")
check("B-11", not any(m in blob for m in NON_WHITELISTED),
      "non-whitelisted metadata values (commit/author/email) absent from output")
check("B-12", "$ /fake/gitleaks dir" in log_text
      and "faketool-aws-key faketool/config.py:12" in log_text,
      "log keeps command + rule/file/line triage metadata")

# ==========================================================================
# C. multiple findings
# ==========================================================================
records = [
    fake_record(rule="faketool-aws-key", file="faketool/config.py", line=12,
                secret=FAKE_SECRET_A),
    fake_record(rule="faketool-generic-api-key", file="faketool/settings.ini",
                line=3, secret=FAKE_SECRET_B, tags=("key",)),
    fake_record(rule="faketool-aws-key", file="faketool/config.py", line=12,
                secret=FAKE_SECRET_A),
]
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=1,
                                                stdout=json.dumps(records)))
check("C-01", len(res.findings) == 3,
      "three report records -> three findings")
ids = [f["finding_id"] for f in res.findings]
check("C-02", len(set(ids)) == 2,
      "identical locator duplicates collapse to one id; distinct locator differs")
check("C-03", no_secret(observable_blob(res, log_text)),
      "no fictional secret anywhere with multiple findings")
check("C-04", res.meta["records_seen"] == 3 and res.meta["records_skipped"] == 0,
      "meta records counts (no raw output stored in meta)")

# ==========================================================================
# D. empty scan
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout="[]"))
check("D-01", res.status == "COMPLETED" and res.findings == [],
      "rc=0 with empty array -> COMPLETED, zero findings")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=""))
check("D-02", res.status == "FAILED" and "empty report" in res.detail
      and res.findings == [],
      "rc=0 with BLANK output -> FAILED (EXT-1.3-F1 fail-closed; never a clean result)")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=""))
check("D-03", res.status == "FAILED" and "empty report" in res.detail
      and res.findings == [],
      "rc=1 with no report -> FAILED (fail-closed, never silent success)")

# ==========================================================================
# E. invalid JSON (with secrets in the raw output — must not leak)
# ==========================================================================
bad = "garbage {" + FAKE_SECRET_A + " " + FAKE_SECRET_B + "}"
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=bad))
check("E-01", res.status == "FAILED" and "not valid JSON" in res.detail,
      "invalid JSON -> FAILED with safe detail")
check("E-02", no_secret(observable_blob(res, log_text)),
      "failure path does not leak the secret-bearing raw output")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                                stdout='{"not":"an array"}'))
check("E-03", res.status == "FAILED" and "not a JSON array" in res.detail,
      "non-array JSON report -> FAILED")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout="null"))
check("E-04", res.status == "FAILED" and "not a JSON array" in res.detail,
      "JSON null report -> FAILED (fail-closed)")

# ==========================================================================
# F. abnormal exit codes
# ==========================================================================
res, log_text = run_adapter(
    TMP_DIR, FakeRunner(returncode=2,
                        stdout=json.dumps([fake_record(secret=FAKE_SECRET_C)])))
check("F-01", res.status == "FAILED" and "exit 2" in res.detail
      and res.findings == [],
      "rc=2 -> FAILED even with a parseable report (fail-closed)")
check("F-02", no_secret(observable_blob(res, log_text)),
      "abnormal-exit path leaks nothing")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=127, stdout=""))
check("F-03", res.status == "FAILED" and "exit 127" in res.detail,
      "rc=127 (binary problem) -> FAILED with exit code only")

# ==========================================================================
# G. timeout
# ==========================================================================
fake = FakeRunner(exception=subprocess.TimeoutExpired(cmd="gitleaks", timeout=30))
res, log_text = run_adapter(TMP_DIR, fake, timeout=30)
check("G-01", res.status == "TIMEOUT" and "exceeded" in res.detail,
      "timeout -> TIMEOUT status (runner-classifiable)")
check("G-02", fake.calls and fake.calls[0][1] == 30,
      "timeout budget forwarded to the subprocess seam")
check("G-03", no_secret(observable_blob(res, log_text)),
      "timeout path leaks nothing")

# ==========================================================================
# H. file/line mapping
# ==========================================================================
res, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps(
    [fake_record(file="faketool/a/b/c.py", line=10, end_line=14)])))
check("H-01", res.findings[0]["location"] == "faketool/a/b/c.py:10-14",
      "StartLine != EndLine -> file:start-end range")
res, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps(
    [fake_record(file="faketool/x.py", line=None)])))
check("H-02", res.findings[0]["location"] == "faketool/x.py",
      "missing StartLine -> bare file location (no invented line)")
res, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps(
    [fake_record(file="faketool/y.py", line=7, end_line=7)])))
check("H-03", res.findings[0]["location"] == "faketool/y.py:7",
      "equal start/end lines collapse to a single line")

# ==========================================================================
# I. finding_id stability
# ==========================================================================
r1 = fake_record()
res_a, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps([r1])))
res_b, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps([dict(r1)])))
check("I-01", res_a.findings[0]["finding_id"] == res_b.findings[0]["finding_id"],
      "identical record -> identical finding_id across runs")
res_c, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps(
    [fake_record(file="faketool/other.py")])))
check("I-02", res_c.findings[0]["finding_id"] != res_a.findings[0]["finding_id"],
      "different file -> different finding_id")
res_d, _ = run_adapter(TMP_DIR, FakeRunner(returncode=1, stdout=json.dumps(
    [fake_record(rule="faketool-other-rule")])))
check("I-03", res_d.findings[0]["finding_id"] != res_a.findings[0]["finding_id"],
      "different rule -> different finding_id")

# ==========================================================================
# J. unauthorized directory refusal (adapter-level scope guard)
# ==========================================================================
for i, (label, target) in enumerate([
        ("home", str(Path.home())),
        ("drive-root", str(Path("C:/"))),
        ("missing-dir", str(Path(TMP_DIR) / "does-not-exist")),
        ("file-not-dir", str(tmp_file))]):
    fake = FakeRunner()
    res, log_text = run_adapter(target, fake)
    check(f"J-{i:02d}", res.status == "FAILED" and res.ok is False
          and fake.calls == [],
          f"refuse to scan {label}: FAILED and NO subprocess spawned")

# ==========================================================================
# K. malformed records (skipped safely, secrets never echoed)
# ==========================================================================
records = [
    fake_record(secret=FAKE_SECRET_A),
    {"RuleID": "faketool-no-file", "Secret": FAKE_SECRET_B},   # missing File
    "not-a-dict",                                              # wrong type
    fake_record(file="faketool/z.py", line="not-an-int", secret=FAKE_SECRET_C),
    fake_record(file="faketool/w.py", line=5, tags="not-a-list"),
    fake_record(rule="faketool-ok", file="faketool/ok.py", line=9,
                secret=FAKE_SECRET_A),
]
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=1,
                                                stdout=json.dumps(records)))
check("K-01", len(res.findings) == 2,
      "2 well-formed records converted; 4 malformed records skipped")
check("K-02", res.meta["records_seen"] == 6 and res.meta["records_skipped"] == 4,
      "meta counts malformed skips honestly")
check("K-03", no_secret(observable_blob(res, log_text)),
      "skip messages and output contain no secrets or record values")
check("K-04", "skipped" in log_text,
      "malformed-record skips are logged (auditable, value-free)")

# ==========================================================================
# L. cross-scenario residue sweep over every observed run
# ==========================================================================
leaks = []
for idx, (result, log_text) in enumerate(OBSERVED):
    if not no_secret(observable_blob(result, log_text)):
        leaks.append(idx)
check("L-01", not leaks,
      f"all {len(OBSERVED)} observed runs are free of fictional secrets "
      f"in every observable field")

print("-" * 78)
print(f"EXT-1 GITLEAKS ADAPTER TESTS: {checks_run - failures}/{checks_run} checks passed")
tmp.cleanup()
gl_mod._spawn = REAL_SPAWN
sys.exit(1 if failures else 0)
