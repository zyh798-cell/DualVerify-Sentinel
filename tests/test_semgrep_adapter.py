"""EXT-2: Semgrep adapter tests (mocked execution — no real tool call).

The semgrep binary is NOT required and is NOT installed on this machine:
every test replaces the single subprocess seam (semgrep._spawn) with a
scripted fake, so exit codes, timeouts, invalid JSON, tool errors and
malformed records are all exercised without installing or running anything.
The one REAL subprocess call in this file is `sys.executable -c ...` (used to
prove the version-check suppression env var reaches the child) — no semgrep,
no network, no scan of any real tree.

SECURITY: semgrep reports carry MATCHED SOURCE CODE (`extra.lines`). All
fixtures are fictional and assembled at runtime; checks only ever print
check ids and descriptions, and a dedicated residue sweep proves the source
line never reaches any observable field.

Coverage map (task book -> section):
  A  registration / identity / gate / command contract / env suppression
  B  normal conversion (single finding) — whitelist + no source residue
  C  multiple findings
  D  empty scan (and blank stdout fail-closed)
  E  invalid JSON / non-object / missing results
  F  abnormal exit codes
  G  timeout
  H  file/line mapping
  I  finding_id stability
  J  unauthorized directory refusal (no spawn)
  K  rules-source enforcement (missing config / missing path) — no spawn
  L  tool errors -> INCOMPLETE scan, fail-closed, no findings harvested
  M  malformed records
  N  severity mapping (ERROR/WARNING/INFO, unknown fail-closed)
  O  cross-scenario source-residue sweep
  P  CR-01 exit-code contract (only rc==0 is a completed scan)
  Q  CR-02 completeness signals (COMPLETE/PARTIAL/INCOMPLETE shim)
  R  CR-03 untrusted-value sanitisation (control chars / injection)

EXT-2 REMEDIATION (CR-01/02/03): sections P/Q/R were added by the
remediation pass. Execution is STILL fully mocked at the single `_spawn`
seam — no real semgrep is installed, run or required.

Run:  python tests/test_semgrep_adapter.py
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
import vuln_hunter.adapters_ext.semgrep as sg_mod  # noqa: E402
from vuln_hunter.adapters import GateRequired  # noqa: E402
from vuln_hunter.adapters_ext import register_semgrep  # noqa: E402
from vuln_hunter.adapters_ext.semgrep import (  # noqa: E402
    SEMGREP_SEVERITY_MAP, SemgrepAdapter,
)

# EXT-2: registration is explicit; importing any module never registers.
register_semgrep()

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
# Fictional fixtures — source shapes assembled at runtime, never real.
# ---------------------------------------------------------------------------
FAKE_SOURCE_LINE = "password = " + "f1ct10al-" + "s0urce-l1ne"   # matched code
FAKE_SECRET_IN_SOURCE = "AKIA" + "X" * 4 + "1234" * 3            # secret-shaped
FAKE_FINGERPRINT = "f1ct10al" + "fingerprint"                    # non-whitelisted
ALL_RESIDUE = [FAKE_SOURCE_LINE, FAKE_FINGERPRINT, FAKE_SECRET_IN_SOURCE]
CHECK_ID = "faketool.lang.security.hardcoded-password"
RULE_REF = "https://example.invalid/rules/hardcoded-password"


def fake_result(check_id=CHECK_ID, path="faketool/app.py", line=12,
                end_line=None, severity="ERROR",
                message="Fictional hardcoded credential pattern",
                source_line=FAKE_SOURCE_LINE, metadata=None):
    """One realistic semgrep `results` record. The matched SOURCE LINE and
    the fingerprint are populated ON PURPOSE so tests can prove they never
    leak into the unified Finding or any log."""
    if metadata is None:
        metadata = {
            "cwe": ["CWE-798: Use of Hard-coded Credentials"],
            "confidence": "HIGH",
            "references": [RULE_REF],
            "unmodeled-key": {"free-form": "ignored"},   # not whitelisted
        }
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 5, "offset": 100},
        "end": {"line": line if end_line is None else end_line,
                "col": 20, "offset": 130},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": metadata,
            "lines": source_line,                 # MATCHED SOURCE: never read
            "fingerprint": FAKE_FINGERPRINT,      # non-whitelisted
        },
    }


def fake_report(results, errors=None, skipped_paths=None, *,
                include_errors=True, include_paths=True,
                include_skipped=True, scanned=None):
    """Build a semgrep-shaped report. CR-02 tests can OMIT completeness
    fields (include_errors / include_paths / include_skipped) to prove the
    adapter never treats a report with unverifiable coverage as complete."""
    d = {"version": "1.2.3-fictional", "results": results}
    if include_errors:
        d["errors"] = errors if errors is not None else []
    if include_paths:
        paths = {"scanned": scanned if scanned is not None
                 else ["faketool/app.py"]}
        if include_skipped:
            paths["skipped"] = (skipped_paths if skipped_paths is not None
                                else [])
        d["paths"] = paths
    return json.dumps(d)


class FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = "fictional-stderr"


class FakeRunner:
    """Replaces sg_mod._spawn. Scriptable result or exception; records calls."""

    def __init__(self, returncode=0, stdout="{}", exception=None):
        self.returncode = returncode
        self.stdout = stdout
        self.exception = exception
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((list(cmd), timeout))
        if self.exception is not None:
            raise self.exception
        return FakeProc(self.returncode, self.stdout)


REAL_SPAWN = sg_mod._spawn
OBSERVED = []  # (result, log_text) pairs for the final residue sweep


def run_adapter(target, fake, timeout=60, binary="/fake/semgrep", step=None):
    """Install the fake, run the adapter, capture the log, restore _spawn."""
    sg_mod._spawn = fake
    old_which = sg_mod.shutil.which
    old_fallbacks = sg_mod.SEMGREP_FALLBACKS
    sg_mod.shutil.which = lambda name: binary if name == "semgrep" else None
    sg_mod.SEMGREP_FALLBACKS = []
    try:
        log = io.StringIO()
        st = step if step is not None else {"id": "s5-semgrep",
                                          "adapter": "semgrep",
                                          "target": target,
                                          "target_kind": "fs_path",
                                          "timeout": timeout,
                                          "semgrep_rules": RULES_DIR}
        result = SemgrepAdapter()._run(target, timeout, log, st)
        OBSERVED.append((result, log.getvalue()))
        return result, log.getvalue()
    finally:
        sg_mod._spawn = REAL_SPAWN
        sg_mod.shutil.which = old_which
        sg_mod.SEMGREP_FALLBACKS = old_fallbacks


def observable_blob(result, log_text):
    """Everything a downstream layer could observe from one run."""
    parts = [result.detail, log_text,
             json.dumps(result.meta, ensure_ascii=False, default=str)]
    for f in result.findings:
        parts.append(json.dumps(f, ensure_ascii=False, default=str))
    return "\n".join(parts)


def no_residue(blob):
    return not any(s in blob for s in ALL_RESIDUE)


tmp = tempfile.TemporaryDirectory(prefix="dvs-semgrep-test-")
TMP_DIR = tmp.name
RULES_DIR = str(Path(TMP_DIR) / "rules")
Path(RULES_DIR).mkdir(parents=True, exist_ok=True)
Path(RULES_DIR, "rule.yaml").write_text(
    "# fictional local rule — no registry, no network\n", encoding="utf-8")
tmp_file = Path(TMP_DIR) / "not-a-dir.txt"
tmp_file.write_text("fictional file content\n", encoding="utf-8")

print("=" * 78)
print("EXT-2 SEMGREP ADAPTER TESTS (mocked execution)")
print("=" * 78)

# ==========================================================================
# A. registration / identity / gate / command contract / env suppression
# ==========================================================================
check("A-01", adapters_mod._REGISTRY.get("semgrep") is not None
      and isinstance(adapters_mod._REGISTRY["semgrep"], SemgrepAdapter),
      "explicit register_semgrep() registers the adapter in _REGISTRY")
check("A-02", adapters_mod.adapter_risk("semgrep") == "R1",
      "adapter_risk('semgrep') == R1 (local scan, no network)")
check("A-03", adapters_mod.get_adapter("semgrep", object()) is not None,
      "get_adapter returns the adapter with a live policy object")
a = SemgrepAdapter()
check("A-04", a.id == "semgrep" and a.risk == "R1"
      and "metadata-only" in a.description,
      "adapter identity: id/risk/description")
check("A-05", raises_gate(lambda: a.execute(None, policy=None, timeout=5,
                                            log=io.StringIO())),
      "execute() without ticket/policy raises GateRequired (inherited gate)")

# preflight with no binary anywhere
sg_mod.shutil.which = lambda name: None
sg_mod.SEMGREP_FALLBACKS = []
check("A-06", a.preflight() is not None and "semgrep" in a.preflight(),
      "preflight reports the missing binary (no auto-install)")
check("A-07", a.binary() is None, "binary() returns None when not installed")

sg_mod.shutil.which = lambda name: "/fake/semgrep" if name == "semgrep" else None
check("A-08", a.preflight() is None and a.binary() == "/fake/semgrep",
      "preflight passes once a binary is resolvable")
cmd = a.build_command(TMP_DIR, {"semgrep_rules": RULES_DIR})
check("A-09", cmd == ["/fake/semgrep", "scan", TMP_DIR,
                      "--config", RULES_DIR,
                      "--json", "--metrics", "off"],
      "build_command: scan + target + LOCAL --config + --json + --metrics off "
      "(no registry/auto, no --quiet, no unverified flags)")
check("A-10", not any("auto" in str(part).lower() for part in cmd)
      and "registry" not in " ".join(cmd).lower(),
      "command never references the semgrep registry/auto config")
# The real _spawn must hand the child a version-check-suppressed environment.
# Only sys.executable is spawned here (semgrep is NOT installed) — offline.
env_probe = sg_mod._spawn(
    [sys.executable, "-c",
     "import os;print(os.environ.get('SEMGREP_ENABLE_VERSION_CHECK'))"], 30)
check("A-11", env_probe.returncode == 0
      and env_probe.stdout.strip() == "false",
      "_spawn sets SEMGREP_ENABLE_VERSION_CHECK=false in the child env "
      "(version-robust, no CLI flag dependency)")
check("A-12", SEMGREP_SEVERITY_MAP == {
    "error": "high", "warning": "medium", "info": "info",
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "experiment": "info", "inventory": "info"},
    "SEMGREP_SEVERITY_MAP covers the official nine-value vocabulary "
    "(batch-1 extension: CRITICAL/HIGH/MEDIUM/LOW + legacy EXPERIMENT/INVENTORY)")

# ==========================================================================
# B. normal conversion (single finding) — whitelist + no source residue
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                                stdout=fake_report([fake_result()])))
check("B-01", res.status == "COMPLETED" and res.ok is True and len(res.findings) == 1,
      "rc=0 with a valid report -> COMPLETED with 1 finding")
f0 = res.findings[0]
check("B-02", f0["tool"] == "semgrep" and f0["finding_type"] == "semgrep_finding",
      "finding_type/tool set from the adapter contract")
check("B-03", f0["rule_id"] == CHECK_ID and f0["location"] == "faketool/app.py:12",
      "check_id -> rule_id; path:start.line -> location")
check("B-04", f0["severity"] == "high"
      and f0["title"] == f"semgrep: {CHECK_ID}",
      "ERROR -> high (documented mapping); title carries the rule id only")
check("B-05", f0["description"] ==
      f"semgrep rule {CHECK_ID} matched at faketool/app.py:12 "
      f"— Fictional hardcoded credential pattern",
      "description = rule + location + rule message (no source code)")
check("B-06", f0["references"] == [RULE_REF],
      "metadata.references -> references")
check("B-07", f0["evidence"] ==
      "rule metadata: cwe=CWE-798: Use of Hard-coded Credentials, confidence=HIGH"
      and f0["evidence_redacted"] is False,
      "evidence = whitelisted rule METADATA only; nothing to redact")
check("B-08", f0["target"] == TMP_DIR and f0["finding_id"].startswith("fnd_"),
      "target = scanned dir; finding_id computed")
check("B-09", "unmodeled-key" not in f0["evidence"] and "free-form" not in f0["evidence"],
      "non-whitelisted metadata keys never reach the evidence field")
blob = observable_blob(res, log_text)
check("B-10", no_residue(blob),
      "NO matched source line / fingerprint / secret-shaped text in "
      "detail/log/meta/findings (extra.lines is NEVER read)")
check("B-11", all(k not in f0 for k in ("lines", "fingerprint", "extra", "start",
                                        "end", "col", "offset")),
      "non-whitelisted keys absent from the finding dict")
check("B-12", "$ /fake/semgrep scan" in log_text
      and f"{CHECK_ID} faketool/app.py:12" in log_text,
      "log keeps the command + rule/file/line triage metadata")
check("B-13", res.meta["records_seen"] == 1 and res.meta["records_used"] == 1
      and res.meta["records_skipped"] == 0 and res.meta["errors_seen"] == 0,
      "meta records counts (no raw output stored in meta)")

# ==========================================================================
# C. multiple findings
# ==========================================================================
records = [
    fake_result(),
    fake_result(check_id="faketool.lang.security.sql-injection",
                path="faketool/db.py", line=3),
    fake_result(),   # exact duplicate locator -> same finding_id
]
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                                stdout=fake_report(records)))
check("C-01", len(res.findings) == 3,
      "three report records -> three findings")
ids = [f["finding_id"] for f in res.findings]
check("C-02", len(set(ids)) == 2,
      "identical locator duplicates collapse to one id; distinct locator differs")
check("C-03", no_residue(observable_blob(res, log_text)),
      "no source residue anywhere with multiple findings")
check("C-04", res.meta["records_seen"] == 3 and res.meta["records_skipped"] == 0,
      "meta records counts")

# ==========================================================================
# D. empty scan (and blank stdout fail-closed)
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report([])))
check("D-01", res.status == "COMPLETED" and res.findings == [],
      "rc=0 with an empty results array -> COMPLETED, zero findings")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=""))
check("D-02", res.status == "FAILED" and "empty report" in res.detail
      and res.findings == [],
      "rc=0 with BLANK output -> FAILED (fail-closed; never a clean result)")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout="   "))
check("D-03", res.status == "FAILED" and "empty report" in res.detail
      and res.findings == [],
      "rc=0 with whitespace-only output -> FAILED (fail-closed; never a "
      "clean result)")

# ==========================================================================
# E. invalid JSON / non-object / missing or malformed containers
# ==========================================================================
bad = "garbage {" + FAKE_SOURCE_LINE + " " + FAKE_SECRET_IN_SOURCE + "}"
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=bad))
check("E-01", res.status == "FAILED" and "not valid JSON" in res.detail,
      "invalid JSON -> FAILED with safe detail")
check("E-02", no_residue(observable_blob(res, log_text)),
      "failure path does not leak the raw (source-bearing) output")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                                stdout='{"results": []}'))
check("E-03", res.status == "FAILED" and res.findings == []
      and "lacks 'errors'" in res.detail
      and res.meta["completeness"] == "INCOMPLETE",
      "CR-02: report WITHOUT 'errors'/'paths' -> FAILED (completeness "
      "unverifiable), never a clean 0-finding COMPLETED")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout="null"))
check("E-04", res.status == "FAILED" and "not a JSON object" in res.detail,
      "JSON null report -> FAILED (fail-closed)")
res, log_text = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout='{"errors": [], "paths": {}}'))
check("E-05", res.status == "FAILED" and "results" in res.detail,
      "report without a 'results' array -> FAILED (malformed report)")
res, log_text = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout='{"results": {"not": "a list"}}'))
check("E-06", res.status == "FAILED" and "results" in res.detail,
      "'results' that is not a list -> FAILED")
res, log_text = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout='{"results": [], "errors": "oops"}'))
check("E-07", res.status == "FAILED" and "errors" in res.detail,
      "'errors' that is not a list -> FAILED")

# ==========================================================================
# F. abnormal exit codes
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(
    returncode=2, stdout=fake_report([fake_result(source_line=FAKE_SOURCE_LINE)])))
check("F-01", res.status == "FAILED" and "exit 2" in res.detail
      and res.findings == [],
      "rc=2 -> FAILED even with a parseable report (fail-closed)")
check("F-02", no_residue(observable_blob(res, log_text)),
      "abnormal-exit path leaks nothing")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=127, stdout=""))
check("F-03", res.status == "FAILED" and "exit 127" in res.detail,
      "rc=127 (binary problem) -> FAILED with exit code only")

# ==========================================================================
# G. timeout
# ==========================================================================
fake = FakeRunner(exception=subprocess.TimeoutExpired(cmd="semgrep", timeout=30))
res, log_text = run_adapter(TMP_DIR, fake, timeout=30)
check("G-01", res.status == "TIMEOUT" and "exceeded" in res.detail,
      "timeout -> TIMEOUT status (runner-classifiable)")
check("G-02", fake.calls and fake.calls[0][1] == 30,
      "timeout budget forwarded to the subprocess seam")
check("G-03", no_residue(observable_blob(res, log_text)),
      "timeout path leaks nothing")

# ==========================================================================
# H. file/line mapping
# ==========================================================================
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(path="faketool/a/b/c.py",
                                                  line=10, end_line=14)])))
check("H-01", res.findings[0]["location"] == "faketool/a/b/c.py:10-14",
      "start.line != end.line -> path:start-end range")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(path="faketool/x.py",
                                                  line=None)])))
check("H-02", res.findings[0]["location"] == "faketool/x.py",
      "missing start line -> bare path location (no invented line)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(path="faketool/y.py", line=7,
                                                  end_line=7)])))
check("H-03", res.findings[0]["location"] == "faketool/y.py:7",
      "equal start/end lines collapse to a single line")

# ==========================================================================
# I. finding_id stability
# ==========================================================================
r1 = fake_result()
res_a, _ = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                           stdout=fake_report([r1])))
res_b, _ = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                           stdout=fake_report([dict(r1)])))
check("I-01", res_a.findings[0]["finding_id"] == res_b.findings[0]["finding_id"],
      "identical record -> identical finding_id across runs")
res_c, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(path="faketool/other.py")])))
check("I-02", res_c.findings[0]["finding_id"] != res_a.findings[0]["finding_id"],
      "different path -> different finding_id")
res_d, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(check_id="faketool.other-rule")])))
check("I-03", res_d.findings[0]["finding_id"] != res_a.findings[0]["finding_id"],
      "different check_id -> different finding_id")

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
# K. rules-source enforcement — no registry fallback, no network, no spawn
# ==========================================================================
fake = FakeRunner(returncode=0, stdout=fake_report([]))
step_no_rules = {"id": "s5-semgrep", "adapter": "semgrep", "target": TMP_DIR,
                 "target_kind": "fs_path", "timeout": 30}
res, log_text = run_adapter(TMP_DIR, fake, step=step_no_rules)
check("K-01", res.status == "FAILED" and "rules" in res.detail
      and fake.calls == [],
      "step without a rules source -> FAILED, NO spawn, NO registry fallback")
step_missing_path = dict(step_no_rules, semgrep_rules=str(Path(TMP_DIR) / "nope"))
res, log_text = run_adapter(TMP_DIR, FakeRunner(), step=step_missing_path)
check("K-02", res.status == "FAILED" and "not found" in res.detail,
      "non-existent rules path -> FAILED with a clear configuration message")
fake_k03 = FakeRunner()
step_blank = dict(step_no_rules, semgrep_rules="   ")
res, log_text = run_adapter(TMP_DIR, fake_k03, step=step_blank)
check("K-03", res.status == "FAILED" and fake_k03.calls == [],
      "blank rules string -> FAILED, no spawn")
fake_k04 = FakeRunner(returncode=0, stdout=fake_report([]))
res, log_text = run_adapter(TMP_DIR, fake_k04, step=dict(
    step_no_rules, semgrep_rules=str(tmp_file)))
check("K-04", res.status == "COMPLETED" and len(fake_k04.calls) == 1,
      "a FILE rules path is accepted (semgrep accepts a single YAML rule "
      "file) — the adapter checks existence only, never the rule content")

# ==========================================================================
# L. tool errors -> INCOMPLETE scan, fail-closed, no findings harvested
# ==========================================================================
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [fake_result(source_line=FAKE_SOURCE_LINE)],
    errors=[{"type": "fictional-parse-error", "path": "faketool/broken.py",
             "message": "fictional"}])))
check("L-01", res.status == "FAILED" and res.findings == [],
      "non-empty errors[] -> FAILED (INCOMPLETE scan); findings never harvested")
check("L-02", "incomplete" in res.detail and res.meta["errors_seen"] == 1
      and res.meta["records_used"] == 0,
      "detail states incompleteness; meta counts errors honestly")
check("L-03", no_residue(observable_blob(res, log_text)),
      "incomplete-scan path leaks no source code")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [], skipped_paths=[{"path": "faketool/big.min.js",
                        "reason": "exceeded max target bytes"}])))
check("L-04", res.status == "COMPLETED"
      and res.meta["completeness"] == "PARTIAL"
      and "[completeness=PARTIAL]" in res.detail
      and "skipped" in res.detail
      and res.meta["paths_skipped"] == 1,
      "CR-02: EXPLAINED skipped path -> COMPLETED but explicitly labelled "
      "PARTIAL in detail/meta (never passed off as a complete scan)")
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [], skipped_paths=["faketool/big.min.js"])))
check("L-05", res.status == "FAILED" and res.findings == []
      and res.meta["completeness"] == "INCOMPLETE"
      and "without a stated reason" in res.detail,
      "CR-02: UNEXPLAINED skipped path -> FAILED (fail-closed), no findings")

# ==========================================================================
# M. malformed records (skipped safely, source never echoed)
# ==========================================================================
records = [
    fake_result(),
    {"check_id": "faketool-no-path", "extra": {"severity": "ERROR"}},  # no path
    "not-a-dict",                                                     # wrong type
    fake_result(check_id=""),                                         # empty id
    fake_result(severity="WEIRD"),                                    # bad severity
    fake_result(metadata="not-an-object"),                            # bad metadata
    {"check_id": "faketool-bad-extra", "path": "faketool/z.py",
     "extra": "not-an-object"},
    fake_result(check_id="faketool-ok2", path="faketool/ok.py", line=9),
]
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0,
                                                stdout=fake_report(records)))
check("M-01", len(res.findings) == 2,
      "2 well-formed records converted; 6 malformed records skipped")
check("M-02", res.meta["records_seen"] == 8 and res.meta["records_skipped"] == 6,
      "meta counts malformed skips honestly")
check("M-03", no_residue(observable_blob(res, log_text)),
      "skip messages and output contain no source line or record values")
check("M-04", "skipped" in log_text,
      "malformed-record skips are logged (auditable, value-free)")
check("M-05", res.meta["skip_counts"] == {
    "unsupported_severity": 1, "malformed_record": 5},
    "skip_counts classifies skips: 1 unsupported severity (WEIRD) + "
    "5 malformed records")
check("M-06", res.meta["completeness"] == "PARTIAL"
      and "[completeness=PARTIAL]" in res.detail
      and "6 record(s) skipped" in res.detail,
    "D3: records_skipped>0 -> completeness=PARTIAL, visible in detail")

# ==========================================================================
# N. severity mapping (official nine values; unknown fail-closed + visible)
# ==========================================================================
for sev, expected in (
        ("ERROR", "high"), ("WARNING", "medium"), ("INFO", "info"),
        ("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"),
        ("LOW", "low"), ("EXPERIMENT", "info"), ("INVENTORY", "info"),
        ("error", "high"), ("warning", "medium"), ("info", "info"),
        ("critical", "critical"), ("high", "high"), ("medium", "medium"),
        ("low", "low")):
    res, _ = run_adapter(TMP_DIR, FakeRunner(
        returncode=0, stdout=fake_report([fake_result(severity=sev)])))
    check(f"N-{sev}", res.status == "COMPLETED"
          and len(res.findings) == 1
          and res.findings[0]["severity"] == expected,
          f"severity {sev!r} -> {expected!r} (official mapping, "
          f"case-insensitive input)")
# D2: legacy categories keep their ORIGINAL token visible in the name.
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(severity="EXPERIMENT")])))
check("N-EXP-audit", res.findings[0]["severity"] == "info"
      and "EXPERIMENT" in res.findings[0]["name"]
      and "遗留" in res.findings[0]["name"],
      "EXPERIMENT -> info but the ORIGINAL category token and a legacy "
      "audit note are preserved in the finding name (D2)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result(severity="INVENTORY")])))
check("N-INV-audit", res.findings[0]["severity"] == "info"
      and "INVENTORY" in res.findings[0]["name"]
      and "遗留" in res.findings[0]["name"],
      "INVENTORY -> info but the ORIGINAL category token and a legacy "
      "audit note are preserved in the finding name (D2)")
# Unknown / missing / non-string severities are skipped, never downgraded.
for sev in ("WEIRD", "", None):
    res, _ = run_adapter(TMP_DIR, FakeRunner(
        returncode=0, stdout=fake_report([fake_result(severity=sev)])))
    check(f"N-bad-{sev!r}", res.status == "COMPLETED"
          and res.findings == []
          and res.meta["records_skipped"] == 1
          and res.meta["skip_counts"]["unsupported_severity"] == 1,
          f"severity {sev!r} is NOT in the mapping -> record skipped "
          f"(fail-closed, never silently downgraded to info)")
for sev in (123, ["HIGH"]):
    res, _ = run_adapter(TMP_DIR, FakeRunner(
        returncode=0, stdout=fake_report([fake_result(severity=sev)])))
    check(f"N-bad-type-{sev!r}", res.status == "COMPLETED"
          and res.findings == []
          and res.meta["records_skipped"] == 1
          and res.meta["skip_counts"]["malformed_record"] == 1,
          f"severity {sev!r} is not a string -> record skipped as malformed "
          f"(fail-closed)")

# ==========================================================================
# S. D3/W1-02: skipped-record visibility + PARTIAL downgrade (batch 1)
# ==========================================================================
# S-01: 1 valid + 1 unsupported severity -> PARTIAL, visible count + category.
res, log_text = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [fake_result(), fake_result(check_id="faketool.weird",
                                severity="WEIRD")])))
check("S-01", res.status == "COMPLETED"
      and res.meta["completeness"] == "PARTIAL"
      and "[completeness=PARTIAL]" in res.detail
      and "1 record(s) skipped" in res.detail
      and "unsupported severity" in res.detail
      and res.meta["records_skipped"] == 1
      and res.meta["records_used"] == 1
      and res.meta["skip_counts"] == {"unsupported_severity": 1,
                                      "malformed_record": 0},
      "D3/W1-02: 1 skipped record -> PARTIAL + detail shows count and "
      "reason category; skip_counts structured in meta")

# S-02: mixed skips -> both categories counted, total visible.
res, _ = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [fake_result(), fake_result(severity="WEIRD"),
     fake_result(check_id="faketool.badmeta", metadata="not-an-object")])))
check("S-02", res.meta["skip_counts"] == {"unsupported_severity": 1,
                                          "malformed_record": 1}
      and res.meta["records_skipped"] == 2
      and "2 record(s) skipped" in res.detail
      and "unsupported severity" in res.detail
      and "malformed record" in res.detail,
      "mixed skips -> both reason categories counted and shown in detail")

# S-03: legacy categories are harvested (not skipped), name carries audit.
res, _ = run_adapter(TMP_DIR, FakeRunner(returncode=0, stdout=fake_report(
    [fake_result(severity="EXPERIMENT"),
     fake_result(check_id="faketool.inv", severity="INVENTORY")])))
check("S-03", res.status == "COMPLETED" and len(res.findings) == 2
      and all(f["severity"] == "info" for f in res.findings)
      and res.meta["records_skipped"] == 0
      and res.meta["completeness"] == "COMPLETE",
      "EXPERIMENT/INVENTORY are harvested as info (D2): no skip, no "
      "fabricated severity, original category preserved in name")

# S-04: no skips -> COMPLETE, no skip text.
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()])))
check("S-04", res.meta["completeness"] == "COMPLETE"
      and "skipped" not in res.detail,
      "a clean scan stays COMPLETE with no skip text")

# ==========================================================================
# P. CR-01: exit-code contract — ONLY rc==0 is a completed scan
# ==========================================================================
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=1, stdout=fake_report([])))
check("P-01", res.status == "FAILED" and res.findings == []
      and "exit 1" in res.detail
      and res.meta["completeness"] == "INCOMPLETE",
      "rc=1 + VALID empty JSON -> FAILED (no --error: an unproven "
      "non-zero exit is never a completed scan)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=1, stdout=fake_report([fake_result()])))
check("P-02", res.status == "FAILED" and res.findings == []
      and "no findings harvested" in res.detail,
      "rc=1 + valid report WITH findings -> FAILED and NO findings "
      "harvested (findings require a proven complete scan)")
for _rc in (2, 3, 4, 5, 7, 8, 13, 14, 127):
    res, _ = run_adapter(TMP_DIR, FakeRunner(
        returncode=_rc, stdout=fake_report([fake_result()])))
    check(f"P-03-{_rc}", res.status == "FAILED" and res.findings == [],
          f"rc={_rc} with a parseable report -> FAILED, no findings")
check("P-04", "--error" not in a.build_command(
    TMP_DIR, {"semgrep_rules": RULES_DIR}),
    "build_command never passes --error (no optional-flag dependency; "
    "rc=1 therefore has NO 'findings found' meaning)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()])))
check("P-05", res.status == "COMPLETED" and len(res.findings) == 1
      and res.meta["completeness"] == "COMPLETE",
      "rc=0 + valid COMPLETE report -> COMPLETED; findings come from "
      "results[], NOT from the exit code")

# ==========================================================================
# Q. CR-02: completeness signals (COMPLETE / PARTIAL / INCOMPLETE shim)
# ==========================================================================
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()], include_errors=False)))
check("Q-01", res.status == "FAILED" and res.findings == []
      and res.meta["completeness"] == "INCOMPLETE"
      and "lacks 'errors'" in res.detail,
      "missing 'errors' field -> FAILED (explicit policy: unverifiable, "
      "never optimistically defaulted to an empty array)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()], include_paths=False)))
check("Q-02", res.status == "FAILED" and res.findings == []
      and "lacks a 'paths'" in res.detail,
      "missing 'paths' object -> FAILED (coverage unverifiable)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()], include_skipped=False)))
check("Q-03", res.status == "FAILED" and res.findings == []
      and "lacks 'paths.skipped'" in res.detail,
      "missing 'paths.skipped' -> FAILED (skipped files cannot be ruled out)")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()],
                                     errors=[{"type": "parse-error"}])))
check("Q-04", res.status == "FAILED" and res.findings == []
      and res.meta["completeness"] == "INCOMPLETE"
      and res.meta["errors_seen"] == 1
      and "incomplete" in res.detail,
      "errors[] non-empty -> INCOMPLETE/FAILED, no findings harvested")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report(
        [fake_result()],
        skipped_paths=[{"path": "a.js", "reason": "binary"},
                       {"path": "b.js", "reason": "too large"}])))
check("Q-05", res.status == "COMPLETED" and len(res.findings) == 1
      and res.meta["completeness"] == "PARTIAL"
      and "[completeness=PARTIAL]" in res.detail
      and res.meta["paths_skipped"] == 2,
      "all skips EXPLAINED -> PARTIAL (COMPLETED but explicitly NOT a "
      "complete scan); findings harvested from valid results[]")
res, _ = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([fake_result()])))
check("Q-06", res.status == "COMPLETED"
      and res.meta["completeness"] == "COMPLETE"
      and "[completeness=COMPLETE]" in res.detail,
      "no errors / no skips / all fields present -> COMPLETE")
check("Q-07", all(r.status in ("COMPLETED", "FAILED", "TIMEOUT")
                  for r, _t in OBSERVED),
      "compatibility shim: NO new status value is emitted (frozen "
      "runner.STATUS_PRIORITY / AdapterResult schema untouched)")

# ==========================================================================
# R. CR-03: untrusted-value sanitisation (no control chars / no injection)
# ==========================================================================
evil_id = ("faketool.lang.security.evil\n"
           "- **[CRITICAL]** FORGED FINDING | \x1b[31mred\x1b[0m\tend")
evil_path = "faketool/../evil\r\n- injected line.py"
evil_msg = "normal message\n- **[HIGH]** forged \x00 NUL"
evil_ref = "javascript:alert(1)\n- fake reference"
rec_evil = fake_result(
    check_id=evil_id, path=evil_path, message=evil_msg,
    metadata={"cwe": "CWE-798: Use of Hard-coded Credentials",
              "references": [evil_ref]})
res, log_text = run_adapter(TMP_DIR, FakeRunner(
    returncode=0, stdout=fake_report([rec_evil])))
check("R-01", res.status == "COMPLETED" and len(res.findings) == 1,
      "CR-03: a record with hostile values still yields ONE finding "
      "(necessary evidence preserved, record NOT dropped)")
f_evil = res.findings[0]
blob_evil = observable_blob(res, log_text)
_all_fields = (f_evil["title"] + f_evil["rule_id"] + f_evil["location"]
               + f_evil["description"] + f_evil["name"] + f_evil["evidence"])
check("R-02", not any(ord(c) < 32 or 127 <= ord(c) <= 159
                      for c in _all_fields),
      "no terminal control characters survive in any Finding field")
check("R-03", "\n" not in f_evil["name"] and "\r" not in f_evil["name"]
      and "**[CRITICAL]**" not in f_evil["name"],
      "name (rendered verbatim by frozen report.py) is a single inert "
      "line: no forged report line can be created")
check("R-04", r"\*\*" in f_evil["name"] and r"\|" in f_evil["name"],
      "Markdown metacharacters (*, |) from tool output are backslash-escaped")
check("R-05", no_residue(blob_evil),
      "CR-03: extra.lines / fingerprint STILL never read, even for a "
      "hostile record (matched source stays out of every observable field)")
check("R-06", "evil" in f_evil["rule_id"].lower(),
      "sanitisation preserves readable evidence text (escaped, not deleted)")
check("R-07", sg_mod._log_line("safe\n- forged\r\npath") ==
      "safe - forged path",
      "operator-supplied command-line values cannot forge log lines")

# ==========================================================================
# O. cross-scenario residue sweep over every observed run
# ==========================================================================
leaks = []
for idx, (result, log_text) in enumerate(OBSERVED):
    if not no_residue(observable_blob(result, log_text)):
        leaks.append(idx)
check("O-01", not leaks,
      f"all {len(OBSERVED)} observed runs are free of matched source lines / "
      f"fingerprints / secret-shaped text in every observable field")

print("-" * 78)
print(f"EXT-2 SEMGREP ADAPTER TESTS: {checks_run - failures}/{checks_run} checks passed")
tmp.cleanup()
sg_mod._spawn = REAL_SPAWN
sys.exit(1 if failures else 0)
