"""EXT-1.2 regression tests: explicit registration, report semantics, gate.

All execution is mocked (the single gitleaks._spawn seam is replaced); no
real gitleaks binary is installed or called. Secret-shaped fixtures are
fictional and assembled at runtime.

Coverage map:
  A  import paths that must NOT register the adapter (fresh subprocesses)
  B  CLI start-up is the single explicit registration entry
  C  idempotent registration; built-in trio untouched
  D  authorization gate is NOT bypassed (no ticket -> refuse; final execute)
  E  severity source is visible in the rendered report; Finding Schema intact
  F  planner reads binary state without registering; explicit registry setup

Run:  python tests/test_ext12_registration.py
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
import vuln_hunter.adapters_ext.gitleaks as gl_mod  # noqa: E402
import vuln_hunter.planner as planner_mod  # noqa: E402
from vuln_hunter.adapters import GateRequired, ToolAdapter, get_adapter  # noqa: E402
from vuln_hunter.adapters_ext import register_gitleaks  # noqa: E402
from vuln_hunter.adapters_ext.gitleaks import (  # noqa: E402
    GitleaksAdapter,
)
from vuln_hunter.findings import Finding  # noqa: E402
from vuln_hunter.policy import PolicyEngine  # noqa: E402
from vuln_hunter.report import render_report  # noqa: E402

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


SCHEMA_KEYS = {
    "schema_version", "finding_id", "tool", "finding_type", "title",
    "severity", "target", "location", "rule_id", "description",
    "evidence", "evidence_redacted", "references",
}
FAKE_SECRET = "AKIA" + "X" * 4 + "1234" * 3       # fictional, runtime-built
FAKE_MATCH = 'aws_key = "' + FAKE_SECRET + '"'     # fictional, runtime-built

tmp = tempfile.TemporaryDirectory(prefix="dvs-ext12-test-")
TMP_DIR = Path(tmp.name)
scope_path = TMP_DIR / "scope.json"
scope = {
    "client": "ext12-test",
    "in_scope": ["127.0.0.1"],
    "out_of_scope": ["everything else"],
    "window": "2020-01-01T00:00Z/2099-01-01T00:00Z",
    "confirmed_by": "ext12-test",
}
scope_path.write_text(json.dumps(scope), encoding="utf-8")


def fresh_py(code: str) -> subprocess.CompletedProcess:
    """Run code in a brand-new interpreter against the working source tree."""
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd=str(ROOT), timeout=120,
    )


def not_registered_after_import(mod: str) -> bool:
    p = fresh_py(
        "import importlib;"
        f"importlib.import_module({mod!r});"
        "from vuln_hunter.adapters import _REGISTRY;"
        "print('gitleaks' in _REGISTRY)"
    )
    return p.returncode == 0 and p.stdout.strip() == "False"


class FakeProc:
    def __init__(self, stdout):
        self.returncode = 1
        self.stdout = stdout
        self.stderr = "fictional-stderr"


class FakeRunner:
    calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((list(cmd), timeout))
        record = {
            "Description": "fictional rule",
            "StartLine": 7,
            "EndLine": 7,
            "Match": FAKE_MATCH,
            "Secret": FAKE_SECRET,
            "File": "faketool/config.py",
            "Commit": "dead" + "beefcafe1234",
            "Author": "fictional-author",
            "Tags": ["key", "aws"],
            "RuleID": "faketool-aws-key",
            "Link": "https://example.invalid/rules/faketool-aws-key",
        }
        return FakeProc(json.dumps([record]))


def adapter_finding():
    """One mocked gitleaks scan -> the emitted finding dict."""
    real_spawn = gl_mod._spawn
    real_which = gl_mod.shutil.which
    gl_mod._spawn = FakeRunner()
    gl_mod.shutil.which = lambda name: "/fake/gitleaks"
    try:
        res = GitleaksAdapter()._run(str(TMP_DIR), 30, io.StringIO())
        return res, res.findings[0]
    finally:
        gl_mod._spawn = real_spawn
        gl_mod.shutil.which = real_which


print("=" * 78)
print("EXT-1.2 REGISTRATION / REPORT SEMANTICS TESTS (mocked, read-only)")
print("=" * 78)

# ==========================================================================
# A. no import path may register the adapter
# ==========================================================================
check("A-00", "gitleaks" not in adapters_mod._REGISTRY,
      "this test process starts unregistered (module imports are side-effect free)")
for i, mod in enumerate([
        "vuln_hunter", "vuln_hunter.adapters", "vuln_hunter.planner",
        "vuln_hunter.adapters_ext", "vuln_hunter.adapters_ext.gitleaks",
        "vuln_hunter.__main__", "vuln_hunter.runner"], start=1):
    check(f"A-{i:02d}", not_registered_after_import(mod),
          f"fresh process: importing {mod} does NOT register gitleaks")
builtin_probe = fresh_py(
    "import vuln_hunter.adapters;"
    "from vuln_hunter.adapters import _REGISTRY;"
    "print(sorted(_REGISTRY))")
check("A-08", builtin_probe.stdout.strip() ==
      "['bandit', 'http_probe', 'nuclei']",
      "built-in trio registry shape unchanged (no extension leakage)")

# ==========================================================================
# B. CLI start-up is the single explicit registration entry
# ==========================================================================
cli_probe = fresh_py(
    "from vuln_hunter.adapters import _REGISTRY;"
    "print('before-import', 'gitleaks' in _REGISTRY);"
    "import vuln_hunter.__main__ as m;"
    "print('after-import', 'gitleaks' in _REGISTRY);"
    f"m.main(['gate-check', {str(scope_path)!r}]);"
    "print('after-start', 'gitleaks' in _REGISTRY);"
    "print('registry', sorted(_REGISTRY))")
out = cli_probe.stdout
check("B-01", cli_probe.returncode == 0 and "before-import False" in out,
      "fresh process starts unregistered before any CLI call")
check("B-02", "after-import False" in out,
      "importing vuln_hunter.__main__ alone still does NOT register")
check("B-03", "after-start True" in out and "gitleaks" in out,
      "calling main() (CLI start-up) registers gitleaks explicitly")
check("B-04", "['bandit', 'gitleaks', 'http_probe', 'nuclei']" in out,
      "CLI registry = built-in trio + gitleaks, nothing else")
cli_gate = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "gate-check", str(scope_path)],
    capture_output=True, text=True, cwd=str(ROOT), timeout=120)
check("B-05", cli_gate.returncode == 0 and "scope OK" in cli_gate.stdout,
      "`python -m vuln_hunter gate-check` starts cleanly (offline, rc=0)")

# ==========================================================================
# C. idempotent explicit registration
# ==========================================================================
builtin_before = {k: adapters_mod._REGISTRY[k]
                  for k in ("http_probe", "nuclei", "bandit")}
register_gitleaks()
first_instance = adapters_mod._REGISTRY["gitleaks"]
for _ in range(3):
    register_gitleaks()
check("C-01", isinstance(first_instance, GitleaksAdapter),
      "first explicit registration installs a GitleaksAdapter")
check("C-02", adapters_mod._REGISTRY["gitleaks"] is first_instance,
      "4 registration calls are a no-op after the first (same instance kept)")
check("C-03", len(adapters_mod._REGISTRY) == 4
      and sorted(adapters_mod._REGISTRY) ==
      ["bandit", "gitleaks", "http_probe", "nuclei"],
      "no duplicate entries; registry size stays 4")
check("C-04", all(adapters_mod._REGISTRY[k] is builtin_before[k]
                  for k in builtin_before),
      "Bandit / HTTPProbe / Nuclei instances are never replaced")

# ==========================================================================
# D. authorization gate is NOT bypassed
# ==========================================================================
adapter = GitleaksAdapter()
pol = PolicyEngine(scope, "safe_scan")
check("D-01", raises_gate(lambda: get_adapter("gitleaks", None)),
      "get_adapter without a live policy still raises GateRequired")
check("D-02", raises_gate(lambda: adapter.execute(
    None, policy=pol, timeout=5, log=io.StringIO())),
      "execute() without a RunTicket raises GateRequired")
check("D-03", raises_gate(lambda: adapter.execute(
    object(), policy=pol, timeout=5, log=io.StringIO())),
      "execute() with a forged non-RunTicket raises GateRequired")
check("D-04", GitleaksAdapter.execute is ToolAdapter.execute,
      "the adapter does NOT override the final execute() gate")
t_passive = PolicyEngine(scope, "passive").issue_ticket(
    str(TMP_DIR), "gitleaks", target_kind="fs_path")
res_passive = adapter.execute(
    t_passive, policy=PolicyEngine(scope, "passive"), timeout=30,
    log=io.StringIO(),
    step={"id": "s4-gitleaks", "adapter": "gitleaks", "target": str(TMP_DIR),
          "target_kind": "fs_path"})
check("D-05", res_passive.status == "REFUSED" and "ceiling" in res_passive.detail,
      "passive mode (R0 ceiling) still REFUSES the R1 adapter")
no_registry_probe = fresh_py(
    "import vuln_hunter.planner\n"
    "from vuln_hunter.adapters import get_adapter\n"
    "try:\n"
    "    get_adapter('gitleaks', object())\n"
    "    print('NO_ERROR')\n"
    "except KeyError:\n"
    "    print('KEYERROR')\n")
check("D-06", no_registry_probe.stdout.strip() == "KEYERROR",
      "without explicit registration the adapter is simply unavailable")

# ==========================================================================
# E. severity provenance in the report + Finding Schema unchanged
# ==========================================================================
plain = Finding(
    tool="gitleaks", finding_type="gitleaks_finding",
    title="gitleaks: faketool-aws-key", severity="high",
    target=str(TMP_DIR), location="faketool/config.py:7",
    rule_id="faketool-aws-key", description="fictional",
    evidence="rule tags: key, aws", references=(),
)
check("E-01", set(plain.to_dict()) == SCHEMA_KEYS and len(SCHEMA_KEYS) == 13,
      "Finding.to_dict() still has exactly the 13 unified schema fields")
res, f = adapter_finding()
check("E-02", set(f) == SCHEMA_KEYS | {"name"},
      "emitted finding = 13 schema fields + ONLY the legacy render alias")
check("E-03", all(f[k] == plain.to_dict()[k] for k in (
    "schema_version", "tool", "finding_type", "title", "severity",
    "location", "rule_id", "evidence_redacted")),
      "schema field values unchanged (severity still 'high', title unchanged)")
check("E-04", f["severity"] == "high" and f["finding_id"].startswith("fnd_"),
      "severity remains the documented system default, finding_id computed")
check("E-05", isinstance(f["name"], str) and f["name"].startswith(f["title"])
      and "为系统默认策略" in f["name"]
      and "非 Gitleaks 原生判定" in f["name"],
      "render alias explicitly marks severity as a system default, not a "
      "tool-native judgement")
check("E-06", FAKE_SECRET not in json.dumps(f, ensure_ascii=False)
      and FAKE_SECRET not in res.detail,
      "Secret/Match fictional values never enter finding or detail")

report = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=scope,
    gate_ok=True, gate_message="ok",
    plan=[{"id": "s4-gitleaks", "adapter": "gitleaks", "target": str(TMP_DIR)}],
    results={"s4-gitleaks": {"adapter": "gitleaks", "status": "COMPLETED",
                              "attempts": 1, "detail": "1 finding(s)"}},
    summary="COMPLETED",
    findings=[{"step": "s4-gitleaks", **f}],
    journal_path=str(TMP_DIR / "journal.jsonl"),
    decision_trace=None, audit=None)
check("E-07", "**high**" in report and "为系统默认策略" in report
      and "非 Gitleaks 原生判定" in report
      and "Gitleaks 报告不含 severity 字段" in report,
      "rendered report shows the severity value together with a visible "
      "system-default provenance note")
check("E-08", "gitleaks: faketool-aws-key" in report
      and FAKE_SECRET not in report,
      "report still shows tool-provided rule metadata, with no secret residue")
check("E-09", "Gitleaks 原生判定为 high" not in report,
      "report contains no statement claiming gitleaks reported high itself")

# ==========================================================================
# F. planner reads binary state but never registers
# ==========================================================================
check("F-01", not_registered_after_import("vuln_hunter.planner"),
      "importing planner does not register (re-checked after all edits)")
old_gb = planner_mod.gitleaks_binary
planner_mod.gitleaks_binary = lambda: "/fake/gitleaks"
try:
    plan = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                  source_dir=str(TMP_DIR))
finally:
    planner_mod.gitleaks_binary = old_gb
s4 = [s for s in plan if s["id"] == "s4-gitleaks"]
check("F-02", len(s4) == 1 and s4[0]["target_kind"] == "fs_path",
      "planner still emits the fs_path gitleaks step from binary state")
check("F-03", get_adapter("gitleaks", pol) is first_instance,
      "after explicit registration the Executor path resolves the adapter")

print("-" * 78)
print(f"EXT-1.2 TESTS: {checks_run - failures}/{checks_run} checks passed")
tmp.cleanup()
sys.exit(1 if failures else 0)
