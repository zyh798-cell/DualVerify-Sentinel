"""EXT-2: Semgrep adapter formal integration tests (no real tool call).

Verifies the EXT-2 wiring end to end WITHOUT installing or running semgrep —
the single subprocess seam (semgrep._spawn) is replaced by a scripted fake,
exactly like the EXT-2 adapter tests. The authorization gate, planner,
executor, journal and report are all REAL.

Coverage map (task book -> section):
  T1 packaging      pyproject ships the subpackage; layout on disk       (A)
  T2 registration   import-for-registration via the CLI module/process;
                    duplicate registration harmless; built-in trio
                    untouched; registration != execution; CLI help      (B)
  T3 execution      planner emits s5-semgrep only with source_dir AND a
                    resolvable binary AND a LOCAL rules source; fs_path
                    survives TaskGraph                                   (C)
  T4 authorization  REAL gate: no-ticket GateRequired, passive-mode
                    REFUSED, target_kind mismatch (both directions),
                    scope-hash binding, window at issuance, cancellation,
                    timeout, path guard behind a VALID ticket, rules-source
                    enforcement behind a valid ticket,
                    Executor success/failure/skip paths                  (D, E)
  security          results + attempt logs + journal + rendered report
                    are free of matched source code in every scenario    (F)
  remediation       CR-01 exit code / CR-02 completeness / CR-03 value
                    sanitisation through the REAL Executor + renderer     (G)

EXT-2 REMEDIATION: section G exercises the fixed behaviours through the
real gate/planner/executor/journal/report; the tool seam is still mocked
(no real semgrep installed, run or required).

Run:  python tests/test_semgrep_integration.py
"""
import io
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vuln_hunter.__main__ as cli_mod  # noqa: E402,F401  (CLI start-up under test)
import vuln_hunter.adapters as adapters_mod  # noqa: E402
import vuln_hunter.adapters_ext  # noqa: E402  (import has NO registration side effect)
import vuln_hunter.adapters_ext.semgrep as sg_mod  # noqa: E402
import vuln_hunter.planner as planner_mod  # noqa: E402
from vuln_hunter.adapters import GateRequired  # noqa: E402
from vuln_hunter.adapters_ext.gitleaks import register_gitleaks  # noqa: E402
from vuln_hunter.adapters_ext.semgrep import (  # noqa: E402
    SemgrepAdapter, register_semgrep,
)
from vuln_hunter.journal import EvidenceJournal, audit_status  # noqa: E402
from vuln_hunter.policy import PolicyEngine, PolicyRefusal  # noqa: E402
from vuln_hunter.report import render_report  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402
from vuln_hunter.taskgraph import GraphBuilder  # noqa: E402

# EXT-2: tests that exercise the Executor need an explicitly prepared
# registry. Importing modules (including __main__) does not register
# adapters — only the CLI start-up path calls register_gitleaks() and
# register_semgrep(). Both are registered here so the B-section assertions
# can prove that semgrep registration leaves the gitleaks instance untouched.
register_gitleaks()
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
FAKE_FINGERPRINT = "f1ct10al" + "fingerprint"
ALL_RESIDUE = [FAKE_SOURCE_LINE, FAKE_FINGERPRINT]
CHECK_ID = "faketool.lang.security.hardcoded-password"
RULE_REF = "https://example.invalid/rules/hardcoded-password"


def fake_result(check_id=CHECK_ID, path="faketool/app.py", line=12,
                end_line=None, severity="ERROR",
                source_line=FAKE_SOURCE_LINE):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 5, "offset": 100},
        "end": {"line": line if end_line is None else end_line,
                "col": 20, "offset": 130},
        "extra": {
            "message": "Fictional hardcoded credential pattern",
            "severity": severity,
            "metadata": {"cwe": ["CWE-798"], "confidence": "HIGH",
                         "references": [RULE_REF]},
            "lines": source_line,             # MATCHED SOURCE: never read
            "fingerprint": FAKE_FINGERPRINT,  # non-whitelisted
        },
    }


def fake_report(results, errors=None, *, include_errors=True,
                include_paths=True, skipped_paths=None):
    """Build a semgrep-shaped report; CR-02 scenarios may omit completeness
    fields or inject skipped paths (explained vs unexplained)."""
    d = {"version": "1.2.3-fictional", "results": results}
    if include_errors:
        d["errors"] = errors if errors is not None else []
    if include_paths:
        d["paths"] = {"scanned": ["faketool/app.py"],
                      "skipped": skipped_paths if skipped_paths is not None
                      else []}
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
# Installed immediately: proves that import/registration alone never spawns.
IMPORT_SPAWN_WATCH = FakeRunner()
sg_mod._spawn = IMPORT_SPAWN_WATCH

OBSERVED = []   # (label, [observable texts]) for the final residue sweep
EX_DIRS = []    # executor temp dirs, cleaned up at the end

tmp = tempfile.TemporaryDirectory(prefix="dvs-sg-int-")
TMP_DIR = tmp.name
RULES_DIR = str(Path(TMP_DIR) / "rules")
Path(RULES_DIR).mkdir(parents=True, exist_ok=True)
Path(RULES_DIR, "rule.yaml").write_text(
    "# fictional local rule — no registry, no network\n", encoding="utf-8")
scope_path = Path(TMP_DIR) / "scope.json"


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=2)).strftime(fmt)}")


def base_scope(**kw) -> dict:
    d = {"client": "sg-int-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "sg-int-test"}
    d.update(kw)
    return d


def s5_step(target, timeout=30, sid="s5-semgrep", rules=RULES_DIR):
    return {"id": sid, "adapter": "semgrep", "target": target,
            "timeout": timeout, "target_kind": "fs_path",
            "semgrep_rules": rules}


def patched(fake, binary="/fake/semgrep", fallbacks=None):
    """Install the fake spawn (+ binary resolution); returns restore()."""
    old_which = sg_mod.shutil.which
    old_fallbacks = sg_mod.SEMGREP_FALLBACKS
    sg_mod._spawn = fake
    sg_mod.shutil.which = lambda name: binary if name == "semgrep" else None
    sg_mod.SEMGREP_FALLBACKS = fallbacks if fallbacks is not None else []

    def restore():
        sg_mod._spawn = REAL_SPAWN
        sg_mod.shutil.which = old_which
        sg_mod.SEMGREP_FALLBACKS = old_fallbacks

    return restore


def make_executor(mode="safe_scan", **scope_kw):
    d = Path(tempfile.mkdtemp(prefix="dvs-sg-int-ex-"))
    EX_DIRS.append(d)
    journal = EvidenceJournal(d / "journal.jsonl")
    policy = PolicyEngine(base_scope(**scope_kw), mode)
    ex = Executor(policy, journal, d / "ev", sleep_fn=lambda s: None)
    return d, ex, policy, journal


def run_step(ex, step, fake, **kw):
    restore = patched(fake, **kw)
    try:
        return ex.run_step(step)
    finally:
        restore()


def dir_texts(d: Path):
    texts = []
    if not d.exists():
        return texts
    for p in sorted(d.rglob("*")):
        if p.is_file():
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    return texts


def result_texts(result):
    texts = [result.detail,
             json.dumps(result.meta, ensure_ascii=False, default=str)]
    for f in result.findings:
        texts.append(json.dumps(f, ensure_ascii=False, default=str))
    return texts


def rec_texts(rec):
    return [json.dumps(rec, ensure_ascii=False, default=str)]


def observe(label, texts, ex_dir=None):
    all_texts = [t for t in texts if t]
    if ex_dir is not None:
        all_texts.extend(dir_texts(Path(ex_dir)))
    OBSERVED.append((label, all_texts))


def no_residue(blob):
    return not any(s in blob for s in ALL_RESIDUE)


print("=" * 78)
print("EXT-2 SEMGREP INTEGRATION TESTS (mocked execution, real gate)")
print("=" * 78)

# ==========================================================================
# A. T1 packaging: the subpackage must ship, not just import from a checkout
# ==========================================================================
pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
check("A-01", '"vuln_hunter.adapters_ext"' in pyproject,
      "pyproject [tool.setuptools] packages includes the adapters_ext subpackage")
import vuln_hunter.adapters_ext as ext_pkg  # noqa: E402
check("A-02", (Path(ext_pkg.__file__).parent / "semgrep.py").exists()
      and (Path(ext_pkg.__file__).parent / "gitleaks.py").exists()
      and (Path(ext_pkg.__file__).parent / "__init__.py").exists(),
      "subpackage layout on disk: __init__.py + gitleaks.py + semgrep.py")

# ==========================================================================
# B. T2 registration entry point
# ==========================================================================
check("B-01", isinstance(adapters_mod._REGISTRY.get("semgrep"), SemgrepAdapter),
      "explicit register_semgrep() prepares the CLI registry "
      "(imports have no registration side effect)")
check("B-02", IMPORT_SPAWN_WATCH.calls == [],
      "import/registration alone never spawns the tool (no auto-scan)")
before = dict(adapters_mod._REGISTRY)
try:
    register_semgrep()
    register_semgrep()
    dup_ok = True
except Exception:  # noqa: BLE001 - test harness
    dup_ok = False
check("B-03", dup_ok and isinstance(adapters_mod._REGISTRY.get("semgrep"),
                                    SemgrepAdapter)
      and adapters_mod._REGISTRY["semgrep"] is before["semgrep"],
      "duplicate register_semgrep() calls are true no-ops "
      "(idempotent, no replacement of the registered instance)")
check("B-04", all(adapters_mod._REGISTRY[k] is before[k]
                  for k in ("http_probe", "nuclei", "bandit", "gitleaks")),
      "built-in trio AND the gitleaks adapter instances are untouched by "
      "semgrep registration (no cross-adapter side effects)")
check("B-05", sorted(adapters_mod._REGISTRY) == ["bandit", "gitleaks",
                                                 "http_probe", "nuclei",
                                                 "semgrep"],
      "registry = built-in trio + gitleaks + semgrep, nothing else")
check("B-06", raises_gate(lambda: adapters_mod.get_adapter("semgrep", None)),
      "registry lookup without a live policy raises GateRequired "
      "(registration grants no execution)")
scope_path.write_text(json.dumps(base_scope()), encoding="utf-8")
gate_proc = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "gate-check", str(scope_path)],
    capture_output=True, text=True, cwd=str(ROOT), timeout=120)
check("B-07", gate_proc.returncode == 0 and "scope OK" in gate_proc.stdout,
      "CLI subprocess `python -m vuln_hunter gate-check` starts cleanly "
      "with explicit registration (exit 0, offline)")
cli_probe_code = (
    "import vuln_hunter.__main__ as m;"
    f"m.main(['gate-check', {str(scope_path)!r}]);"
    "from vuln_hunter.adapters import _REGISTRY;"
    "print(sorted(_REGISTRY))"
)
probe = subprocess.run(
    [sys.executable, "-c", cli_probe_code],
    capture_output=True, text=True, cwd=str(ROOT), timeout=120)
check("B-08", probe.returncode == 0 and "semgrep" in probe.stdout
      and "gitleaks" in probe.stdout and "bandit" in probe.stdout,
      "CLI start-up (main) registers semgrep AND gitleaks in a fresh "
      "subprocess (EXT-2 does not regress EXT-1)")
help_proc = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "run", "--help"],
    capture_output=True, text=True, cwd=str(ROOT), timeout=120)
check("B-09", help_proc.returncode == 0 and "--semgrep-rules" in help_proc.stdout
      and "gitleaks" in help_proc.stdout and "semgrep" in help_proc.stdout,
      "CLI --help documents --semgrep-rules and the extended --source-dir")

# ==========================================================================
# C. T3 execution flow: planner + taskgraph
# ==========================================================================
plan_plain = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080")
check("C-01", [s["id"] for s in plan_plain] == ["s1-probe", "s2-nuclei"],
      "no source_dir -> plan unchanged (no fs steps)")

old_gb = planner_mod.gitleaks_binary
old_sb = planner_mod.semgrep_binary
planner_mod.gitleaks_binary = lambda: None
planner_mod.semgrep_binary = lambda: "/fake/semgrep"
try:
    plan_rules = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                        source_dir=TMP_DIR,
                                        semgrep_rules=RULES_DIR)
finally:
    planner_mod.gitleaks_binary = old_gb
    planner_mod.semgrep_binary = old_sb
check("C-02", [s["id"] for s in plan_rules] ==
      ["s1-probe", "s2-nuclei", "s3-bandit", "s5-semgrep"],
      "source_dir + resolvable binary + LOCAL rules -> s5-semgrep appended")
s5 = plan_rules[-1]
check("C-03", s5["adapter"] == "semgrep" and s5["target"] == TMP_DIR
      and s5["target_kind"] == "fs_path" and "deps" not in s5
      and s5["semgrep_rules"] == RULES_DIR,
      "s5-semgrep: adapter/target/fs_path kind/rules; no deps "
      "(independent of the bandit/gitleaks outcomes)")

planner_mod.gitleaks_binary = lambda: None
planner_mod.semgrep_binary = lambda: None
try:
    plan_nobin = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                        source_dir=TMP_DIR,
                                        semgrep_rules=RULES_DIR)
finally:
    planner_mod.gitleaks_binary = old_gb
    planner_mod.semgrep_binary = old_sb
check("C-04", [s["id"] for s in plan_nobin] ==
      ["s1-probe", "s2-nuclei", "s3-bandit"],
      "binary not resolvable -> semgrep step omitted "
      "(a missing optional tool never reddens an existing run)")

planner_mod.gitleaks_binary = lambda: None
planner_mod.semgrep_binary = lambda: "/fake/semgrep"
try:
    plan_norules = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                          source_dir=TMP_DIR)
    plan_emptyrules = planner_mod.build_plan("vuln_validation",
                                             "127.0.0.1:8080",
                                             source_dir=TMP_DIR,
                                             semgrep_rules="")
finally:
    planner_mod.gitleaks_binary = old_gb
    planner_mod.semgrep_binary = old_sb
check("C-05", [s["id"] for s in plan_norules] ==
      ["s1-probe", "s2-nuclei", "s3-bandit"]
      and [s["id"] for s in plan_emptyrules] ==
      ["s1-probe", "s2-nuclei", "s3-bandit"],
      "no rules source -> semgrep step omitted (the planner never plans a "
      "step that would have to fetch rules from the network)")

planner_mod.gitleaks_binary = lambda: "/fake/gitleaks"
planner_mod.semgrep_binary = lambda: "/fake/semgrep"
try:
    plan_all = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                      source_dir=TMP_DIR,
                                      semgrep_rules=RULES_DIR)
finally:
    planner_mod.gitleaks_binary = old_gb
    planner_mod.semgrep_binary = old_sb
check("C-06", [s["id"] for s in plan_all] ==
      ["s1-probe", "s2-nuclei", "s3-bandit", "s4-gitleaks", "s5-semgrep"],
      "all tools resolvable -> bandit, gitleaks and semgrep all planned, "
      "in that order")

gph = GraphBuilder.from_plan(plan_rules)
check("C-07", gph.nodes["s5-semgrep"].target_kind == "fs_path"
      and gph.nodes["s3-bandit"].target_kind == "fs_path"
      and gph.nodes["s1-probe"].target_kind == "net",
      "TaskGraph preserves target_kind: fs_path for local scans, net for probe")

# ==========================================================================
# D. T4 authorization chain (real gate, mocked tool)
# ==========================================================================
a = SemgrepAdapter()
check("D-01", raises_gate(lambda: a.execute(
    None, policy=PolicyEngine(base_scope(), "safe_scan"),
    timeout=5, log=io.StringIO())),
    "execute() without a RunTicket raises GateRequired (no unguarded path)")

# D-02 passive mode (R0 ceiling) refuses the R1 adapter before any spawn
pol_r0 = PolicyEngine(base_scope(), "passive")
t_r0 = pol_r0.issue_ticket(TMP_DIR, "semgrep", target_kind="fs_path")
fake_d02 = FakeRunner()
restore = patched(fake_d02)
try:
    res_d02 = a.execute(t_r0, policy=pol_r0, timeout=30, log=io.StringIO(),
                        step=s5_step(TMP_DIR))
finally:
    restore()
check("D-02", res_d02.status == "REFUSED" and "ceiling" in res_d02.detail
      and fake_d02.calls == [],
      "passive mode (R0 ceiling) REFUSES the R1 adapter before any spawn")

# D-03 happy path through the real gate
pol_ok = PolicyEngine(base_scope(), "safe_scan")
t_ok = pol_ok.issue_ticket(TMP_DIR, "semgrep", target_kind="fs_path")
fake_d03 = FakeRunner(returncode=0, stdout=fake_report([fake_result()]))
restore = patched(fake_d03)
try:
    log_d03 = io.StringIO()
    res_d03 = a.execute(t_ok, policy=pol_ok, timeout=30, log=log_d03,
                        step=s5_step(TMP_DIR))
finally:
    restore()
check("D-03", res_d03.status == "COMPLETED" and len(res_d03.findings) == 1
      and fake_d03.calls and fake_d03.calls[0][0][:3] == ["/fake/semgrep", "scan",
                                                         TMP_DIR]
      and fake_d03.calls[0][0][4] == RULES_DIR,
      "valid fs_path RunTicket -> execute() runs the tool (mocked) on the "
      "TICKET target with the LOCAL rules source")
observe("D-03", result_texts(res_d03) + [log_d03.getvalue()])

# D-04 target_kind mismatch, refused in BOTH directions
t_net = pol_ok.issue_ticket("127.0.0.1", "semgrep")  # net kind, in scope
fake_d04 = FakeRunner()
restore = patched(fake_d04)
try:
    res_d04 = a.execute(t_net, policy=pol_ok, timeout=30, log=io.StringIO(),
                        step=s5_step(TMP_DIR))
    res_d04b = a.execute(t_ok, policy=pol_ok, timeout=30, log=io.StringIO(),
                         step={"id": "s5", "adapter": "semgrep",
                               "target": TMP_DIR, "timeout": 30,
                               "semgrep_rules": RULES_DIR})
finally:
    restore()
check("D-04", res_d04.status == "REFUSED" and "target_kind" in res_d04.detail
      and res_d04b.status == "REFUSED" and "target_kind" in res_d04b.detail
      and fake_d04.calls == [],
      "target_kind mismatch refused in BOTH directions (net ticket on fs "
      "step; fs ticket on a default-net step)")

# D-05 scope-hash binding: ticket dies when scope content changes
t_bind = pol_ok.issue_ticket(TMP_DIR, "semgrep", target_kind="fs_path")
pol_ok.scope["in_scope"].append("10.0.0.1")  # content change after issuance
fake_d05 = FakeRunner()
restore = patched(fake_d05)
try:
    res_d05 = a.execute(t_bind, policy=pol_ok, timeout=30, log=io.StringIO(),
                        step=s5_step(TMP_DIR))
finally:
    restore()
check("D-05", res_d05.status == "REFUSED"
      and "scope content changed" in res_d05.detail and fake_d05.calls == [],
      "scope content change after issuance invalidates the RunTicket")

# D-06 window is enforced at issuance even for fs_path targets
pol_old = PolicyEngine(
    base_scope(window="2020-01-01T00:00Z/2020-01-02T00:00Z"), "safe_scan")
try:
    pol_old.issue_ticket(TMP_DIR, "semgrep", target_kind="fs_path")
    d06 = False
except PolicyRefusal:
    d06 = True
check("D-06", d06,
      "expired authorization window -> PolicyRefusal at issuance "
      "(fs_path skips only the net-scope check)")

# D-07 adapter-level path guard BEHIND a valid ticket (defense in depth)
pol_guard = PolicyEngine(base_scope(), "safe_scan")
t_home = pol_guard.issue_ticket(str(Path.home()), "semgrep",
                                target_kind="fs_path")
fake_d07 = FakeRunner()
restore = patched(fake_d07)
try:
    log_d07 = io.StringIO()
    res_d07 = a.execute(t_home, policy=pol_guard, timeout=30, log=log_d07,
                        step=s5_step(str(Path.home())))
finally:
    restore()
check("D-07", res_d07.status == "FAILED" and fake_d07.calls == [],
      "even with a valid ticket the adapter refuses to scan the home "
      "directory (defense in depth, no spawn)")
observe("D-07", result_texts(res_d07) + [log_d07.getvalue()])

# D-08 rules-source enforcement BEHIND a valid ticket (no registry fallback)
t_rules = pol_guard.issue_ticket(TMP_DIR, "semgrep", target_kind="fs_path")
fake_d08 = FakeRunner()
restore = patched(fake_d08)
try:
    log_d08 = io.StringIO()
    res_d08 = a.execute(t_rules, policy=pol_guard, timeout=30, log=log_d08,
                        step={"id": "s5", "adapter": "semgrep",
                              "target": TMP_DIR, "target_kind": "fs_path",
                              "timeout": 30})
finally:
    restore()
check("D-08", res_d08.status == "FAILED" and "rules" in res_d08.detail
      and fake_d08.calls == [],
      "a valid ticket WITHOUT a rules source -> FAILED with no spawn: the "
      "adapter never falls back to the registry/auto config (no network)")
observe("D-08", result_texts(res_d08) + [log_d08.getvalue()])

# D-09 cancellation through the Executor
d09, ex09, _pol09, _j09 = make_executor("safe_scan")
(d09 / "ev" / "CANCEL").write_text("cancel", encoding="utf-8")
fake_d09 = FakeRunner()
rec_d09 = run_step(ex09, s5_step(TMP_DIR), fake_d09)
check("D-09", rec_d09["status"] == "CANCELLED" and fake_d09.calls == [],
      "CANCEL file in the evidence dir -> step CANCELLED, tool never spawned")

# D-10 timeout through the Executor attempt loop
d10, ex10, _pol10, _j10 = make_executor("safe_scan")
fake_d10 = FakeRunner(exception=subprocess.TimeoutExpired(cmd="semgrep",
                                                          timeout=30))
rec_d10 = run_step(ex10, s5_step(TMP_DIR, timeout=30), fake_d10)
check("D-10", rec_d10["status"] == "TIMEOUT" and len(fake_d10.calls) == 2,
      "tool timeout -> TIMEOUT after the bounded retry loop (2 attempts, "
      "never a fake success)")
observe("D-10", rec_texts(rec_d10), d10)

# ==========================================================================
# E. Executor end-to-end (success / failure / skip / report)
# ==========================================================================
d_e01, ex_e01, _pol_e01, journal_e01 = make_executor("safe_scan")
fake_e01 = FakeRunner(returncode=0, stdout=fake_report([fake_result()]))
rec_e01 = run_step(ex_e01, s5_step(TMP_DIR), fake_e01)
check("E-01", rec_e01["status"] == "COMPLETED"
      and len(rec_e01["findings"]) == 1
      and rec_e01["findings"][0]["severity"] == "high",
      "Executor path: COMPLETED; severity = the documented ERROR->high "
      "mapping (a semgrep-reported fact, translated)")
f_e01 = rec_e01["findings"][0]
check("E-02", f_e01["finding_id"].startswith("fnd_") and f_e01["tool"] == "semgrep"
      and f_e01["evidence_redacted"] is False
      and f_e01["location"] == "faketool/app.py:12",
      "unified Finding schema survives the executor path "
      "(id/tool/location/redaction flag)")
check("E-03", isinstance(f_e01.get("name"), str)
      and f_e01["name"].startswith(f_e01["title"])
      and "由 Semgrep 报告的" in f_e01["name"]
      and "非 DualVerify-Sentinel 自行判定" in f_e01["name"]
      and f_e01["finding_type"] == "semgrep_finding",
      "renderer alias carries an explicit severity-source marker; "
      "13 schema fields (incl. severity) untouched")
observe("E-01", rec_texts(rec_e01), d_e01)

d_e04, ex_e04, _pol_e04, _j04 = make_executor("safe_scan")
fake_e04 = FakeRunner()
rec_e04 = run_step(ex_e04, s5_step(TMP_DIR), fake_e04, binary=None)
check("E-04", rec_e04["status"] == "SKIPPED"
      and "preflight" in rec_e04.get("reason", "") and fake_e04.calls == [],
      "missing binary through the Executor -> SKIPPED with the preflight "
      "reason (honest, no spawn)")

d_e05, ex_e05, _pol_e05, _j05 = make_executor("safe_scan")
fake_e05 = FakeRunner(returncode=2,
                      stdout=fake_report([fake_result()]))
rec_e05 = run_step(ex_e05, s5_step(TMP_DIR), fake_e05)
check("E-05", rec_e05["status"] == "FAILED" and "exit 2" in rec_e05["detail"]
      and rec_e05["findings"] == [],
      "abnormal exit through the Executor -> FAILED; findings never "
      "harvested from a failed scan")
observe("E-05", rec_texts(rec_e05), d_e05)

d_e06, ex_e06, _pol_e06, _j06 = make_executor("safe_scan")
fake_e06 = FakeRunner(returncode=0,
                      stdout=fake_report([fake_result()],
                                         errors=[{"type": "fictional-parse-error"}]))
rec_e06 = run_step(ex_e06, s5_step(TMP_DIR), fake_e06)
check("E-06", rec_e06["status"] == "FAILED" and "incomplete" in rec_e06["detail"]
      and rec_e06["findings"] == [],
      "tool errors through the Executor -> FAILED (INCOMPLETE scan); no "
      "findings harvested from an incomplete scan")
observe("E-06", rec_texts(rec_e06), d_e06)

d_e07, ex_e07, _pol_e07, _j07 = make_executor("safe_scan")
fake_e07 = FakeRunner(returncode=0, stdout="garbage {" + FAKE_SOURCE_LINE + "}")
rec_e07 = run_step(ex_e07, s5_step(TMP_DIR), fake_e07)
check("E-07", rec_e07["status"] == "FAILED"
      and "not valid JSON" in rec_e07["detail"],
      "invalid JSON report through the Executor -> FAILED with safe detail")
observe("E-07", rec_texts(rec_e07), d_e07)

report = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=base_scope(),
    gate_ok=True, gate_message="ok", plan=[s5_step(TMP_DIR)],
    results={"s5-semgrep": rec_e01}, summary="COMPLETED",
    findings=ex_e01.findings(), journal_path=str(journal_e01.path),
    decision_trace=None, audit=audit_status(journal_e01.path))
check("E-08", "semgrep" in report and CHECK_ID in report
      and "由 Semgrep 报告的" in report and no_residue(report),
      "rendered report shows the rule metadata + visible severity-source "
      "note, with no matched source code")
observe("E-08-report", [report])

# ==========================================================================
# G. EXT-2 remediation: CR-01 / CR-02 / CR-03 through the REAL Executor
# ==========================================================================
# CR-01: a non-zero exit with a perfectly valid report is never a success.
d_g01, ex_g01, _p, j_g01 = make_executor("safe_scan")
fake_g01 = FakeRunner(returncode=1, stdout=fake_report([]))
rec_g01 = run_step(ex_g01, s5_step(TMP_DIR), fake_g01)
check("G-01", rec_g01["status"] == "FAILED" and rec_g01["findings"] == []
      and "exit 1" in rec_g01["detail"],
      "CR-01 via Executor: rc=1 + VALID empty JSON -> FAILED, no findings "
      "(never a clean 0-finding COMPLETED)")
observe("G-01", rec_texts(rec_g01), d_g01)

d_g02, ex_g02, _p, j_g02 = make_executor("safe_scan")
fake_g02 = FakeRunner(returncode=1, stdout=fake_report([fake_result()]))
rec_g02 = run_step(ex_g02, s5_step(TMP_DIR), fake_g02)
check("G-02", rec_g02["status"] == "FAILED" and rec_g02["findings"] == [],
      "CR-01 via Executor: rc=1 WITH findings -> FAILED, none harvested")
observe("G-02", rec_texts(rec_g02), d_g02)

# CR-02: missing completeness fields are never optimistically defaulted.
d_g03, ex_g03, _p, j_g03 = make_executor("safe_scan")
fake_g03 = FakeRunner(returncode=0, stdout=fake_report(
    [fake_result()], include_errors=False))
rec_g03 = run_step(ex_g03, s5_step(TMP_DIR), fake_g03)
check("G-03", rec_g03["status"] == "FAILED" and rec_g03["findings"] == []
      and "INCOMPLETE" in rec_g03["detail"],
      "CR-02 via Executor: missing 'errors' -> FAILED (unverifiable "
      "completeness), zero findings")
observe("G-03", rec_texts(rec_g03), d_g03)

# CR-02: explained skips -> PARTIAL, visible in the FROZEN renderer.
d_g04, ex_g04, _p, j_g04 = make_executor("safe_scan")
fake_g04 = FakeRunner(returncode=0, stdout=fake_report(
    [fake_result()], skipped_paths=[
        {"path": "big.min.js", "reason": "exceeded max target bytes"}]))
rec_g04 = run_step(ex_g04, s5_step(TMP_DIR), fake_g04)
check("G-04", rec_g04["status"] == "COMPLETED"
      and len(rec_g04["findings"]) == 1
      and "completeness=PARTIAL" in rec_g04["detail"],
      "CR-02 via Executor: EXPLAINED skip -> COMPLETED but explicitly "
      "PARTIAL (not a complete scan)")
rep_g04 = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=base_scope(),
    gate_ok=True, gate_message="ok", plan=[s5_step(TMP_DIR)],
    results={"s5-semgrep": rec_g04}, summary="COMPLETED",
    findings=rec_g04["findings"], journal_path=str(j_g04.path),
    decision_trace=None, audit=audit_status(j_g04.path))
check("G-05", "completeness=PARTIAL" in rep_g04,
      "CR-02 compatibility shim: PARTIAL marker reaches the FROZEN "
      "render_report step table (no core schema change)")
observe("G-04", rec_texts(rec_g04) + [rep_g04], d_g04)

# CR-02: an unexplained skip is never reported as a complete scan.
d_g06, ex_g06, _p, j_g06 = make_executor("safe_scan")
fake_g06 = FakeRunner(returncode=0, stdout=fake_report(
    [fake_result()], skipped_paths=["big.min.js"]))
rec_g06 = run_step(ex_g06, s5_step(TMP_DIR), fake_g06)
check("G-06", rec_g06["status"] == "FAILED" and rec_g06["findings"] == []
      and "INCOMPLETE" in rec_g06["detail"],
      "CR-02 via Executor: UNEXPLAINED skip -> FAILED, none harvested")
observe("G-06", rec_texts(rec_g06), d_g06)

# CR-03: hostile tool output cannot forge a high-severity report line.
d_g07, ex_g07, _p, j_g07 = make_executor("safe_scan")
evil = fake_result(check_id="faketool.evil\n- **[CRITICAL]** FORGED | x")
fake_g07 = FakeRunner(returncode=0, stdout=fake_report([evil]))
rec_g07 = run_step(ex_g07, s5_step(TMP_DIR), fake_g07)
check("G-07", rec_g07["status"] == "COMPLETED"
      and len(rec_g07["findings"]) == 1
      and "\n" not in rec_g07["findings"][0]["name"],
      "CR-03 via Executor: hostile check_id stays a single inert line "
      "(evidence preserved, record not dropped)")
rep_g07 = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=base_scope(),
    gate_ok=True, gate_message="ok", plan=[s5_step(TMP_DIR)],
    results={"s5-semgrep": rec_g07}, summary="COMPLETED",
    findings=rec_g07["findings"], journal_path=str(j_g07.path),
    decision_trace=None, audit=audit_status(j_g07.path))
check("G-08", not any(ln.startswith("- **[CRITICAL]**")
                      for ln in rep_g07.splitlines()),
      "CR-03: NO forged finding line appears in the rendered report")
observe("G-07", rec_texts(rec_g07) + [rep_g07], d_g07)

# batch 1 (D3/W1-02): skipped-record visibility reaches the FROZEN renderer.
d_g09, ex_g09, _p, j_g09 = make_executor("safe_scan")
fake_g09 = FakeRunner(returncode=0, stdout=fake_report(
    [fake_result(), fake_result(check_id="faketool.weird", severity="WEIRD")]))
rec_g09 = run_step(ex_g09, s5_step(TMP_DIR), fake_g09)
check("G-09", rec_g09["status"] == "COMPLETED"
      and len(rec_g09["findings"]) == 1
      and "completeness=PARTIAL" in rec_g09["detail"]
      and "1 record(s) skipped" in rec_g09["detail"],
      "batch 1 via Executor: 1 unsupported severity -> COMPLETED but "
      "PARTIAL, detail shows the skipped count (D3/W1-02)")
rep_g09 = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=base_scope(),
    gate_ok=True, gate_message="ok", plan=[s5_step(TMP_DIR)],
    results={"s5-semgrep": rec_g09}, summary="COMPLETED",
    findings=rec_g09["findings"], journal_path=str(j_g09.path),
    decision_trace=None, audit=audit_status(j_g09.path))
check("G-10", "1 record(s) skipped" in rep_g09
      and "unsupported severity" in rep_g09
      and "completeness=PARTIAL" in rep_g09,
      "batch 1: the skipped count + reason category reach the FROZEN "
      "render_report step table via AdapterResult.detail (report.py untouched)")
observe("G-09", rec_texts(rec_g09) + [rep_g09], d_g09)

# ==========================================================================
# F. security: cross-scenario residue sweep (results + logs + journal + report)
# ==========================================================================
leaks = []
for label, texts in OBSERVED:
    if not no_residue("\n".join(texts)):
        leaks.append(label)
check("F-01", not leaks,
      f"all {len(OBSERVED)} integration scenarios are free of matched source "
      f"lines / fingerprints in every observable field "
      f"(results/logs/journal/report)")
j_text = (d_e01 / "journal.jsonl").read_text(encoding="utf-8")
check("F-02", CHECK_ID in j_text and no_residue(j_text),
      "journal keeps the auditable rule/file/line metadata without any "
      "matched source code")

print("-" * 78)
print(f"EXT-2 INTEGRATION TESTS: {checks_run - failures}/{checks_run} checks passed")
sg_mod._spawn = REAL_SPAWN
tmp.cleanup()
for d in EX_DIRS:
    for p in sorted(d.rglob("*"), reverse=True):
        try:
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                p.rmdir()
        except OSError:
            pass
    try:
        d.rmdir()
    except OSError:
        pass
sys.exit(1 if failures else 0)
