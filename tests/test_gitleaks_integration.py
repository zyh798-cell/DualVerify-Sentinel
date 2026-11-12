"""EXT-1.1: Gitleaks adapter formal integration tests (no real tool call).

Verifies the EXT-1.1 wiring end to end WITHOUT installing or running
gitleaks — the single subprocess seam (gitleaks._spawn) is replaced by a
scripted fake, exactly like the EXT-1 adapter tests. The authorization
gate, planner, executor, journal and report are all REAL.

Coverage map (task book -> section):
  T1 packaging      pyproject ships the subpackage; layout on disk       (A)
  T2 registration   import-for-registration via the CLI module/process;
                    duplicate registration harmless; built-in trio
                    untouched; registration != execution; --source-dir
                    help documents gitleaks                             (B)
  T3 execution      planner emits s4-gitleaks only with source_dir AND a
                    resolvable binary; fs_path survives TaskGraph         (C)
  T4 authorization  REAL gate: no-ticket GateRequired, passive-mode
                    REFUSED, target_kind mismatch (both directions),
                    scope-hash binding, window at issuance, cancellation,
                    timeout, path guard behind a VALID ticket,
                    Executor success/failure/skip paths                  (D, E)
  T5 severity       GITLEAKS_DEFAULT_SEVERITY is a documented SYSTEM
                    default constant — never a tool-reported fact         (E)
  security          results + attempt logs + journal + rendered report
                    are free of fictional secrets in every scenario       (F)

Run:  python tests/test_gitleaks_integration.py
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
import vuln_hunter.adapters_ext.gitleaks as gl_mod  # noqa: E402
import vuln_hunter.planner as planner_mod  # noqa: E402
from vuln_hunter.adapters import GateRequired  # noqa: E402
from vuln_hunter.adapters_ext.gitleaks import (  # noqa: E402
    GITLEAKS_DEFAULT_SEVERITY, GitleaksAdapter, register_gitleaks,
)
from vuln_hunter.journal import EvidenceJournal, audit_status  # noqa: E402
from vuln_hunter.policy import PolicyEngine, PolicyRefusal  # noqa: E402
from vuln_hunter.report import render_report  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402
from vuln_hunter.taskgraph import GraphBuilder  # noqa: E402

# EXT-1.2: tests that exercise the Executor need an explicitly prepared
# registry. Importing modules (including __main__) no longer registers
# adapters — only the CLI start-up path calls register_gitleaks().
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
ALL_SECRETS = [FAKE_SECRET_A, FAKE_SECRET_B]


def fake_record(rule="faketool-aws-key", file="faketool/config.py", line=12,
                secret=FAKE_SECRET_A, end_line=None, tags=("key", "aws")):
    """One realistic gitleaks report record. Secret-bearing and
    non-whitelisted fields are populated ON PURPOSE so tests can prove
    they never leak into findings, logs, journal or the report."""
    return {
        "Description": "Fictional AWS-shaped access key",
        "StartLine": line,
        "EndLine": line if end_line is None else end_line,
        "Match": f'aws_key = "{secret}"',          # secret-bearing: never read
        "Secret": secret,                           # secret-bearing: never read
        "File": file,
        "Commit": "dead" + "beefcafe1234",          # non-whitelisted
        "Author": "fictional-author",               # non-whitelisted
        "Email": "fictional@example.invalid",       # non-whitelisted
        "Fingerprint": f"{file}:{rule}:{line}",
        "Tags": list(tags),
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
# Installed immediately: proves that import/registration alone never spawns.
IMPORT_SPAWN_WATCH = FakeRunner()
gl_mod._spawn = IMPORT_SPAWN_WATCH

OBSERVED = []   # (label, [observable texts]) for the final residue sweep
EX_DIRS = []    # executor temp dirs, cleaned up at the end

tmp = tempfile.TemporaryDirectory(prefix="dvs-gl-int-")
TMP_DIR = tmp.name
scope_path = Path(TMP_DIR) / "scope.json"


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=2)).strftime(fmt)}")


def base_scope(**kw) -> dict:
    d = {"client": "gl-int-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "gl-int-test"}
    d.update(kw)
    return d


def s4_step(target, timeout=30, sid="s4-gitleaks"):
    return {"id": sid, "adapter": "gitleaks", "target": target,
            "timeout": timeout, "target_kind": "fs_path"}


def patched(fake, binary="/fake/gitleaks", fallbacks=None):
    """Install the fake spawn (+ optional binary resolution); returns restore()."""
    old_which = gl_mod.shutil.which
    old_fallbacks = gl_mod.GITLEAKS_FALLBACKS
    gl_mod._spawn = fake
    gl_mod.shutil.which = lambda name: binary if name == "gitleaks" else None
    if fallbacks is not None:
        gl_mod.GITLEAKS_FALLBACKS = fallbacks

    def restore():
        gl_mod._spawn = REAL_SPAWN
        gl_mod.shutil.which = old_which
        gl_mod.GITLEAKS_FALLBACKS = old_fallbacks

    return restore


def make_executor(mode="safe_scan", **scope_kw):
    d = Path(tempfile.mkdtemp(prefix="dvs-gl-int-ex-"))
    EX_DIRS.append(d)
    journal = EvidenceJournal(d / "journal.jsonl")
    policy = PolicyEngine(base_scope(**scope_kw), mode)
    ex = Executor(policy, journal, d / "ev", sleep_fn=lambda s: None)
    return d, ex, policy, journal


def run_step(ex, step, fake, binary="/fake/gitleaks", fallbacks=None):
    restore = patched(fake, binary, fallbacks)
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


def no_secret(blob):
    return not any(s in blob for s in ALL_SECRETS)


print("=" * 78)
print("EXT-1.1 GITLEAKS INTEGRATION TESTS (mocked execution, real gate)")
print("=" * 78)

# ==========================================================================
# A. T1 packaging: the subpackage must ship, not just import from a checkout
# ==========================================================================
pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
check("A-01", '"vuln_hunter.adapters_ext"' in pyproject,
      "pyproject [tool.setuptools] packages includes the adapters_ext subpackage")
import vuln_hunter.adapters_ext as ext_pkg  # noqa: E402
check("A-02", (Path(ext_pkg.__file__).parent / "gitleaks.py").exists()
      and (Path(ext_pkg.__file__).parent / "__init__.py").exists(),
      "subpackage layout on disk: __init__.py + gitleaks.py")

# ==========================================================================
# B. T2 registration entry point
# ==========================================================================
check("B-01", isinstance(adapters_mod._REGISTRY.get("gitleaks"), GitleaksAdapter),
      "explicit register_gitleaks() prepares the CLI registry "
      "(imports have no registration side effect)")
check("B-02", IMPORT_SPAWN_WATCH.calls == [],
      "import/registration alone never spawns the tool (no auto-scan)")
before = dict(adapters_mod._REGISTRY)
try:
    register_gitleaks()
    register_gitleaks()
    dup_ok = True
except Exception:  # noqa: BLE001 - test harness
    dup_ok = False
check("B-03", dup_ok and isinstance(adapters_mod._REGISTRY.get("gitleaks"),
                                    GitleaksAdapter)
      and adapters_mod._REGISTRY["gitleaks"] is before["gitleaks"],
      "duplicate register_gitleaks() calls are true no-ops "
      "(idempotent, no replacement of the registered instance)")
check("B-04", all(adapters_mod._REGISTRY[k] is before[k]
                  for k in ("http_probe", "nuclei", "bandit")),
      "built-in adapter instances are untouched by extension registration")
check("B-05", sorted(adapters_mod._REGISTRY) == ["bandit", "gitleaks",
                                                 "http_probe", "nuclei"],
      "registry = built-in trio + gitleaks, nothing else")
check("B-06", raises_gate(lambda: adapters_mod.get_adapter("gitleaks", None)),
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
check("B-08", probe.returncode == 0 and "gitleaks" in probe.stdout
      and "bandit" in probe.stdout,
      "CLI start-up (main) registers gitleaks in a fresh subprocess")
help_proc = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "run", "--help"],
    capture_output=True, text=True, cwd=str(ROOT), timeout=120)
check("B-09", help_proc.returncode == 0 and "gitleaks" in help_proc.stdout,
      "CLI --source-dir help documents gitleaks alongside bandit")

# ==========================================================================
# C. T3 execution flow: planner + taskgraph
# ==========================================================================
plan_plain = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080")
check("C-01", [s["id"] for s in plan_plain] == ["s1-probe", "s2-nuclei"],
      "no source_dir -> plan unchanged (no fs steps)")

old_gb = planner_mod.gitleaks_binary
planner_mod.gitleaks_binary = lambda: "/fake/gitleaks"
try:
    plan_src = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                      source_dir=TMP_DIR)
finally:
    planner_mod.gitleaks_binary = old_gb
check("C-02", [s["id"] for s in plan_src] ==
      ["s1-probe", "s2-nuclei", "s3-bandit", "s4-gitleaks"],
      "source_dir + resolvable binary -> s4-gitleaks appended after bandit")
s4 = plan_src[-1]
check("C-03", s4["adapter"] == "gitleaks" and s4["target"] == TMP_DIR
      and s4["target_kind"] == "fs_path" and "deps" not in s4,
      "s4-gitleaks: adapter/target/fs_path kind; no deps "
      "(independent of the bandit outcome)")

planner_mod.gitleaks_binary = lambda: None
try:
    plan_nobin = planner_mod.build_plan("vuln_validation", "127.0.0.1:8080",
                                        source_dir=TMP_DIR)
finally:
    planner_mod.gitleaks_binary = old_gb
check("C-04", [s["id"] for s in plan_nobin] ==
      ["s1-probe", "s2-nuclei", "s3-bandit"],
      "binary not resolvable -> gitleaks step omitted "
      "(a missing optional tool never reddens an existing run)")

gph = GraphBuilder.from_plan(plan_src)
check("C-05", gph.nodes["s4-gitleaks"].target_kind == "fs_path"
      and gph.nodes["s3-bandit"].target_kind == "fs_path"
      and gph.nodes["s1-probe"].target_kind == "net",
      "TaskGraph preserves target_kind: fs_path for local scans, net for probe")

# ==========================================================================
# D. T4 authorization chain (real gate, mocked tool)
# ==========================================================================
a = GitleaksAdapter()
check("D-01", raises_gate(lambda: a.execute(
    None, policy=PolicyEngine(base_scope(), "safe_scan"),
    timeout=5, log=io.StringIO())),
    "execute() without a RunTicket raises GateRequired (no unguarded path)")

# D-02 passive mode (R0 ceiling) refuses the R1 adapter before any spawn
pol_r0 = PolicyEngine(base_scope(), "passive")
t_r0 = pol_r0.issue_ticket(TMP_DIR, "gitleaks", target_kind="fs_path")
fake_d02 = FakeRunner()
restore = patched(fake_d02)
try:
    res_d02 = a.execute(t_r0, policy=pol_r0, timeout=30, log=io.StringIO(),
                        step=s4_step(TMP_DIR))
finally:
    restore()
check("D-02", res_d02.status == "REFUSED" and "ceiling" in res_d02.detail
      and fake_d02.calls == [],
      "passive mode (R0 ceiling) REFUSES the R1 adapter before any spawn")

# D-03 happy path through the real gate
pol_ok = PolicyEngine(base_scope(), "safe_scan")
t_ok = pol_ok.issue_ticket(TMP_DIR, "gitleaks", target_kind="fs_path")
fake_d03 = FakeRunner(returncode=1, stdout=json.dumps([fake_record()]))
restore = patched(fake_d03)
try:
    log_d03 = io.StringIO()
    res_d03 = a.execute(t_ok, policy=pol_ok, timeout=30, log=log_d03,
                        step=s4_step(TMP_DIR))
finally:
    restore()
check("D-03", res_d03.status == "COMPLETED" and len(res_d03.findings) == 1
      and fake_d03.calls and fake_d03.calls[0][0][:2] == ["/fake/gitleaks", "dir"]
      and fake_d03.calls[0][0][2] == TMP_DIR,
      "valid fs_path RunTicket -> execute() runs the tool (mocked) on the "
      "TICKET target and returns findings")
observe("D-03", result_texts(res_d03) + [log_d03.getvalue()])

# D-04 target_kind mismatch, refused in BOTH directions
t_net = pol_ok.issue_ticket("127.0.0.1", "gitleaks")  # net kind, in scope
fake_d04 = FakeRunner()
restore = patched(fake_d04)
try:
    res_d04 = a.execute(t_net, policy=pol_ok, timeout=30, log=io.StringIO(),
                        step=s4_step(TMP_DIR))
    res_d04b = a.execute(t_ok, policy=pol_ok, timeout=30, log=io.StringIO(),
                         step={"id": "s4", "adapter": "gitleaks",
                               "target": TMP_DIR, "timeout": 30})
finally:
    restore()
check("D-04", res_d04.status == "REFUSED" and "target_kind" in res_d04.detail
      and res_d04b.status == "REFUSED" and "target_kind" in res_d04b.detail
      and fake_d04.calls == [],
      "target_kind mismatch refused in BOTH directions (net ticket on fs "
      "step; fs ticket on a default-net step)")

# D-05 scope-hash binding: ticket dies when scope content changes
t_bind = pol_ok.issue_ticket(TMP_DIR, "gitleaks", target_kind="fs_path")
pol_ok.scope["in_scope"].append("10.0.0.1")  # content change after issuance
fake_d05 = FakeRunner()
restore = patched(fake_d05)
try:
    res_d05 = a.execute(t_bind, policy=pol_ok, timeout=30, log=io.StringIO(),
                        step=s4_step(TMP_DIR))
finally:
    restore()
check("D-05", res_d05.status == "REFUSED"
      and "scope content changed" in res_d05.detail and fake_d05.calls == [],
      "scope content change after issuance invalidates the RunTicket")

# D-06 window is enforced at issuance even for fs_path targets
pol_old = PolicyEngine(
    base_scope(window="2020-01-01T00:00Z/2020-01-02T00:00Z"), "safe_scan")
try:
    pol_old.issue_ticket(TMP_DIR, "gitleaks", target_kind="fs_path")
    d06 = False
except PolicyRefusal:
    d06 = True
check("D-06", d06,
      "expired authorization window -> PolicyRefusal at issuance "
      "(fs_path skips only the net-scope check)")

# D-07 adapter-level path guard BEHIND a valid ticket (defense in depth)
pol_guard = PolicyEngine(base_scope(), "safe_scan")
t_home = pol_guard.issue_ticket(str(Path.home()), "gitleaks",
                                target_kind="fs_path")
fake_d07 = FakeRunner()
restore = patched(fake_d07)
try:
    log_d07 = io.StringIO()
    res_d07 = a.execute(t_home, policy=pol_guard, timeout=30, log=log_d07,
                        step=s4_step(str(Path.home())))
finally:
    restore()
check("D-07", res_d07.status == "FAILED" and fake_d07.calls == [],
      "even with a valid ticket the adapter refuses to scan the home "
      "directory (defense in depth, no spawn)")
observe("D-07", result_texts(res_d07) + [log_d07.getvalue()])

# D-08 cancellation through the Executor
d08, ex08, _pol08, _j08 = make_executor("safe_scan")
(d08 / "ev" / "CANCEL").write_text("cancel", encoding="utf-8")
fake_d08 = FakeRunner()
rec_d08 = run_step(ex08, s4_step(TMP_DIR), fake_d08)
check("D-08", rec_d08["status"] == "CANCELLED" and fake_d08.calls == [],
      "CANCEL file in the evidence dir -> step CANCELLED, tool never spawned")

# D-09 timeout through the Executor attempt loop
d09, ex09, _pol09, _j09 = make_executor("safe_scan")
fake_d09 = FakeRunner(exception=subprocess.TimeoutExpired(cmd="gitleaks",
                                                          timeout=30))
rec_d09 = run_step(ex09, s4_step(TMP_DIR, timeout=30), fake_d09)
check("D-09", rec_d09["status"] == "TIMEOUT" and len(fake_d09.calls) == 2,
      "tool timeout -> TIMEOUT after the bounded retry loop (2 attempts, "
      "never a fake success)")
observe("D-09", rec_texts(rec_d09), d09)

# ==========================================================================
# E. T5 severity + Executor end-to-end (success / failure / skip / report)
# ==========================================================================
d_e01, ex_e01, _pol_e01, journal_e01 = make_executor("safe_scan")
fake_e01 = FakeRunner(returncode=1, stdout=json.dumps([fake_record()]))
rec_e01 = run_step(ex_e01, s4_step(TMP_DIR), fake_e01)
check("E-01", rec_e01["status"] == "COMPLETED"
      and len(rec_e01["findings"]) == 1
      and rec_e01["findings"][0]["severity"] == GITLEAKS_DEFAULT_SEVERITY
      and GITLEAKS_DEFAULT_SEVERITY == "high",
      "Executor path: COMPLETED; severity = the documented SYSTEM default "
      "constant (gitleaks reports no severity — never a tool fact)")
f_e01 = rec_e01["findings"][0]
check("E-02", f_e01["finding_id"].startswith("fnd_") and f_e01["tool"] == "gitleaks"
      and f_e01["evidence_redacted"] is False
      and f_e01["location"] == "faketool/config.py:12",
      "unified Finding schema survives the executor path "
      "(id/tool/location/redaction flag)")
check("E-07", isinstance(f_e01.get("name"), str)
      and f_e01["name"].startswith(f_e01["title"])
      and "为系统默认策略" in f_e01["name"]
      and "非 Gitleaks 原生判定" in f_e01["name"]
      and f_e01["finding_type"] == "gitleaks_finding"
      and f_e01["severity"] == GITLEAKS_DEFAULT_SEVERITY,
      "renderer alias carries an explicit severity-source marker; "
      "13 schema fields (incl. severity=high) untouched")
observe("E-01", rec_texts(rec_e01), d_e01)

d_e03, ex_e03, _pol_e03, _j03 = make_executor("safe_scan")
fake_e03 = FakeRunner(returncode=2,
                      stdout=json.dumps([fake_record(secret=FAKE_SECRET_A)]))
rec_e03 = run_step(ex_e03, s4_step(TMP_DIR), fake_e03)
check("E-03", rec_e03["status"] == "FAILED" and "exit 2" in rec_e03["detail"]
      and rec_e03["findings"] == [],
      "abnormal exit through the Executor -> FAILED; findings never "
      "harvested from a failed scan")
observe("E-03", rec_texts(rec_e03), d_e03)

d_e04, ex_e04, _pol_e04, _j04 = make_executor("safe_scan")
fake_e04 = FakeRunner()
rec_e04 = run_step(ex_e04, s4_step(TMP_DIR), fake_e04,
                   binary=None, fallbacks=[])
check("E-04", rec_e04["status"] == "SKIPPED"
      and "preflight" in rec_e04.get("reason", "") and fake_e04.calls == [],
      "missing binary through the Executor -> SKIPPED with the preflight "
      "reason (honest, no spawn)")

d_e05, ex_e05, _pol_e05, _j05 = make_executor("safe_scan")
fake_e05 = FakeRunner(returncode=1, stdout="garbage {" + FAKE_SECRET_B + "}")
rec_e05 = run_step(ex_e05, s4_step(TMP_DIR), fake_e05)
check("E-05", rec_e05["status"] == "FAILED"
      and "not valid JSON" in rec_e05["detail"],
      "invalid JSON report through the Executor -> FAILED with safe detail")
observe("E-05", rec_texts(rec_e05), d_e05)

report = render_report(
    mode="safe_scan", risk="R1", scope_path=str(scope_path), scope=base_scope(),
    gate_ok=True, gate_message="ok", plan=[s4_step(TMP_DIR)],
    results={"s4-gitleaks": rec_e01}, summary="COMPLETED",
    findings=ex_e01.findings(), journal_path=str(journal_e01.path),
    decision_trace=None, audit=audit_status(journal_e01.path))
check("E-06", "gitleaks" in report and "faketool-aws-key" in report
      and "为系统默认策略" in report
      and "非 Gitleaks 原生判定" in report
      and no_secret(report),
      "rendered report shows rule metadata + visible severity-source note, "
      "with no secret residue")
observe("E-06-report", [report])

# ==========================================================================
# F. security: cross-scenario residue sweep (results + logs + journal + report)
# ==========================================================================
leaks = []
for label, texts in OBSERVED:
    if not no_secret("\n".join(texts)):
        leaks.append(label)
check("F-01", not leaks,
      f"all {len(OBSERVED)} integration scenarios are free of fictional "
      f"secrets in every observable field (results/logs/journal/report)")
j_text = (d_e01 / "journal.jsonl").read_text(encoding="utf-8")
check("F-02", "faketool-aws-key" in j_text and no_secret(j_text),
      "journal keeps the auditable rule/file/line metadata without any secret")

print("-" * 78)
print(f"EXT-1.1 INTEGRATION TESTS: {checks_run - failures}/{checks_run} checks passed")
gl_mod._spawn = REAL_SPAWN
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
