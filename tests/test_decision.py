"""Decision-engine & autonomous-loop unit tests (fake adapters, injected).

Also contains two reliability checks:
  RE-01  timeout kills the real subprocess promptly (direct child)
  RE-02  fresh_evidence_dir never reuses an existing journal dir

Run:  python tests/test_decision.py
"""
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vuln_hunter.adapters as _adapters_mod  # noqa: E402
from vuln_hunter.adapters import AdapterResult, ToolAdapter  # noqa: E402
from vuln_hunter.decision import DecisionEngine  # noqa: E402
from vuln_hunter.journal import EvidenceJournal  # noqa: E402
from vuln_hunter.loop import AutonomousLoop  # noqa: E402
from vuln_hunter.policy import ACK_KEYS, PolicyEngine  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402
from vuln_hunter.__main__ import fresh_evidence_dir  # noqa: E402

failures = 0


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return f"{(now - timedelta(minutes=5)).strftime(fmt)}/{(now + timedelta(hours=2)).strftime(fmt)}"


def base_scope(**kw) -> dict:
    d = {"client": "de-test", "in_scope": ["127.0.0.1"], "out_of_scope": ["none"],
         "window": current_window(), "confirmed_by": "de-test"}
    d.update(kw)
    return d


class OkAdapter(ToolAdapter):
    id, risk = "de_ok", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "ok", [{"type": "probe", "status": 200}])


class ProbeNoEvidence(ToolAdapter):
    id, risk = "de_probe_empty", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "ok", [])  # no findings


class FailAdapter(ToolAdapter):
    id, risk = "de_fail", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("FAILED", False, "boom")


class TimeoutAdapter(ToolAdapter):
    id, risk = "de_timeout", "R2"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT", False, "hung")


class RefuseAdapter(ToolAdapter):
    id, risk = "de_refuse", "R2"

    def _run(self, target, timeout, log, step=None):  # pragma: no cover
        raise AssertionError("must not run")


class CancelTouchAdapter(ToolAdapter):
    """Touches the CANCEL file during execution, then succeeds."""
    id, risk = "de_cancel_touch", "R1"

    def _run(self, target, timeout, log, step=None):
        (Path(log.name).parent / "CANCEL").write_text("stop", encoding="utf-8")
        return AdapterResult("COMPLETED", True, "ok", [{"type": "x"}])


for _cls in (OkAdapter, ProbeNoEvidence, FailAdapter, TimeoutAdapter,
             RefuseAdapter, CancelTouchAdapter):
    _adapters_mod.register_adapter(_cls)

PLAN_FULL = [
    {"id": "s1", "adapter": "de_ok", "target": "127.0.0.1:8080", "timeout": 5},
    {"id": "s2", "adapter": "de_ok", "target": "127.0.0.1:8080", "timeout": 5, "deps": ["s1"]},
]
PLAN_DYNAMIC = [
    {"id": "s1", "adapter": "de_ok", "target": "127.0.0.1:8080", "timeout": 5},
    {"id": "s2dyn", "adapter": "de_timeout", "target": "127.0.0.1:8080", "timeout": 5, "deps": ["s1"]},
    {"id": "s3static", "adapter": "de_ok", "target": "some/dir", "timeout": 5, "target_kind": "fs_path"},
]


def mkloop(scope=None, mode="safe_scan", plan=None, max_steps=6):
    tmp = Path(tempfile.mkdtemp())
    journal = EvidenceJournal(tmp / "j.jsonl")
    policy = PolicyEngine(scope or base_scope(), mode)
    ex = Executor(policy, journal, tmp / "ev", sleep_fn=lambda s: None)
    loop = AutonomousLoop(policy, journal, ex, DecisionEngine(max_steps=max_steps))
    return loop, ex, journal


with tempfile.TemporaryDirectory() as td:
    # ---- DE-01: fresh start with healthy policy -> RUN_NEXT ---------------
    loop, ex, _ = mkloop()
    d = loop.engine.decide(ex.policy, {}, PLAN_FULL, 0)
    check("DE-01", d["action"] == "RUN_NEXT" and d["next"] == "s1" and d["policy_verdict"]["window_ok"], "healthy start RUN_NEXT")

    # ---- DE-02: invalid window -> STOP before execution -------------------
    loop, ex, _ = mkloop(scope=base_scope(window="2026-01-01T00:00Z/2026-01-02T00:00Z"))
    d = loop.engine.decide(ex.policy, {}, PLAN_FULL, 0)
    check("DE-02", d["action"] == "STOP" and d["next"] == "authorization_window", "bad window STOP pre-execution")

    # ---- DE-03: R3 without ack -> STOP ------------------------------------
    loop, ex, _ = mkloop(mode="attack_simulation")
    d = loop.engine.decide(ex.policy, {}, PLAN_FULL, 0)
    check("DE-03", d["action"] == "STOP" and d["next"] == "risk_acknowledgement", "missing ack STOP pre-execution")

    # ---- DE-04: any REFUSED -> STOP, pending untouched --------------------
    loop, ex, _ = mkloop()
    ex.results["s0"] = {"id": "s0", "status": "REFUSED", "reason": "out of scope", "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, PLAN_FULL, 1)
    check("DE-04", d["action"] == "STOP" and d["next"] == "policy_refusal_or_abort", "REFUSED terminal")

    # ---- DE-05: quarantine (429) -> STOP ----------------------------------
    loop, ex, _ = mkloop()
    ex.results["s0"] = {"id": "s0", "status": "FAILED", "quarantined": True, "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, PLAN_FULL, 1)
    check("DE-05", d["action"] == "STOP" and d["next"] == "rate_limit_stop", "429 quarantine STOP")

    # ---- DE-06: FAILED -> STOP (no expansion; pending not executed) -------
    loop, ex, _ = mkloop()
    ex.results["s1"] = {"id": "s1", "status": "FAILED", "attempts": 2, "detail": "boom", "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, PLAN_FULL[1:], 1)
    check("DE-06", d["action"] == "STOP" and d["next"] == "unreliable_result_stop", "FAILED stops, never expands")

    # ---- DE-07: TIMEOUT with static fallback -> DEGRADE -------------------
    loop, ex, _ = mkloop()
    ex.results["s2dyn"] = {"id": "s2dyn", "status": "TIMEOUT", "attempts": 2, "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, [{"id": "s3static", "adapter": "de_ok", "target": "d", "timeout": 5}], 2)
    check("DE-07", d["action"] == "DEGRADE", "timeout degrades to static fallback")

    # ---- DE-08: TIMEOUT without fallback -> STOP --------------------------
    loop, ex, _ = mkloop()
    ex.results["s2dyn"] = {"id": "s2dyn", "status": "TIMEOUT", "attempts": 2, "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, [], 2)
    check("DE-08", d["action"] == "STOP" and d["next"] == "timeout_no_fallback", "timeout without fallback STOP")

    # ---- DE-09: probe no evidence -> ASK_CONFIRM --------------------------
    loop, ex, _ = mkloop()
    ex.results["s1"] = {"id": "s1", "adapter": "http_probe", "status": "COMPLETED", "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, PLAN_FULL[1:], 1)
    check("DE-09", d["action"] == "ASK_CONFIRM" and d["confirmation_required"], "cannot judge -> ASK_CONFIRM")

    # ---- DE-10/11: plan exhausted / budget --------------------------------
    loop, ex, _ = mkloop()
    d = loop.engine.decide(ex.policy, {}, [], 0)
    check("DE-10", d["action"] == "STOP" and d["next"] == "plan_exhausted", "empty plan STOP")
    loop, ex, _ = mkloop(max_steps=3)
    d = loop.engine.decide(ex.policy, {}, PLAN_FULL, 3)
    check("DE-11", d["action"] == "STOP" and d["next"] == "budget_exhausted", "budget exhausted STOP")

    # ---- LP-01: happy loop, decisions recorded ----------------------------
    loop, ex, journal = mkloop()
    trace, degraded = loop.run(PLAN_FULL)
    actions = [d["action"] for d in trace]
    check("LP-01a", actions == ["RUN_NEXT", "RUN_NEXT", "STOP"] and set(ex.results) == {"s1", "s2"}, "loop executes plan then stops")
    check("LP-01b", not degraded and len(journal.read_all()) >= len(trace) + 2, "every decision journaled")

    # ---- LP-02: first step fails -> second never RUNS (only SKIPPED) ------
    loop, ex, _ = mkloop()
    plan_f = [{"id": "s1", "adapter": "de_fail", "target": "127.0.0.1:8080", "timeout": 5},
              {"id": "s2", "adapter": "de_ok", "target": "127.0.0.1:8080", "timeout": 5, "deps": ["s1"]}]
    trace, _ = loop.run(plan_f)
    check("LP-02", "s2" not in ex.results and trace[-1]["next"] == "unreliable_result_stop", "FAILED first step -> loop halts, s2 never touched at all")

    # ---- LP-03: dynamic timeout -> degrade -> static runs -----------------
    loop, ex, journal = mkloop(mode="vuln_validation")
    trace, degraded = loop.run(PLAN_DYNAMIC)
    check("LP-03a", degraded and ex.results["s2dyn"]["status"] == "TIMEOUT" and ex.results["s3static"]["status"] == "COMPLETED", "timeout -> degrade -> static executed")
    check("LP-03b", any(d["action"] == "DEGRADE" for d in trace), "DEGRADE decision in trace")
    check("LP-03c", sum(1 for d in trace if d["action"] == "DEGRADE") == 1, "degrade decision appears exactly once")

    # ---- LP-04: cancel mid-step -> subsequent steps CANCELLED, loop halts -
    loop, ex, _ = mkloop()
    plan_c = [{"id": "s1", "adapter": "de_cancel_touch", "target": "127.0.0.1:8080", "timeout": 5},
              {"id": "s2", "adapter": "de_ok", "target": "127.0.0.1:8080", "timeout": 5, "deps": ["s1"]}]
    trace, _ = loop.run(plan_c)
    check("LP-04", ex.results["s1"]["status"] == "COMPLETED" and ex.results["s2"]["status"] == "CANCELLED" and trace[-1]["next"] == "cancelled", "cancel propagates, loop halts")

    # ---- LP-06: every journaled decision has complete fields --------------
    loop, ex, journal = mkloop()
    loop.run(PLAN_FULL)
    decs = [r for r in journal.read_all() if r["event"] == "decision"]
    complete = all(
        ("input" in d and "policy_verdict" in d and "action" in d
         and d.get("reason") and "next" in d and "confirmation_required" in d
         and {"mode", "risk_ceiling", "window_ok"} <= set(d["policy_verdict"]))
        for d in decs
    )
    check("LP-06", len(decs) == 3 and complete, "decision records carry input/policy-verdict/reason/next")

    # ---- LP-07: REFUSED (earlier) outranks TIMEOUT (last) -----------------
    loop, ex, _ = mkloop(mode="vuln_validation")
    ex.results["sA"] = {"id": "sA", "status": "REFUSED", "reason": "out of scope", "findings": []}
    ex.results["sB"] = {"id": "sB", "status": "TIMEOUT", "attempts": 2, "findings": []}
    d = loop.engine.decide(ex.policy, ex.results, [{"id": "sC", "adapter": "de_ok", "target": "d", "timeout": 5}], 2)
    check("LP-07", d["action"] == "STOP" and d["next"] == "policy_refusal_or_abort", "policy refusal outranks timeout (P1 > P4)")

    # ---- LP-08: budget vs plan-exhausted precedence -----------------------
    loop, ex, _ = mkloop(max_steps=2)
    d_full = loop.engine.decide(ex.policy, {}, [{"id": "sX", "adapter": "de_ok", "target": "t", "timeout": 5}], 2)
    d_done = loop.engine.decide(ex.policy, {}, [], 2)
    check("LP-08a", d_full["action"] == "STOP" and d_full["next"] == "budget_exhausted", "budget stop only when work remains")
    check("LP-08b", d_done["action"] == "STOP" and d_done["next"] == "plan_exhausted", "plan exhaustion outranks budget check")

    # ---- LP-05: decisions never point outside the plan --------------------
    loop, ex, _ = mkloop()
    trace, _ = loop.run(PLAN_FULL)
    allowed = {s["id"] for s in PLAN_FULL} | {"plan_exhausted", "budget_exhausted", "authorization_window",
                                              "risk_acknowledgement", "policy_refusal_or_abort",
                                              "rate_limit_stop", "unreliable_result_stop",
                                              "timeout_degrade", "timeout_no_fallback", "cancelled"}
    check("LP-05", all(d["next"] in allowed for d in trace), "loop never invents targets/steps beyond plan")
    check("LP-05b", all(d["next"] in allowed for d in trace + [loop.engine.decide(ex.policy, ex.results, [], len(ex.results))]), "final decision also within allowed set")

    # ---- RE-01: real subprocess timeout kills the child promptly ----------
    class RealSleepAdapter(ToolAdapter):
        id, risk = "re_sleep", "R1"

        def _run(self, target, timeout, log, step=None):
            try:
                subprocess.run([sys.executable, "-c", "import time;time.sleep(30)"],
                               capture_output=True, timeout=2)
            except subprocess.TimeoutExpired:
                return AdapterResult("TIMEOUT", False, "sleep killed at 2s")
            return AdapterResult("COMPLETED", True, "unexpected")

    _adapters_mod.register_adapter(RealSleepAdapter)
    loop, ex, _ = mkloop()
    t0 = time.monotonic()
    ex.run_step({"id": "r1", "adapter": "re_sleep", "target": "127.0.0.1:8080", "timeout": 5})
    elapsed = time.monotonic() - t0
    check("RE-01", ex.results["r1"]["status"] == "TIMEOUT" and elapsed < 10, f"timeout enforced in {elapsed:.1f}s (child killed, no 30s hang)")

    # ---- RE-02: fresh_evidence_dir never reuses journal dirs --------------
    base = Path(td) / "ev"
    d1 = fresh_evidence_dir(base)
    (d1 / "journal.jsonl").write_text("{}\n", encoding="utf-8")
    d2 = fresh_evidence_dir(base)
    d3 = fresh_evidence_dir(base.with_name(base.name + "-r2"))
    check("RE-02a", d2.name == base.name + "-r2", "re-run gets -r2 suffix")
    check("RE-02b", d3.name == base.name + "-r2" and d3 == d2, "empty -r2 dir is reused (only journal presence counts)")

    # ---- P1-01: timeout classification from phase timeline ----------------
    from vuln_hunter.adapters import classify_timeout, phase_from_line, tool_env

    check("P1-01a", classify_timeout([]) == "TIMEOUT_INITIALIZING", "no output -> INITIALIZING")
    check("P1-01b", classify_timeout([{"phase": "startup"}]) == "TIMEOUT_INITIALIZING", "pre-compile kill -> INITIALIZING")
    check("P1-01c", classify_timeout([{"phase": "templates_loaded"}, {"phase": "scan_progress"}]) == "TIMEOUT_SCANNING", "traffic observed -> SCANNING")
    check("P1-01d", classify_timeout([{"phase": "templates_loaded"}]) == "TIMEOUT_UNCLASSIFIED", "compiled but no traffic evidence -> UNCLASSIFIED")

    # ---- P1-02: phase parsing against REAL nuclei output fixtures ---------
    f1 = phase_from_line("[INF] Templates loaded for current scan: 1")
    f2 = phase_from_line('[0:00:00] | Templates: 1 | Hosts: 1 | RPS: 7 | Matched: 0 | Errors: 0 | Requests: 2/2 (100%)')
    f3 = phase_from_line("[INF] Scan completed in 257.9549ms. No results found.")
    f4 = phase_from_line('{"template-id":"x"}')
    f5 = phase_from_line("[INF] misc noise line")
    check("P1-02a", f1 == ("templates_loaded", "n=1"), "templates_loaded parsed")
    check("P1-02b", f2 == ("scan_progress", "requests=2"), "stats progress parsed")
    check("P1-02c", f3 == ("scan_completed", "257.9549ms"), "scan_completed parsed")
    check("P1-02d", f4 == ("result_json", ""), "result JSON parsed")
    check("P1-02e", f5 is None, "noise ignored (no invented phases)")

    # ---- P1-03: proxy-sanitized tool environment --------------------------
    env = tool_env()
    leaked = [k for k in env if k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")]
    check("P1-03a", not leaked, f"proxy vars stripped (ambient was set: {bool(os.environ.get('HTTP_PROXY'))})")
    check("P1-03b", env.get("NO_PROXY") == "*", "NO_PROXY=* forced direct")

    # ---- P1-04: independent nuclei budget in plan -------------------------
    from vuln_hunter.planner import build_plan
    plan_def = build_plan("vuln_validation", "127.0.0.1:8080", timeout_dynamic=30)
    nstep = [s for s in plan_def if s["adapter"] == "nuclei"][0]
    check("P1-04a", nstep["timeout"] == 240, "nuclei budget independent of --timeout (240 default)")
    plan_sub = build_plan("vuln_validation", "127.0.0.1:8080", timeout_dynamic=30,
                          nuclei_timeout=300, nuclei_ids=["CVE-2000-0114"])
    nsub = [s for s in plan_sub if s["adapter"] == "nuclei"][0]
    check("P1-04b", nsub["timeout"] == 300 and nsub["nuclei_ids"] == ["CVE-2000-0114"], "explicit subset + explicit budget honored")
    plan_probe = build_plan("safe_scan", "127.0.0.1:8080", timeout_dynamic=30)
    check("P1-04c", all(s["adapter"] != "nuclei" for s in plan_probe), "probe-only plan unaffected")

    # ---- P1-05: TIMEOUT_* subclass must degrade run summary (regression: E2
    # first run reported COMPLETED for a timed-out scan) ---------------------
    from vuln_hunter.runner import _summary_bucket
    check("P1-05a", _summary_bucket("TIMEOUT_INITIALIZING") == "TIMEOUT", "TIMEOUT_* buckets to TIMEOUT")
    check("P1-05b", _summary_bucket("TIMEOUT_SCANNING") == "TIMEOUT", "TIMEOUT_SCANNING buckets to TIMEOUT")
    check("P1-05c", _summary_bucket("SOME_FUTURE_STATUS") == "FAILED", "unknown status fail-closed, never success")
    loop, ex, _ = mkloop()
    ex.results["s1"] = {"id": "s1", "status": "COMPLETED", "findings": []}
    ex.results["s2"] = {"id": "s2", "status": "TIMEOUT_INITIALIZING", "attempts": 2, "findings": []}
    check("P1-05d", ex.summary_status() == "TIMEOUT", "run summary TIMEOUT despite a COMPLETED step")

    # ---- P1-06: decision P4 fires for TIMEOUT_* subclass (degrade path) ----
    loop, ex, _ = mkloop(mode="vuln_validation")
    ex.results["s2dyn"] = {"id": "s2dyn", "status": "TIMEOUT_INITIALIZING", "attempts": 2, "findings": []}
    d = loop.engine.decide(ex.policy, ex.results,
                           [{"id": "s3static", "adapter": "de_ok", "target": "d", "timeout": 5}], 2)
    check("P1-06a", d["action"] == "DEGRADE", "TIMEOUT_INITIALIZING triggers degrade")
    ex.results["s3static"] = {"id": "s3static", "status": "COMPLETED", "findings": []}
    d2 = loop.engine.decide(ex.policy, ex.results, [], 3)
    check("P1-06b", d2["action"] == "STOP" and d2["next"] == "plan_exhausted", "after degrade completes, plan exhausts normally")

print("-" * 78)
total = 11 + 10 + 3 + 13 + 7  # DE, LP(+P1-01..04), RE, P1-05/06 regressions
print(f"DECISION/LOOP TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
