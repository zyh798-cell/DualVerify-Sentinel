"""S3-C2A tests: AutonomousLoop scheduling on TaskGraph (static plans only).

No P9, no dynamic spawning, no real targets — fake adapters only.

Run:  python tests/test_graph_loop.py
"""
import io
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter  # noqa: E402
from vuln_hunter.decision import DecisionEngine  # noqa: E402
from vuln_hunter.journal import EvidenceJournal, verify  # noqa: E402
from vuln_hunter.loop import AutonomousLoop  # noqa: E402
from vuln_hunter.policy import PolicyEngine  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402
from vuln_hunter.taskgraph import (  # noqa: E402
    GraphBuilder, TaskGraph, TaskGraphError,
)

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
    d = {"client": "gl-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "gl-test"}
    d.update(kw)
    return d


class OkAdapter(ToolAdapter):
    id, risk = "gl_ok", "R1"
    order = []

    def _run(self, target, timeout, log, step=None):
        OkAdapter.order.append(step["id"] if step else target)
        return AdapterResult("COMPLETED", True, "ok")


class RefuseAdapter(ToolAdapter):
    id, risk = "gl_refuse", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("REFUSED", False, "policy-refused (fake)")


class TimeoutAdapter(ToolAdapter):
    id, risk = "gl_timeout", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT", False, "hung")


class TimeoutInitAdapter(ToolAdapter):
    id, risk = "gl_tinit", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT_INITIALIZING", False, "killed before traffic")


class TimeoutScanAdapter(ToolAdapter):
    id, risk = "gl_tscan", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT_SCANNING", False, "killed mid-scan")


class FakeNuclei(ToolAdapter):
    id, risk = "gl_nuclei", "R2"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT", False, "hung (fake dynamic)")


class NoEvidenceProbe(ToolAdapter):
    id, risk = "http_probe", "R1"  # overrides real probe in this test process

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "empty", findings=[])


for cls in (OkAdapter, RefuseAdapter, TimeoutAdapter, TimeoutInitAdapter,
            TimeoutScanAdapter, FakeNuclei, NoEvidenceProbe):
    register_adapter(cls)


def step(nid, adapter="gl_ok", target=None, **kw) -> dict:
    s = {"id": nid, "adapter": adapter,
         "target": target if target is not None else "127.0.0.1",
         "timeout": 5}
    s.update(kw)
    return s


def mkloop(mode="safe_scan", max_steps=6, **scope_kw):
    tmp = Path(tempfile.mkdtemp())
    journal = EvidenceJournal(tmp / "j.jsonl")
    policy = PolicyEngine(base_scope(**scope_kw), mode)
    ex = Executor(policy, journal, tmp / "ev", sleep_fn=lambda s: None)
    loop = AutonomousLoop(policy, journal, ex, DecisionEngine(max_steps=max_steps))
    return loop, ex, journal


def events(jpath: Path) -> list[str]:
    return [json.loads(l)["rec"]["event"]
            for l in Path(jpath).read_text(encoding="utf-8").splitlines()
            if l.strip()]


with tempfile.TemporaryDirectory() as td:

    # ---- GL-01 legacy list[dict] interface --------------------------------
    loop, ex, j = mkloop()
    trace, degraded = loop.run([step("a"), step("b", target="127.0.0.1:9")])
    check("GL-01", isinstance(trace, list) and degraded is False
          and trace[-1]["action"] == "STOP" and ex.summary_status() == "COMPLETED",
          f"legacy plan runs unchanged ({len(trace)} decisions)")

    # ---- GL-02 GraphBuilder conversion inside loop -------------------------
    loop, ex, j = mkloop()
    loop.run([step("a"), step("b", deps=("a",), target="127.0.0.1:9")])
    evs = events(j.path)
    start = [json.loads(l)["rec"] for l in j.path.read_text(encoding="utf-8").splitlines()
             if '"loop_start"' in l][0]
    check("GL-02", start["plan"] == ["a", "b"] and "decision" in evs
          and evs[-1] == "loop_end",
          "loop converted list plan via GraphBuilder (loop_start plan ids match)")

    # ---- GL-03 pre-built graph: state write-back ---------------------------
    loop, ex, j = mkloop()
    g = GraphBuilder.from_plan([step("a")])
    loop.run(g)
    check("GL-03", g.nodes["a"].state == "COMPLETED"
          and g.nodes["a"].result["status"] == "COMPLETED",
          "pre-built TaskGraph advanced in place; result rec attached")

    # ---- GL-04/05 dependency order -----------------------------------------
    loop, ex, j = mkloop()
    OkAdapter.order = []
    loop.run([step("a"), step("b", deps=("a",), target="127.0.0.1:9")])
    check("GL-04", OkAdapter.order == ["a", "b"],
          f"execution order follows deps: {OkAdapter.order}")
    check("GL-05", "b" not in OkAdapter.order[:1],
          "downstream never executed before its dependency")

    # ---- GL-06 dep FAILED -> downstream SKIPPED, never executed ------------
    loop, ex, j = mkloop()
    OkAdapter.order = []
    g = GraphBuilder.from_plan([step("a", adapter="gl_refuse"),
                                step("b", deps=("a",))])
    loop.run(g)
    check("GL-06", g.nodes["a"].state == "REFUSED" and g.nodes["b"].state == "SKIPPED"
          and "b" not in OkAdapter.order,
          "REFUSED dep -> downstream graph-SKIPPED without execution")

    # ---- GL-07 multi-layer cascade -----------------------------------------
    loop, ex, j = mkloop()
    g = GraphBuilder.from_plan([step("a", adapter="gl_refuse"),
                                step("b", deps=("a",), target="127.0.0.1:9"),
                                step("c", deps=("b",), target="127.0.0.1:9090")])
    loop.run(g)
    evs = events(j.path)
    check("GL-07", g.nodes["b"].state == "SKIPPED" and g.nodes["c"].state == "SKIPPED"
          and evs.count("node_skipped_by_dependency") == 2,
          "multi-layer cascade: both descendants SKIPPED, each journaled")

    # ---- GL-08 DEGRADE semantics preserved ---------------------------------
    loop, ex, j = mkloop(mode="vuln_validation")
    g = GraphBuilder.from_plan([step("s1dyn", adapter="gl_nuclei"),
                                step("s2dyn", adapter="gl_nuclei", target="127.0.0.1:9"),
                                step("s3", adapter="gl_ok")])
    trace, degraded = loop.run(g)
    degrade_ev = [json.loads(l)["rec"] for l in j.path.read_text(encoding="utf-8").splitlines()
                  if '"degrade"' in l]
    check("GL-08", degraded is True and g.nodes["s2dyn"].state == "SKIPPED"
          and g.nodes["s1dyn"].state == "TIMEOUT"
          and g.nodes["s3"].state == "COMPLETED"
          and degrade_ev and degrade_ev[0]["dropped_dynamic_steps"] == ["s2dyn"],
          "DEGRADE: dynamic PENDING node dropped via legal PENDING->SKIPPED")

    # ---- GL-09 STOP on refusal ---------------------------------------------
    loop, ex, j = mkloop()
    trace, _ = loop.run([step("a", adapter="gl_refuse"), step("b")])
    check("GL-09", trace[0]["action"] == "RUN_NEXT"
          and trace[1]["action"] == "STOP" and trace[1]["next"] == "policy_refusal_or_abort",
          "REFUSED -> P1 STOP (loop halts on refusal)")
    # precise: b must NOT have been executed by the loop
    check("GL-09b", ex.results.get("b", {}).get("status") in (None, "SKIPPED"),
          "downstream of REFUSED never ran")

    # ---- GL-10 ASK_CONFIRM semantics ---------------------------------------
    loop, ex, j = mkloop()
    trace, _ = loop.run([step("p", adapter="http_probe")])
    check("GL-10", trace[-1]["action"] == "ASK_CONFIRM"
          and trace[-1]["next"] == "cannot_reliably_judge",
          "no-evidence probe -> ASK_CONFIRM preserved")

    # ---- GL-11 decision selects READY nodes in rule order ------------------
    loop, ex, j = mkloop()
    trace, _ = loop.run([step("a"), step("b", deps=("a",), target="127.0.0.1:9")])
    seq = [(d["action"], d["next"]) for d in trace]
    check("GL-11", seq == [("RUN_NEXT", "a"), ("RUN_NEXT", "b"),
                           ("STOP", "plan_exhausted")],
          f"decision sequence: {seq}")

    # ---- GL-12 all-terminal normal end -------------------------------------
    loop, ex, j = mkloop()
    loop.run([step("a"), step("b", target="127.0.0.1:9")])
    evs = events(j.path)
    check("GL-12", evs[-1] == "loop_end" and ex.summary_status() == "COMPLETED"
          and verify(j.path)[0],
          "all nodes terminal -> plan_exhausted end, journal chain intact")

    # ---- GL-13 PENDING-without-READY cannot loop forever -------------------
    # Sabotage the scheduler's view (ready_nodes -> []) while PENDING nodes
    # exist: the loop must terminate via the defensive branch or a normal
    # decision stop — never hang. (Post-cascade the inconsistency branch is
    # structurally unreachable; this proves the guard exists anyway.)
    loop2, ex2, j2 = mkloop()
    g2 = GraphBuilder.from_plan([step("a"), step("b", deps=("a",), target="127.0.0.1:9")])
    g2.ready_nodes = lambda: []           # sabotage: scheduler sees nothing ready
    trace2, _ = loop2.run(g2)
    end_reasons = [json.loads(l)["rec"].get("reason") or ""
                   for l in j2.path.read_text(encoding="utf-8").splitlines()
                   if '"loop_end"' in l]
    check("GL-13", trace2 == [] and
          any("scheduler inconsistency" in r for r in end_reasons),
          f"empty-ready situation terminates immediately with journaled "
          f"inconsistency (trace={trace2}, reasons={end_reasons})")

    # ---- GL-14/15/16/17 runner status -> graph state -----------------------
    for case, adapter, expect in [
        ("GL-14", "gl_ok", "COMPLETED"),
        ("GL-15", "gl_refuse", "REFUSED"),
        ("GL-16", "gl_tinit", "TIMEOUT_INITIALIZING"),
        ("GL-17", "gl_tscan", "TIMEOUT_SCANNING"),
    ]:
        loop, ex, j = mkloop()
        g = GraphBuilder.from_plan([step("n", adapter=adapter)])
        loop.run(g)
        check(case, g.nodes["n"].state == expect
              and g.nodes["n"].result["status"] == expect,
              f"runner {expect} faithfully written back")

    # ---- GL-18/19 journal failure: propagate, never fake a terminal --------
    tmp = Path(tempfile.mkdtemp())
    real = EvidenceJournal(tmp / "j.jsonl")

    class AuditFailJournal:
        def __init__(self):
            self.path = real.path

        def append(self, event, **fields):
            if event == "attempt_end":
                raise OSError("audit sink down")
            return real.append(event, **fields)

    policy = PolicyEngine(base_scope(), "safe_scan")
    audit_fail = AuditFailJournal()
    ex = Executor(policy, audit_fail, tmp / "ev", sleep_fn=lambda s: None)
    loop = AutonomousLoop(policy, audit_fail, ex, DecisionEngine())
    g = GraphBuilder.from_plan([step("n", adapter="gl_ok")])
    raised = False
    try:
        loop.run(g)
    except OSError as exc:
        raised = "audit sink down" in str(exc)
    check("GL-18", raised, "journal failure inside run_step propagates out of loop.run")
    check("GL-19", g.nodes["n"].state == "RUNNING"
          and "step_end" not in events(real.path),
          "node NOT faked into a terminal state; no step_end journaled")

    # ---- GL-20 loop guard still armed ---------------------------------------
    class RunForeverEngine:
        max_steps = 100

        def decide(self, *a, **k):
            return {"ts": "t", "input": {}, "policy_verdict": {},
                    "action": "RUN_NEXT", "reason": "forced", "next": "a"}

    loop, ex, j = mkloop(max_steps=100)
    loop.engine = RunForeverEngine()
    g = GraphBuilder.from_plan([step("a")])
    g.mark = lambda *a, **k: None          # sabotage write-back -> endless loop attempt
    trace, _ = loop.run(g)
    check("GL-20", len(trace) >= 3 * 100 + 6 and
          any("guard tripped" in (json.loads(l)["rec"].get("reason") or "")
              for l in j.path.read_text(encoding="utf-8").splitlines()
              if '"loop_end"' in l),
          f"guard tripped after {len(trace)} decisions (no infinite loop)")

    # ---- GL-21 CANCELLED handling -------------------------------------------
    loop, ex, j = mkloop()
    ex.cancel()
    g = GraphBuilder.from_plan([step("a"), step("b", target="127.0.0.1:9")])
    trace, _ = loop.run(g)
    check("GL-21", g.nodes["a"].state == "CANCELLED"
          and any(d["action"] == "STOP" and d["next"] == "cancelled" for d in trace),
          "cancelled run: node CANCELLED, decision STOP 'cancelled'")

    # ---- GL-22 empty / invalid plans ----------------------------------------
    loop, ex, j = mkloop()
    trace, _ = loop.run([])
    check("GL-22a", len(trace) == 1 and trace[0]["next"] == "plan_exhausted",
          "empty plan -> single plan_exhausted decision")
    try:
        loop.run([{"id": "x", "adapter": "gl_ok"}])   # missing target
        check("GL-22b", False, "invalid plan accepted!")
    except TaskGraphError as exc:  # noqa: F821
        check("GL-22b", "missing required field" in str(exc),
              f"invalid plan rejected: {str(exc)[:50]}")

    # ---- GL-23 legacy decision-sequence parity (reference) ------------------
    # Reference sequence for a healthy 2-step plan under the UNCHANGED
    # DecisionEngine, derived from the pre-S3 loop semantics.
    loop, ex, j = mkloop()
    trace, _ = loop.run([step("a"), step("b", deps=("a",), target="127.0.0.1:9")])
    seq = [(d["action"], d["next"]) for d in trace]
    expected = [("RUN_NEXT", "a"), ("RUN_NEXT", "b"), ("STOP", "plan_exhausted")]
    check("GL-23", seq == expected,
          f"graph-mode decisions match legacy semantics: {seq}")

print("-" * 78)
total = 25
print(f"GRAPH LOOP TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
