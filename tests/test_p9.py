"""P9-V tests: dynamic focused re-validation from nuclei evidence (opt-in).

No real targets — the fake 'nuclei' adapter overrides the real one in THIS
test process only (established practice, cf. NoEvidenceProbe in
test_graph_loop.py). All evidence is fabricated in-memory; nothing executes
against any network.

Run:  python tests/test_p9.py
"""
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter  # noqa: E402
from vuln_hunter.decision import DecisionEngine  # noqa: E402
from vuln_hunter.journal import EvidenceJournal  # noqa: E402
from vuln_hunter.loop import AutonomousLoop  # noqa: E402
from vuln_hunter.p9 import evaluate_p9  # noqa: E402
from vuln_hunter.policy import PolicyEngine  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402
from vuln_hunter.taskgraph import GraphBuilder  # noqa: E402

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
    d = {"client": "p9-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "p9-test"}
    d.update(kw)
    return d


def finding(template="tpl-demo", **extra) -> dict:
    f = {"type": "nuclei_finding", "template": template,
         "severity": "high", "name": "demo",
         "host": "http://evil.example.com", "matched_at": "http://evil.example.com/x"}
    f.update(extra)
    return f


class FakeNuclei(ToolAdapter):
    """Overrides the real nuclei adapter in this test process.

    Default: broad scans (no nuclei_ids) always 'find' tpl-demo on a host
    OUTSIDE the scope — proving P9 never uses finding.host as a target —
    while focused re-scans come back clean (chain self-terminates).
    chain_mode=True: every run finds a fresh template (exercises
    depth/spawn budgets)."""
    id, risk = "nuclei", "R2"
    calls = []
    chain_mode = False
    counter = 0

    def _run(self, target, timeout, log, step=None):
        FakeNuclei.calls.append((step or {}).get("id"))
        if FakeNuclei.chain_mode:
            FakeNuclei.counter += 1
            return AdapterResult("COMPLETED", True, "find",
                                 findings=[finding(template=f"tpl-{FakeNuclei.counter:04d}")])
        if (step or {}).get("nuclei_ids"):
            return AdapterResult("COMPLETED", True,
                                 f"focused {(step)['nuclei_ids'][0]}: clean")
        return AdapterResult("COMPLETED", True, "broad scan", findings=[finding()])


class DegradeFirst(ToolAdapter):
    """R1 adapter: first call TIMEOUT without retry (triggers DEGRADE),
    second call COMPLETED with nuclei findings — post-degrade completions
    must never reach P9. no_retry is REQUIRED: the Executor would otherwise
    retry the TIMEOUT in-step and complete before any degrade."""
    id, risk = "p9_degrade", "R1"
    calls = 0

    def _run(self, target, timeout, log, step=None):
        DegradeFirst.calls += 1
        if DegradeFirst.calls == 1:
            return AdapterResult("TIMEOUT", False, "first call hangs",
                                 no_retry=True)
        return AdapterResult("COMPLETED", True, "second call finds",
                             findings=[finding()])


register_adapter(FakeNuclei)
register_adapter(DegradeFirst)


def mkloop(mode="vuln_validation", max_steps=8, enable_p9=True, **scope_kw):
    tmp = Path(tempfile.mkdtemp())
    journal = EvidenceJournal(tmp / "j.jsonl")
    policy = PolicyEngine(base_scope(**scope_kw), mode)
    ex = Executor(policy, journal, tmp / "ev", sleep_fn=lambda s: None)
    loop = AutonomousLoop(policy, journal, ex,
                          DecisionEngine(max_steps=max_steps),
                          enable_p9=enable_p9)
    return tmp, journal, ex, loop, policy


def events_of(journal, name):
    return [r for r in journal.read_all() if r.get("event") == name]


def plan(*steps):
    return list(steps)


def unit_graph(target="127.0.0.1", timeout=240, node_id="p"):
    g = GraphBuilder.from_plan([{"id": node_id, "adapter": "nuclei",
                                 "target": target, "timeout": timeout}])
    # Full legal transition chain (terminal states are irreversible).
    for st in ("READY", "RUNNING", "COMPLETED"):
        g.mark(node_id, st)
    return g, g.nodes[node_id]


BROAD = {"id": "s-nuc", "adapter": "nuclei", "target": "127.0.0.1",
         "timeout": 240}
REC_OK = {"status": "COMPLETED", "adapter_risk": "R2", "target": "127.0.0.1",
          "findings": [finding()], "quarantined": False}

# ---------------------------------------------------------------------------
print("=" * 78)
print("P9-V TESTS")
print("=" * 78)

# P9-01 — happy path: COMPLETED broad nuclei -> one focused child, executed
# through the Runner, target verbatim, exact fields, full audit trail.
tmp, journal, ex, loop, policy = mkloop()
FakeNuclei.calls.clear()
loop.run(plan(dict(BROAD)))
child = ex.results.get("s-nuc-p9v-tpl-demo")
check("P9-01a", child is not None and child["status"] == "COMPLETED",
      "child spawned and executed via Runner")
check("P9-01b", "s-nuc-p9v-tpl-demo" in FakeNuclei.calls,
      "child went through the real run_step path (fake nuclei invoked)")
check("P9-01c", child is not None and child.get("target") == "127.0.0.1",
      "target inherited VERBATIM (finding.host is evil.example.com — unused)")
check("P9-01d", events_of(journal, "p9_decision_start")
      and events_of(journal, "p9_trigger")
      and events_of(journal, "p9_checks")
      and events_of(journal, "p9_spawn"),
      "journal has decision_start/trigger/checks/spawn events")
spawn_ev = events_of(journal, "p9_spawn")[0]
check("P9-01e", spawn_ev["child"] == "s-nuc-p9v-tpl-demo"
      and spawn_ev["adapter"] == "nuclei" and spawn_ev["target"] == "127.0.0.1"
      and spawn_ev["timeout"] == 240 and spawn_ev["spawn_depth"] == 1
      and spawn_ev["template"] == "tpl-demo",
      "p9_spawn event records child identity/budget")

# P9-02 — nuclei FAILED but carrying partial findings must NOT trigger.
graph, p = unit_graph()
rec_failed = {"id": "p", "adapter": "nuclei", "adapter_risk": "R2",
              "target": "127.0.0.1", "status": "FAILED",
              "detail": "exit 1 (incomplete)", "findings": [finding()],
              "quarantined": False}
ev2, child2 = evaluate_p9(graph, p, rec_failed, policy)
skip2 = [f for n, f in ev2 if n == "p9_skip"]
check("P9-02", child2 is None and skip2
      and "not COMPLETED" in skip2[0]["reason"],
      "FAILED with partial findings -> p9_skip, no child")

# P9-03 — TIMEOUT family never triggers.
for st in ("TIMEOUT", "TIMEOUT_INITIALIZING", "TIMEOUT_SCANNING"):
    rec_t = dict(REC_OK, status=st)
    ev3, child3 = evaluate_p9(graph, p, rec_t, policy)
    check(f"P9-03[{st}]", child3 is None
          and any(n == "p9_skip" for n, _ in ev3),
          "timeout family -> no spawn")

# P9-04 — findings missing / empty / wrong container / non-dict element.
bad_evidence = [
    ("missing", {"status": "COMPLETED", "adapter_risk": "R2"}),
    ("empty", {"status": "COMPLETED", "adapter_risk": "R2", "findings": []}),
    ("not-a-list", {"status": "COMPLETED", "adapter_risk": "R2",
                    "findings": "oops"}),
    ("non-dict-elem", {"status": "COMPLETED", "adapter_risk": "R2",
                       "findings": ["oops"], "quarantined": False}),
]
for name, rec4 in bad_evidence:
    ev4, child4 = evaluate_p9(graph, p, rec4, policy)
    check(f"P9-04[{name}]", child4 is None
          and any(n == "p9_evidence_invalid" for n, _ in ev4),
          "malformed evidence -> p9_evidence_invalid")

# P9-05 — template missing / empty / wrong type / bad format.
bad_templates = [
    ("missing", {"type": "nuclei_finding"}),
    ("empty", finding(template="")),
    ("non-str", finding(template=123)),
    ("bad-format", finding(template="has space")),
    ("untrimmed", finding(template=" tpl ")),
]
for name, f5 in bad_templates:
    rec5 = dict(REC_OK, findings=[f5])
    ev5, child5 = evaluate_p9(graph, p, rec5, policy)
    check(f"P9-05[{name}]", child5 is None
          and any(n == "p9_evidence_invalid" for n, _ in ev5),
          "invalid template -> fail-closed")

# P9-06 — quarantined never triggers.
rec6 = dict(REC_OK, quarantined=True)
ev6, child6 = evaluate_p9(graph, p, rec6, policy)
check("P9-06", child6 is None and any(n == "p9_skip" for n, _ in ev6),
      "quarantined -> p9_skip")

# P9-07 — degraded mode never spawns (loop gate).
DegradeFirst.calls = 0
tmp, journal, ex, loop, policy = mkloop()
loop.run(plan(
    {"id": "d1", "adapter": "p9_degrade", "target": "127.0.0.1", "timeout": 5},
    {"id": "d2", "adapter": "p9_degrade", "target": "127.0.0.1", "timeout": 5},
))
d2_p9 = [r for r in journal.read_all()
         if r.get("event", "").startswith("p9_") and r.get("parent") == "d2"]
check("P9-07", not d2_p9, "post-degrade completion never reaches P9")

# P9-08 — passive / safe_scan ceiling rejects R2 child (unit).
graph8, p8 = unit_graph()
for mode in ("passive", "safe_scan"):
    _, _, _, _, pol8 = mkloop(mode=mode, enable_p9=False)
    ev8, child8 = evaluate_p9(graph8, p8, REC_OK, pol8)
    rej = [f for n, f in ev8 if n == "p9_spawn_rejected"]
    check(f"P9-08[{mode}]", child8 is None and rej
          and "ceiling" in rej[0]["reason"], "mode ceiling rejects R2 child")

# P9-09 — target verbatim even when finding points elsewhere (unit).
graph9, p9n = unit_graph(target="127.0.0.1:9")
rec9 = dict(REC_OK, target="127.0.0.1:9",
             findings=[finding(host="http://evil.example.com",
                               matched_at="http://10.9.9.9/")])
_, child9 = evaluate_p9(graph9, p9n, rec9,
                        PolicyEngine(base_scope(), "vuln_validation"))
check("P9-09", child9 is not None and child9.target == "127.0.0.1:9",
      "child target == parent.target verbatim (127.0.0.1:9)")

# P9-10 — scope re-check failure rejects (unit: target outside scope).
pol10 = PolicyEngine(base_scope(in_scope=["10.0.0.1"]), "vuln_validation")
ev10, child10 = evaluate_p9(graph8, p8, REC_OK, pol10)
rej10 = [f for n, f in ev10 if n == "p9_spawn_rejected"]
check("P9-10", child10 is None and rej10
      and "in_scope" in rej10[0]["reason"],
      "second scope check rejects out-of-scope target")

# P9-11 — risk escalation rejected (parent executed risk R1, child R2).
rec11 = dict(REC_OK, adapter_risk="R1")
ev11, child11 = evaluate_p9(graph8, p8, rec11,
                            PolicyEngine(base_scope(), "vuln_validation"))
rej11 = [f for n, f in ev11 if n == "p9_spawn_rejected"]
check("P9-11", child11 is None and rej11
      and "exceeds parent executed risk R1" in rej11[0]["reason"],
      "child R2 > parent R1 -> rejected")

# P9-12 — invalid timeout budget rejects; over-cap budget is capped.
for name, t12 in (("zero", 0), ("negative", -5), ("non-int", "240")):
    g12, p12 = unit_graph()
    p12.timeout = t12
    ev12, child12 = evaluate_p9(g12, p12, REC_OK,
                                PolicyEngine(base_scope(), "vuln_validation"))
    check(f"P9-12[{name}]", child12 is None
          and any(n == "p9_spawn_rejected" for n, _ in ev12),
          "invalid budget -> rejected")
g12c, p12c = unit_graph(timeout=600)
_, child12c = evaluate_p9(g12c, p12c, REC_OK,
                          PolicyEngine(base_scope(), "vuln_validation"))
check("P9-12[cap]", child12c is not None and child12c.timeout == 240,
      "parent 600s capped to P9_MAX_TIMEOUT=240")

# P9-13 — depth and spawn budgets (integration, pre-built graphs).
FakeNuclei.chain_mode = True
FakeNuclei.counter = 0
tmp, journal, ex, loop, policy = mkloop(max_steps=12)
g13 = GraphBuilder.from_plan([dict(BROAD)])
loop.run(g13)
depth_rej = [r for r in journal.read_all()
             if r.get("event") == "p9_spawn_rejected"
             and "exceeds budget" in r.get("reason", "")]
check("P9-13a", len(depth_rej) == 1
      and "spawn depth 3" in depth_rej[0]["reason"],
      "depth-3 attempt refused by add_node (max_spawn_depth=2)")
check("P9-13b", len(events_of(journal, "p9_spawn")) == 2,
      "chain stopped at depth 2: exactly 2 spawns")
# spawn budget: fresh loop, max_spawns=1
FakeNuclei.counter = 0
tmp, journal, ex, loop, policy = mkloop(max_steps=12)
g13b = GraphBuilder.from_plan([dict(BROAD)], max_spawns=1)
loop.run(g13b)
budget_rej = [r for r in journal.read_all()
              if r.get("event") == "p9_spawn_rejected"
              and "spawn budget" in r.get("reason", "")]
check("P9-13c", len(budget_rej) == 1, "max_spawns=1 -> second spawn refused")
FakeNuclei.chain_mode = False

# P9-14 — same template never generated twice.
tmp, journal, ex, loop, policy = mkloop()
loop.run(plan(dict(BROAD), {"id": "s-nuc2", "adapter": "nuclei",
                            "target": "127.0.0.1", "timeout": 240}))
tpl_spawns = events_of(journal, "p9_spawn")
covered = [r for r in journal.read_all()
           if r.get("event") == "p9_evidence_invalid"
           and "already covered" in r.get("reason", "")]
check("P9-14", len(tpl_spawns) == 1 and len(covered) >= 1,
      "second identical-template decision refused (dedup), exactly 1 spawn")

# P9-15 — one child per decision, first qualifying template only; different
# templates can spawn in later independent decisions.
graph15, p15 = unit_graph()
rec15 = dict(REC_OK, findings=[finding(template="tpl-a"),
                               finding(template="tpl-b")])
ev15, child15 = evaluate_p9(graph15, p15, rec15,
                            PolicyEngine(base_scope(), "vuln_validation"))
check("P9-15", child15 is not None
      and child15.params_view["nuclei_ids"] == ["tpl-a"]
      and child15.id == "p-p9v-tpl-a",
      "single child, first template only")
graph15b, q15 = unit_graph(node_id="q")
_, child15b = evaluate_p9(graph15b, q15, rec15,
                          PolicyEngine(base_scope(), "vuln_validation"))
check("P9-15b", child15b is not None and child15b.id == "q-p9v-tpl-a",
      "independent decision generates independently")

# P9-16 — journal write failure propagates (never swallowed).
tmp, journal, ex, loop, policy = mkloop()
orig_append = journal.append


def failing_append(event, **fields):
    if event.startswith("p9_"):
        raise OSError("disk on fire (simulated)")
    return orig_append(event, **fields)


journal.append = failing_append
raised = False
try:
    loop.run(plan(dict(BROAD)))
except OSError as exc:
    raised = "disk on fire" in str(exc)
journal.append = orig_append
check("P9-16", raised, "OSError from p9 journaling propagates out of run()")

# P9-17 — dynamic child executed through the ORIGINAL Runner path with a
# faithful result record (companion to P9-01a/01b).
check("P9-17", child is not None and child.get("adapter") == "nuclei"
      and child.get("attempts") == 1
      and child.get("detail") == "focused tpl-demo: clean"
      and child.get("adapter_risk") == "R2",
      "child result written back by the same Executor machinery")

# P9-18 — static semantics unchanged with P9 ENABLED (order + trace parity).
register_adapter(type("GlOk", (ToolAdapter,),
                      {"id": "gl-ok", "risk": "R1",
                       "_run": lambda self, t, to, log, step=None:
                       AdapterResult("COMPLETED", True, "ok")}))
static_plan = [
    {"id": "a1", "adapter": "gl-ok", "target": "127.0.0.1", "timeout": 5},
    {"id": "a2", "adapter": "gl-ok", "target": "127.0.0.1:9", "timeout": 5,
     "deps": ["a1"]},
]
tmp, journal, ex, loop, policy = mkloop(enable_p9=True)
trace_on, degraded_on = loop.run(plan(*static_plan))
order_on = list(ex.results.keys())
tmp2, journal2, ex2, loop2, _ = mkloop(enable_p9=False)
trace_off, degraded_off = loop2.run(plan(*static_plan))
order_off = list(ex2.results.keys())
check("P9-18", order_on == order_off == ["a1", "a2"]
      and degraded_on is False and degraded_off is False
      and len(trace_on) == len(trace_off),
      "static plan execution identical with P9 on/off")

# P9-19 — default OFF: no dynamic nodes, no p9_* events, even with perfect
# trigger evidence.
tmp, journal, ex, loop, policy = mkloop(enable_p9=False)
loop.run(plan(dict(BROAD)))
check("P9-19a", not any(r.get("event", "").startswith("p9_")
                        for r in journal.read_all()),
      "no p9_* journal events when disabled")
check("P9-19b", all(nid == "s-nuc" for nid in ex.results),
      "no dynamic nodes added when disabled")

# P9-20 — explicit enable is the only way P9 runs (constructor kwarg; the
# CLI --p9 flag feeds exactly this switch).
check("P9-20", loop.enable_p9 is False
      and mkloop(enable_p9=True)[3].enable_p9 is True,
      "opt-in switch honoured at the loop boundary")

# P9-21 — journal hash chain intact after a full P9 run.
tmp, journal, ex, loop, policy = mkloop()
loop.run(plan(dict(BROAD)))
ok, bad, detail = journal.verify()
check("P9-21", ok and detail.startswith("chain OK"),
      f"journal hash chain intact after P9 events ({detail})")

print("-" * 78)
print(f"P9 TESTS: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
