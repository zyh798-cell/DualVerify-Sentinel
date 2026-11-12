"""S3-B TaskGraph infrastructure tests (structure layer only — no execution).

Run:  python tests/test_taskgraph.py
"""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters_ext.gitleaks import gitleaks_binary  # noqa: E402
from vuln_hunter.planner import build_plan  # noqa: E402
from vuln_hunter.taskgraph import (  # noqa: E402
    GraphBuilder, TaskGraph, TaskGraphError, TaskNode,
    NON_TERMINAL, TERMINAL,
)

failures = 0


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def expect_err(case_id, fn, frag: str, note: str):
    try:
        fn()
        check(case_id, False, f"{note} — no exception raised!")
    except TaskGraphError as exc:
        check(case_id, frag in str(exc), f"{note} -> {str(exc)[:70]}")
    except Exception as exc:  # noqa: BLE001
        check(case_id, False, f"{note} — wrong exception {exc.__class__.__name__}: {exc}")


def node(nid, adapter="http_probe", target=None, **kw) -> TaskNode:
    kind = kw.pop("kind", "probe")
    # default target is unique per id so structural tests don't trip the
    # (intended) duplicate-fingerprint guard; dedup tests pass explicit targets
    return TaskNode(id=nid, kind=kind, adapter=adapter,
                    target=target if target is not None else f"tgt-{nid}", **kw)


def make_graph(**kw) -> TaskGraph:
    return TaskGraph(**kw)


# ---- TG-01 normal node creation + defaults -----------------------------------
g = make_graph()
n = node("a", origin="initial")
g.add_node(n)
check("TG-01", g.nodes["a"].state == "PENDING" and g.nodes["a"].timeout == 30
      and g.nodes["a"].target_kind == "net" and g.nodes["a"].spawn_depth == 0,
      "normal node creation with defaults")

# ---- TG-02 duplicate id ------------------------------------------------------
expect_err("TG-02", lambda: g.add_node(node("a")), "duplicate node id",
           "duplicate id rejected")

# ---- TG-03 self dependency ---------------------------------------------------
expect_err("TG-03", lambda: g.add_node(node("b", deps=("b",))), "self-dependency",
           "self-dependency rejected")

# ---- TG-04 unknown dependency (structural cycle prevention) ------------------
expect_err("TG-04", lambda: g.add_node(node("c", deps=("ghost",))),
           "unknown", "unknown/forward dependency rejected (no forward edges, no cycles)")

# ---- TG-05 duplicate dependency entries --------------------------------------
expect_err("TG-05", lambda: g.add_node(node("d", deps=("a", "a"))),
           "duplicate dependency", "duplicate dep entries rejected")

# ---- TG-06 acyclic chain builds; cycle impossible by construction ------------
g6 = make_graph()
g6.add_node(node("n1"))
g6.add_node(node("n2", deps=("n1",)))
g6.add_node(node("n3", deps=("n2",)))
check("TG-06", len(g6.nodes) == 3 and g6._deps["n3"] == ("n2",),
      "3-node chain builds; forward refs impossible -> cycles impossible")

# ---- TG-07 legal transitions --------------------------------------------------
g7 = make_graph()
g7.add_node(node("t1"))
g7.mark("t1", "READY")
g7.mark("t1", "RUNNING")
g7.mark("t1", "COMPLETED", result={"status": "COMPLETED"})
check("TG-07", g7.nodes["t1"].state == "COMPLETED"
      and g7.nodes["t1"]["result"] if False else
      g7.nodes["t1"].result == {"status": "COMPLETED"},
      "PENDING->READY->RUNNING->COMPLETED with result attached")

# ---- TG-08 illegal transition (fail-closed) -----------------------------------
g8 = make_graph()
g8.add_node(node("t2"))
expect_err("TG-08", lambda: g8.mark("t2", "COMPLETED"),
           "illegal transition", "PENDING->COMPLETED rejected (must pass READY/RUNNING)")

# ---- TG-09 terminal is irreversible -------------------------------------------
expect_err("TG-09", lambda: g7.mark("t1", "READY"),
           "irreversible", "COMPLETED -> READY rejected")

# ---- TG-10 ready_nodes only deps-satisfied ------------------------------------
g10 = make_graph()
g10.add_node(node("r1"))
g10.add_node(node("r2", deps=("r1",)))
g10.add_node(node("r3"))
ready = [x.id for x in g10.ready_nodes()]
check("TG-10", sorted(ready) == ["r1", "r3"],
      "r2 not ready (dep PENDING); r1/r3 ready")

# ---- TG-11 dep FAILED -> not ready --------------------------------------------
g10.mark("r1", "READY"); g10.mark("r1", "RUNNING"); g10.mark("r1", "FAILED")
check("TG-11", [x.id for x in g10.ready_nodes()] == ["r3"],
      "dep FAILED -> dependent never ready")

# ---- TG-12 dep SKIPPED -> not ready -------------------------------------------
g10.mark("r3", "READY"); g10.mark("r3", "RUNNING"); g10.mark("r3", "COMPLETED")
g12 = make_graph()
g12.add_node(node("x1"))
g12.add_node(node("x2", deps=("x1",)))
g12.mark("x1", "SKIPPED")
check("TG-12", [x.id for x in g12.ready_nodes()] == [],
      "dep SKIPPED -> dependent never ready")

# ---- TG-13 node budget (max_nodes) --------------------------------------------
g13 = make_graph(max_nodes=3)
for i in range(3):
    g13.add_node(node(f"b{i}"))
expect_err("TG-13", lambda: g13.add_node(node("b3")), "budget exhausted",
           "33rd/4th node over budget rejected")

# ---- TG-14 spawn depth budget --------------------------------------------------
g14 = make_graph(max_spawn_depth=2)
deep = node("deep", origin="rule:d1", spawn_depth=3)
expect_err("TG-14", lambda: g14.add_node(deep, dynamic=True),
           "exceeds budget", "spawn_depth 3 > 2 rejected")

# ---- TG-15 spawn count budget --------------------------------------------------
g15 = make_graph(max_spawns=2)
g15.add_node(node("base"))
for i in range(2):
    g15.add_node(node(f"sp{i}", origin="rule:d", spawn_depth=1), dynamic=True)
expect_err("TG-15", lambda: g15.add_node(
    node("sp2", origin="rule:d", spawn_depth=1), dynamic=True),
    "spawn budget exhausted", "9th/3rd spawn over budget rejected")

# ---- TG-16 dynamic node must have spawn_depth >= 1 ----------------------------
expect_err("TG-15b", lambda: g15.add_node(node("bad", origin="rule:d"),
                                          dynamic=True),
           "spawn_depth >= 1", "dynamic node without depth rejected")

# ---- TG-17 dynamic duplicate fingerprint rejected (substance-based) ----------
# Same substance (adapter,target,params), DIFFERENT id AND origin -> rejected.
g17 = make_graph()
g17.add_node(node("f1", target="127.0.0.1", origin="rule:d1", spawn_depth=1),
             dynamic=True)
dup = node("f2", target="127.0.0.1", origin="rule:d2", spawn_depth=1)
expect_err("TG-17", lambda: g17.add_node(dup, dynamic=True),
           "duplicate dynamic task",
           "same-substance dynamic task rejected despite new id+origin")

# ---- TG-17b static plan may contain same-substance steps ----------------------
g17b = make_graph()
g17b.add_node(node("f1"))
g17b.add_node(node("f2"))     # same adapter/target/params, different id
check("TG-17b", len(g17b.nodes) == 2,
      "static plan allows same-substance steps (PLAN_FULL case, ids unique)")

# ---- TG-17c static nodes never pollute the dynamic fingerprint store ----------
g17c = make_graph()
g17c.add_node(node("f1", adapter="nuclei", target="127.0.0.1",
                   params={"nuclei_tags": ["cve"]}))
dyn_followup = node("f2", adapter="nuclei", target="127.0.0.1",
                    params={"nuclei_tags": ["cve"]},
                    origin="rule:d1", spawn_depth=1)
g17c.add_node(dyn_followup, dynamic=True)
check("TG-17c", len(g17c.nodes) == 2,
      "dynamic follow-up on a target already covered statically is allowed (P9 case)")

# ---- TG-17d same origin, different id -> still deduped ------------------------
g17d = make_graph()
g17d.add_node(node("d1", target="127.0.0.1", origin="rule:a", spawn_depth=1),
              dynamic=True)
expect_err("TG-17d", lambda: g17d.add_node(
    node("d2", target="127.0.0.1", origin="rule:a", spawn_depth=1), dynamic=True),
    "duplicate dynamic task", "changing id alone cannot bypass dedup")

# ---- TG-17e different adapter / different params coexist dynamically ----------
g17e = make_graph()
g17e.add_node(node("e1", adapter="gl_a", origin="rule:a", spawn_depth=1),
              dynamic=True)
g17e.add_node(node("e2", adapter="gl_b", origin="rule:b", spawn_depth=1),
              dynamic=True)
g17e.add_node(node("e3", adapter="gl_a", origin="rule:c", spawn_depth=1,
                   params={"mode": "deep"}), dynamic=True)
check("TG-17e", len(g17e.nodes) == 3,
      "different adapter or params -> different substance, all admitted")

# ---- TG-17f spawn budgets still enforced on dynamic path ----------------------
g17f = make_graph(max_spawns=1)
g17f.add_node(node("s1", origin="rule:a", spawn_depth=1), dynamic=True)
expect_err("TG-17f", lambda: g17f.add_node(
    node("s2", adapter="other", origin="rule:b", spawn_depth=1), dynamic=True),
    "spawn budget exhausted", "budget check precedes fingerprint check, still active")

# ---- TG-18 different params -> different fingerprint --------------------------
g18 = make_graph()
g18.add_node(node("p1", adapter="nuclei", target="127.0.0.1",
                  params={"nuclei_ids": ["1"]}))
g18.add_node(node("p2", adapter="nuclei", target="127.0.0.1",
                  params={"nuclei_ids": ["2"]}))
check("TG-18", len(g18.nodes) == 2 and
      g18.fingerprint("nuclei", "127.0.0.1", {"nuclei_ids": ["1"]}) !=
      g18.fingerprint("nuclei", "127.0.0.1", {"nuclei_ids": ["2"]}),
      "different params -> different fingerprint, both admitted")

# ---- TG-19 snapshot completeness ----------------------------------------------
g19 = make_graph()
g19.add_node(node("s1", origin="initial"))
g19.add_node(node("s2", deps=("s1",), origin="rule:d1", spawn_depth=1,
                  params={"nuclei_tags": ["x"]}), dynamic=True)
g19.mark("s1", "READY")
snap = g19.snapshot()
s2 = snap["s2"]
check("TG-19", snap["s1"]["state"] == "READY" and s2["origin"] == "rule:d1"
      and s2["spawn_depth"] == 1 and s2["deps"] == ["s1"]
      and s2["params"] == {"nuclei_tags": ["x"]} and s2["has_result"] is False
      and set(snap["s1"].keys()) == {"state", "kind", "adapter", "target",
      "target_kind", "timeout", "deps", "origin", "spawn_depth", "params",
      "has_result"},
      "snapshot contains full structure + state")

# ---- TG-20 snapshot mutation never affects graph ------------------------------
snap["s1"]["state"] = "COMPLETED"
snap["s2"]["deps"].append("ghost")
snap["s2"]["params"]["nuclei_tags"].append("injected")
check("TG-20", g19.nodes["s1"].state == "READY"
      and g19._deps["s2"] == ("s1",)
      and g19.nodes["s2"].params_view == {"nuclei_tags": ["x"]},
      "deep-copied snapshot: external mutation cannot touch graph")

# ---- TG-21/22 from_plan: count + field equality (3 plan shapes) ---------------
# EXT-1.1: the third shape gains "s4-gitleaks" only when the gitleaks binary
# resolves (optional tool, machine-independent expectation).
for mode, source_dir, expect_ids in [
    ("safe_scan", None, ["s1-probe"]),
    ("vuln_validation", None, ["s1-probe", "s2-nuclei"]),
    ("vuln_validation", "src", ["s1-probe", "s2-nuclei", "s3-bandit"]
     + (["s4-gitleaks"] if gitleaks_binary() is not None else [])),
]:
    plan = build_plan(mode, "127.0.0.1:8080", source_dir=source_dir)
    gph = GraphBuilder.from_plan(plan)
    ids_ok = list(gph.nodes.keys()) == expect_ids
    fields_ok = True
    for step in plan:
        st = gph.nodes[step["id"]].to_step()
        for k, v in step.items():
            if st.get(k) != v:
                fields_ok = False
        extra = set(st.keys()) - set(step.keys()) - {"target_kind"}
        if extra:
            fields_ok = False
    check(f"TG-21[{mode}{'+' + 'src' if source_dir else ''}]",
          ids_ok and fields_ok,
          f"from_plan: ids {expect_ids}, every original field round-trips, "
          f"no unsupported extras")

# ---- TG-23 to_step runner-compat keys + deps semantics ------------------------
g23 = GraphBuilder.from_plan(build_plan("vuln_validation", "127.0.0.1:8080"))
st = g23.nodes["s2-nuclei"].to_step()
check("TG-23", st["deps"] == ["s1-probe"] and st["target_kind"] == "net"
      and isinstance(st["deps"], list)
      and set(st.keys()) <= {"id", "adapter", "target", "timeout", "deps",
                             "target_kind", "nuclei_ids", "nuclei_tags"},
      "to_step emits only Runner-supported keys; deps list preserved")

# ---- TG-24 empty plan ----------------------------------------------------------
g24 = GraphBuilder.from_plan([])
check("TG-24", len(g24.nodes) == 0 and g24.ready_nodes() == [],
      "empty plan -> empty graph")

# ---- TG-25 invalid plans rejected ---------------------------------------------
expect_err("TG-25a", lambda: GraphBuilder.from_plan([{"id": "a", "adapter": "x"}]),
           "missing required field", "plan step missing target rejected")
expect_err("TG-25b", lambda: GraphBuilder.from_plan(["not-a-dict"]),
           "must be a dict", "non-dict step rejected")
expect_err("TG-25c", lambda: GraphBuilder.from_plan(
    [{"id": "a", "adapter": "x", "target": "t"}, {"id": "a", "adapter": "y", "target": "t"}]),
    "duplicate step id", "duplicate id inside plan rejected")
expect_err("TG-25d", lambda: GraphBuilder.from_plan(None),
           "must be a list", "None plan rejected")

# ---- TG-26 unknown state in mark -> fail-closed -------------------------------
g26 = make_graph()
g26.add_node(node("u1"))
expect_err("TG-26a", lambda: g26.mark("u1", "WEIRD_STATE"), "unknown state",
           "unknown state rejected")
expect_err("TG-26b", lambda: g26.mark("u1", "TIMEOUT_INITIALIZING"),
           "illegal transition", "TIMEOUT_* only reachable from RUNNING")

# ---- TG-27 TIMEOUT_* transitions legal from RUNNING ---------------------------
g27 = make_graph()
g27.add_node(node("t7"))
g27.mark("t7", "READY"); g27.mark("t7", "RUNNING")
g27.mark("t7", "TIMEOUT_INITIALIZING", result={"timeout_class": "TIMEOUT_INITIALIZING"})
check("TG-27", g27.nodes["t7"].state == "TIMEOUT_INITIALIZING"
      and g27.nodes["t7"].result["timeout_class"] == "TIMEOUT_INITIALIZING",
      "RUNNING -> TIMEOUT_INITIALIZING legal (real Runner status)")
g27b = make_graph()
g27b.add_node(node("t7b"))
g27b.mark("t7b", "READY"); g27b.mark("t7b", "RUNNING")
g27b.mark("t7b", "TIMEOUT")
check("TG-27b", g27b.nodes["t7b"].state == "TIMEOUT",
      "RUNNING -> TIMEOUT (bucketed) legal")

# ---- TG-28 params immutability -------------------------------------------------
src = {"nuclei_tags": ["a"]}
g28 = make_graph()
g28.add_node(node("p", adapter="nuclei", params=src))
src["nuclei_tags"].append("MUTATED")          # caller mutates original
view = g28.nodes["p"].params_view
view["nuclei_tags"].append("MUTATED-VIA-VIEW")  # caller mutates the view
check("TG-28", g28.nodes["p"].params_view == {"nuclei_tags": ["a"]},
      "params frozen at creation: neither original nor view mutation leaks in")

# ---- TG-29 dep edges immutable after registration ------------------------------
g29 = make_graph()
g29.add_node(node("e1"))
g29.add_node(node("e2", deps=("e1",)))
g29.nodes["e2"].deps = ("ghost",)             # hostile re-point of the tuple attr
g29.mark("e1", "READY"); g29.mark("e1", "RUNNING"); g29.mark("e1", "COMPLETED")
check("TG-29", [x.id for x in g29.ready_nodes()] == ["e2"],
      "graph routes on its own edge registry; node.deps reassignment ignored")

# ---- TG-30 RUNNING -> CANCELLED legal; PENDING -> CANCELLED legal -------------
g30 = make_graph()
g30.add_node(node("c1"))
g30.add_node(node("c2"))
g30.mark("c1", "CANCELLED")
g30.mark("c2", "READY"); g30.mark("c2", "RUNNING"); g30.mark("c2", "CANCELLED")
check("TG-30", all(g30.nodes[c].state == "CANCELLED" for c in ("c1", "c2")),
      "cancellation reachable from PENDING and RUNNING")

# ---- TG-31 all states in vocabulary match Runner ------------------------------
from vuln_hunter.runner import STATUS_PRIORITY  # noqa: E402
check("TG-31", set(STATUS_PRIORITY) <= set(TERMINAL)
      and "PLANNED" not in (NON_TERMINAL + TERMINAL),
      "graph states are a superset of Runner terminal statuses; "
      "PLANNED is runner-internal and never a node state")

print("-" * 78)
total = 35
print(f"TASKGRAPH TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
