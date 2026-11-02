"""Autonomous loop: plan -> execute -> decide -> act, with a journaled
decision trace. The loop NEVER expands scope: it can only choose among nodes
of the (possibly dynamic, S3-C) task graph — or drop them via DEGRADE.

S3-C2A: scheduling now runs on a TaskGraph. `run()` accepts either the legacy
`list[dict]` plan (converted internally via GraphBuilder.from_plan) or a
pre-built TaskGraph. Execution STILL goes exclusively through
Executor.run_step(); the loop never touches adapters, tickets or tools.

State flow per executed node: PENDING -> READY -> RUNNING -> (runner rec
status). After every execution round, PENDING nodes with a blocking
(non-COMPLETED) terminal dependency are cascade-marked SKIPPED so nothing
stays stuck in PENDING. Journal failures (OSError/JournalIntegrityError)
propagate untouched — audit failures are never disguised as step results.

P9 (OPT-IN, default OFF): when enable_p9=True, each just-completed step is
evaluated by the pure rule layer p9.evaluate_p9(); a generated child is
added via graph.add_node(dynamic=True) and executed through the SAME
Runner/gate path as static nodes. Static-plan behaviour is unchanged when
P9 is off.
"""
from .adapters import adapter_risk
from .p9 import evaluate_p9
from .policy import RISK_ORDER
from .taskgraph import TERMINAL, GraphBuilder, TaskGraph, TaskGraphError

# Terminal states that block downstream nodes (everything except COMPLETED).
_BLOCKING = set(TERMINAL) - {"COMPLETED"}


class AutonomousLoop:
    def __init__(self, policy, journal, executor, decision_engine,
                 enable_p9: bool = False):
        self.policy = policy
        self.journal = journal
        self.executor = executor
        self.engine = decision_engine
        # P9 dynamic follow-up generation is OPT-IN; False preserves the
        # exact pre-P9 static scheduling behaviour.
        self.enable_p9 = enable_p9

    def run(self, plan) -> tuple[list[dict], bool]:
        """Returns (decision_trace, degraded). Executes at most one pending
        node per decision; every decision is journaled before acting.

        `plan` may be a legacy list[dict] (converted via GraphBuilder) or a
        pre-built TaskGraph (whose states are advanced in place)."""
        if isinstance(plan, TaskGraph):
            graph = plan
        else:
            graph = GraphBuilder.from_plan(plan)
        trace: list[dict] = []
        degraded = False
        guard = self.engine.max_steps * 3 + 6  # hard cap against decision loops
        self.journal.append("loop_start", plan=list(graph.nodes),
                            max_steps=self.engine.max_steps)
        while True:
            if len(trace) >= guard:
                self.journal.append("loop_end", reason="decision iteration guard tripped",
                                    degraded=degraded,
                                    summary=self.executor.summary_status())
                return trace, degraded

            # Dependency cascade: a PENDING node whose deps contain any
            # blocking terminal state can never run — mark it SKIPPED now
            # (fixpoint iteration handles multi-layer chains).
            self._cascade_skipped(graph)

            ready = graph.ready_nodes()
            pending_ids = [nid for nid, n in graph.nodes.items()
                           if n.state == "PENDING"]
            if not ready and pending_ids:
                # Post-cascade this is structurally impossible; if it ever
                # happens, stop instead of looping forever (no silent drop:
                # the stuck nodes are named in the journal).
                self.journal.append(
                    "loop_end",
                    reason=f"scheduler inconsistency: pending nodes without "
                           f"ready deps: {pending_ids}",
                    degraded=degraded,
                    summary=self.executor.summary_status())
                return trace, degraded

            d = self.engine.decide(
                self.policy, self.executor.results,
                [n.to_step() for n in ready],
                len(self.executor.results), degraded=degraded,
            )
            self.journal.append("decision", **d)
            trace.append(d)

            if d["action"] in ("STOP", "ASK_CONFIRM"):
                self.journal.append("loop_end", reason=d["reason"],
                                    degraded=degraded,
                                    summary=self.executor.summary_status())
                return trace, degraded

            if d["action"] == "DEGRADE":
                dropped = []
                for n in list(graph.nodes.values()):
                    if n.state == "PENDING" and RISK_ORDER[adapter_risk(n.adapter)] > 1:
                        graph.mark(n.id, "SKIPPED")
                        dropped.append(n.id)
                degraded = True
                self.journal.append("degrade", dropped_dynamic_steps=dropped,
                                    remaining=[nid for nid, n in graph.nodes.items()
                                               if n.state != "SKIPPED"])
                continue

            # RUN_NEXT — the decision names a node id; it must be a graph node
            # in PENDING state, otherwise fail closed (no execution).
            nxt = d.get("next")
            node = graph.nodes.get(nxt) if isinstance(nxt, str) else None
            if node is None or node.state != "PENDING":
                self.journal.append(
                    "loop_end",
                    reason=f"decision/scheduler inconsistency: next={nxt!r} "
                           f"is not a schedulable node",
                    degraded=degraded,
                    summary=self.executor.summary_status())
                return trace, degraded

            graph.mark(node.id, "READY")
            graph.mark(node.id, "RUNNING")
            rec = self.executor.run_step(node.to_step())
            # Faithful write-back: whatever the Runner reports (COMPLETED,
            # FAILED, TIMEOUT_*, REFUSED, ABORTED, CANCELLED, SKIPPED) becomes
            # the node's terminal state. Journal failures inside run_step
            # propagate before this line — never disguised here.
            graph.mark(node.id, rec["status"], rec)

            # P9 (opt-in): evaluate the just-completed step for dynamic
            # follow-up generation. The rule layer is pure; THIS loop owns
            # journaling and graph mutation. add_node(dynamic=True) is the
            # authoritative budget/fingerprint/structure enforcement — a
            # rejection there is journaled and never crashes the run.
            # Journal write failures inside these appends propagate (audit
            # failure semantics unchanged). Degraded mode never spawns.
            if self.enable_p9 and not degraded:
                events, child = evaluate_p9(graph, node, rec, self.policy)
                for ev_name, ev_fields in events:
                    self.journal.append(ev_name, **ev_fields)
                if child is not None:
                    try:
                        graph.add_node(child, dynamic=True)
                        self.journal.append(
                            "p9_spawn", child=child.id, adapter=child.adapter,
                            target=child.target, timeout=child.timeout,
                            spawn_depth=child.spawn_depth,
                            template=(child.params_view.get("nuclei_ids") or [None])[0],
                        )
                    except TaskGraphError as exc:
                        self.journal.append(
                            "p9_spawn_rejected", child=child.id,
                            reason=f"add_node refused: {exc}")

    # ---- dependency cascade -------------------------------------------------
    def _cascade_skipped(self, graph: TaskGraph) -> None:
        """Mark PENDING nodes SKIPPED when any dependency reached a blocking
        terminal state. Fixpoint iteration covers multi-layer chains. Every
        cascade decision is journaled (no silent drops)."""
        changed = True
        while changed:
            changed = False
            for n in list(graph.nodes.values()):
                if n.state != "PENDING":
                    continue
                dep_states = {d: graph.nodes[d].state for d in n.deps}
                blocking = {d: s for d, s in dep_states.items() if s in _BLOCKING}
                if blocking:
                    graph.mark(n.id, "SKIPPED")
                    self.journal.append("node_skipped_by_dependency",
                                        node=n.id, blocking_deps=blocking)
                    changed = True
