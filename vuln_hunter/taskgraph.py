"""TaskGraph: DAG data-structure layer for dynamic task orchestration (S3-B).

This module is PURE STRUCTURE: it never executes tools, never touches policy
gates, and never performs I/O. Execution remains in runner.py (unchanged);
orchestration decisions remain in decision.py/loop.py (S3-C).

Design contract:
- deps may only reference nodes that ALREADY exist in the graph at add time
  (structural acyclicity; an explicit acyclicity assert runs anyway).
- Node states use the EXACT strings Runner/Executor already produce
  (runner.STATUS_PRIORITY + TIMEOUT_INITIALIZING/TIMEOUT_SCANNING subclasses);
  no new state names are invented.
- All state transitions go through TaskGraph.mark() against a whitelist;
  terminal states are irreversible; unknown states fail closed (ValueError).
- Dynamic-node budgets are configurable with safe defaults:
  max_nodes=32, max_spawn_depth=2, max_spawns=8. add_node() adds exactly ONE
  node per call — a single dynamic decision can never batch-insert.
- Fingerprints (adapter,target,params) deduplicate DYNAMIC tasks only:
  initial-plan nodes may legitimately repeat the same substance under
  different ids (e.g. two sequential checks of one target), while two dynamic
  decisions can never spawn an equivalent task — id/origin are not part of
  the fingerprint, so renaming cannot bypass dedup.
- to_step() emits ONLY keys the existing Runner interface already supports.
"""
import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class TaskGraphError(ValueError):
    """Raised for any graph-structure or state-machine violation."""


# Exact status vocabulary already produced by runner/adapters (no new names).
NON_TERMINAL = ("PENDING", "READY", "RUNNING")
TERMINAL = (
    "COMPLETED", "FAILED", "TIMEOUT",
    "TIMEOUT_INITIALIZING", "TIMEOUT_SCANNING",
    "REFUSED", "ABORTED", "SKIPPED", "CANCELLED",
)

_TRANSITIONS: dict[str, set[str]] = {
    "PENDING": {"READY", "SKIPPED", "CANCELLED"},
    "READY": {"RUNNING", "SKIPPED", "CANCELLED"},
    # RUNNING exits only to terminal states (retry stays inside the Executor).
    "RUNNING": {
        "COMPLETED", "FAILED", "TIMEOUT",
        "TIMEOUT_INITIALIZING", "TIMEOUT_SCANNING",
        "REFUSED", "ABORTED", "CANCELLED",
    },
}

_KIND_BY_ADAPTER = {"http_probe": "probe", "nuclei": "scan", "bandit": "static_analysis"}

# Keys to_step() may emit — everything here is already understood by
# runner.run_step / issue_ticket / adapter.execute.
_STEP_KEYS = ("id", "adapter", "target", "timeout", "deps", "target_kind")


@dataclass
class TaskNode:
    id: str
    kind: str
    adapter: str
    target: str
    target_kind: str = "net"
    timeout: int = 30
    deps: tuple[str, ...] = ()
    origin: str = "initial"
    spawn_depth: int = 0
    params: dict = field(default_factory=dict)
    state: str = "PENDING"
    result: dict | None = None

    def __post_init__(self):
        if not self.id or not str(self.id).strip():
            raise TaskGraphError("TaskNode.id must be a non-empty string")
        self.deps = tuple(self.deps or ())
        # Freeze params: keep an immutable internal copy; the public property
        # hands out a fresh deep copy on every access.
        self._params: tuple[tuple[str, Any], ...] = tuple(
            (k, copy.deepcopy(v)) for k, v in (self.params or {}).items()
        )
        if self.state not in NON_TERMINAL:
            raise TaskGraphError(
                f"TaskNode must start non-terminal; got {self.state!r}"
            )

    @property
    def params_view(self) -> dict:
        return {k: copy.deepcopy(v) for k, v in self._params}

    def to_step(self) -> dict:
        """Convert to a step dict the EXISTING Runner accepts unchanged.

        Emits only runner-supported keys; params are merged at top level
        exactly like planner.build_plan() does (e.g. nuclei_ids/nuclei_tags).
        Empty deps are omitted so a plan round-trips field-for-field.
        """
        step = {
            "id": self.id,
            "adapter": self.adapter,
            "target": self.target,
            "timeout": self.timeout,
        }
        if self.deps:
            step["deps"] = list(self.deps)
        step["target_kind"] = self.target_kind
        step.update(self.params_view)
        return step


class TaskGraph:
    """DAG container with state-machine enforcement and dynamic-node budgets.

    Dependency edges are registered graph-side at add time (self._deps); the
    node's own deps tuple is an immutable snapshot, so later external mutation
    of a node cannot change routing.
    """

    def __init__(self, *, max_nodes: int = 32, max_spawn_depth: int = 2,
                 max_spawns: int = 8):
        if max_nodes < 1 or max_spawn_depth < 0 or max_spawns < 0:
            raise TaskGraphError("budgets must be non-negative (max_nodes >= 1)")
        self.max_nodes = max_nodes
        self.max_spawn_depth = max_spawn_depth
        self.max_spawns = max_spawns
        self.nodes: dict[str, TaskNode] = {}
        self._deps: dict[str, tuple[str, ...]] = {}
        self._fingerprints: set[str] = set()

    # ---- construction -----------------------------------------------------
    def add_node(self, node: TaskNode, *, dynamic: bool = False) -> None:
        """Add exactly one node. dynamic=True applies the spawn budgets
        (S3-C calls this once per decision — batching is impossible by API
        shape: there is no add_many)."""
        if not isinstance(node, TaskNode):
            raise TaskGraphError("add_node expects a TaskNode instance")
        if node.id in self.nodes:
            raise TaskGraphError(f"duplicate node id: {node.id!r}")
        if len(self.nodes) >= self.max_nodes:
            raise TaskGraphError(
                f"node budget exhausted ({self.max_nodes}); refusing {node.id!r}"
            )
        deps = tuple(node.deps)
        if node.id in deps:
            raise TaskGraphError(f"self-dependency: {node.id!r} depends on itself")
        if len(set(deps)) != len(deps):
            raise TaskGraphError(f"duplicate dependency entries in {node.id!r}")
        unknown = [d for d in deps if d not in self.nodes]
        if unknown:
            raise TaskGraphError(
                f"dependencies must reference existing nodes; {node.id!r} "
                f"references unknown: {unknown}"
            )
        if dynamic:
            if node.spawn_depth < 1:
                raise TaskGraphError(
                    "dynamic nodes must have spawn_depth >= 1 (initial nodes "
                    "belong to GraphBuilder, not spawn decisions)"
                )
            if node.spawn_depth > self.max_spawn_depth:
                raise TaskGraphError(
                    f"spawn depth {node.spawn_depth} exceeds budget "
                    f"{self.max_spawn_depth}"
                )
            spawns_used = sum(
                1 for n in self.nodes.values()
                if n.origin != "initial" or n.spawn_depth > 0
            )
            if spawns_used >= self.max_spawns:
                raise TaskGraphError(
                    f"spawn budget exhausted ({self.max_spawns}); "
                    f"refusing {node.id!r}"
                )
        fp = self.fingerprint(node.adapter, node.target, node.params_view)
        if dynamic:
            # Dynamic tasks dedupe STRICTLY on substance (adapter, target,
            # params). id/origin/spawn_depth/deps are deliberately NOT part of
            # the fingerprint — changing them cannot bypass dedup. Static
            # (initial-plan) nodes never enter the fingerprint store, so a
            # dynamic follow-up on a target already probed by the initial plan
            # is still allowed (documented P9 use case), while two dynamic
            # decisions can never spawn the same task twice.
            if fp in self._fingerprints:
                raise TaskGraphError(
                    f"duplicate dynamic task for {node.id!r} "
                    f"({node.adapter}, {node.target!r}): an equivalent dynamic "
                    f"task already exists"
                )
            self._fingerprints.add(fp)
        # Structural acyclicity assert: edges point dep -> new node only, and
        # every dep exists, so a cycle cannot exist; walk anyway (fail-closed).
        stack, seen = list(deps), set()
        while stack:
            cur = stack.pop()
            if cur == node.id:
                raise TaskGraphError(f"cycle detected through {node.id!r}")
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self._deps.get(cur, ()))
        self.nodes[node.id] = node
        self._deps[node.id] = deps

    # ---- scheduling support -------------------------------------------------
    def ready_nodes(self) -> list[TaskNode]:
        """PENDING nodes whose deps are ALL COMPLETED. Pure inspection —
        never executes anything and never mutates state."""
        out = []
        for node in self.nodes.values():
            if node.state != "PENDING":
                continue
            if all(self._dep_state(d) == "COMPLETED" for d in self._deps[node.id]):
                out.append(node)
        return out

    def _dep_state(self, dep_id: str) -> str:
        node = self.nodes.get(dep_id)
        if node is None:  # cannot happen (add_node guards); fail closed anyway
            raise TaskGraphError(f"internal: missing dep node {dep_id!r}")
        return node.state

    # ---- state machine ------------------------------------------------------
    def mark(self, node_id: str, state: str, result: dict | None = None) -> None:
        """The ONLY way to change node state. Unknown states and illegal
        transitions fail closed; terminal states are irreversible."""
        node = self.nodes.get(node_id)
        if node is None:
            raise TaskGraphError(f"unknown node: {node_id!r}")
        if state not in NON_TERMINAL and state not in TERMINAL:
            raise TaskGraphError(
                f"unknown state {state!r} (fail-closed; known: "
                f"{sorted(NON_TERMINAL + TERMINAL)})"
            )
        if node.state in TERMINAL:
            raise TaskGraphError(
                f"node {node_id!r} is terminal ({node.state}); "
                f"transitions are irreversible"
            )
        allowed = _TRANSITIONS[node.state]
        if state not in allowed:
            raise TaskGraphError(
                f"illegal transition {node.state} -> {state} for {node_id!r} "
                f"(allowed: {sorted(allowed)})"
            )
        node.state = state
        if result is not None:
            node.result = copy.deepcopy(result)

    # ---- dedup --------------------------------------------------------------
    @staticmethod
    def fingerprint(adapter: str, target: str, params: dict) -> str:
        payload = json.dumps(
            {"adapter": adapter, "target": target,
             "params": sorted((k, v) for k, v in (params or {}).items()),
             },
            sort_keys=True, ensure_ascii=False, default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # ---- export -------------------------------------------------------------
    def snapshot(self) -> dict:
        """Plain-dict deep copy of graph structure+states. Mutating the
        snapshot must never affect the graph."""
        return {
            nid: {
                "state": n.state,
                "kind": n.kind,
                "adapter": n.adapter,
                "target": n.target,
                "target_kind": n.target_kind,
                "timeout": n.timeout,
                "deps": list(self._deps[nid]),
                "origin": n.origin,
                "spawn_depth": n.spawn_depth,
                "params": n.params_view,
                "has_result": n.result is not None,
            }
            for nid, n in self.nodes.items()
        }


class GraphBuilder:
    """Converts the EXISTING planner.build_plan() output into a TaskGraph."""

    @staticmethod
    def from_plan(steps: list[dict], **graph_kwargs) -> TaskGraph:
        if steps is None or not isinstance(steps, (list, tuple)):
            raise TaskGraphError("plan must be a list of step dicts")
        graph = TaskGraph(**graph_kwargs)
        for step in steps:
            if not isinstance(step, dict):
                raise TaskGraphError(f"plan step must be a dict, got {type(step)}")
            missing = [k for k in ("id", "adapter", "target") if not step.get(k)]
            if missing:
                raise TaskGraphError(
                    f"plan step missing required field(s): {missing}"
                )
            if step["id"] in graph.nodes:
                raise TaskGraphError(f"duplicate step id in plan: {step['id']!r}")
            params = {
                k: v for k, v in step.items()
                if k not in ("id", "adapter", "target", "timeout", "deps",
                             "target_kind")
            }
            node = TaskNode(
                id=str(step["id"]),
                kind=_KIND_BY_ADAPTER.get(step["adapter"], "generic"),
                adapter=str(step["adapter"]),
                target=str(step["target"]),
                target_kind=str(step.get("target_kind", "net")),
                timeout=int(step.get("timeout", 30)),
                deps=tuple(str(d) for d in step.get("deps", ())),
                origin="initial",
                spawn_depth=0,
                params=params,
            )
            graph.add_node(node)
        return graph
