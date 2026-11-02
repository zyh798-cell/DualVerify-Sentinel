"""P9-V rule layer: dynamic focused re-validation from REAL nuclei evidence.

P9 is OFF by default. The loop only calls evaluate_p9() when the operator
explicitly enables it (CLI --p9 / AutonomousLoop(enable_p9=True)); disabling
P9 never changes static-plan behaviour.

This module is PURE RULES: it never journals, never executes tools, never
touches tickets. It returns (journal_events, child_node_or_None); the CALLER
(loop.py) journals the events in order and — if a child was produced — adds
it via graph.add_node(child, dynamic=True). TaskGraph.add_node remains the
ONLY authoritative enforcement point for budgets/fingerprints/structure; the
checks below are pre-flight optimizations that produce readable audit events
and avoid guaranteed-to-fail add_node calls.

Trigger contract (all mandatory, fail-closed):
- parent record status EXACTLY "COMPLETED" (FAILED/TIMEOUT_*/REFUSED/ABORTED/
  SKIPPED/CANCELLED never trigger — notably nuclei FAILED may still carry
  partial findings; the status gate is the only defense against them);
- not quarantined;
- findings: non-empty list, every element a dict with type EXACTLY
  "nuclei_finding" and a syntactically valid non-empty template id (any
  malformed element invalidates the WHOLE record — unreliable evidence never
  spawns tasks);
- not in degraded mode (checked by the caller);
- child risk (R2) must not exceed the parent's ACTUAL executed risk
  (rec["adapter_risk"]) nor the current mode ceiling;
- child target is parent.target VERBATIM — finding["host"]/["matched_at"]
  are NEVER used (they may reflect redirects/resolution outside scope);
- child timeout = min(parent.timeout, P9_MAX_TIMEOUT); invalid parent
  budgets reject generation;
- scope re-check via the EXISTING policy.target_allowed() before spawning;
- at most ONE child per P9 decision; a template already covered by an
  equivalent graph node (static or dynamic) is skipped, so a template can
  never be generated twice and the chain self-terminates.
"""
import re

from .adapters import adapter_risk
from .policy import RISK_ORDER
from .taskgraph import TaskNode

P9_ORIGIN = "p9"
# Matches the planner's independent nuclei budget (planner.build_plan default
# cap for the nuclei step); a child can never exceed it or the parent budget.
P9_MAX_TIMEOUT = 240

# Nuclei template ids: alnum start, then alnum/dot/underscore/hyphen. Also
# keeps the generated child id safe (no whitespace, separators or shell-ish
# characters can leak into "f{parent.id}-p9v-{template}").
_TEMPLATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _valid_template(value) -> bool:
    """Non-empty, already-clean string matching the template-id shape."""
    return (
        isinstance(value, str)
        and value == value.strip()
        and value != ""
        and bool(_TEMPLATE_RE.match(value))
    )


def _valid_timeout(value) -> bool:
    """Positive real int (bool is an int subclass — exclude it explicitly)."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


def _equivalent_exists(graph, target: str, template: str) -> bool:
    """True when ANY existing node (static OR dynamic) already runs this
    exact focused re-validation (same adapter/target/single template).
    Covers both 'static plan already contains it' and 'a previous dynamic
    decision already spawned it' — so the same template is never generated
    twice and dynamically spawned children cannot loop on their own
    evidence."""
    for n in graph.nodes.values():
        if n.adapter != "nuclei" or n.target != target:
            continue
        ids = n.params_view.get("nuclei_ids")
        if isinstance(ids, list) and [str(i) for i in ids] == [template]:
            return True
    return False


def _spawns_used(graph) -> int:
    """Mirror of TaskGraph.add_node's own spawn counter (pre-flight only)."""
    return sum(
        1 for n in graph.nodes.values()
        if n.origin != "initial" or n.spawn_depth > 0
    )


def evaluate_p9(graph, parent, rec: dict, policy) -> tuple[list, TaskNode | None]:
    """Evaluate P9-V for one just-completed step record.

    Returns (events, child):
      events — ordered (event_name, fields) pairs for the caller to journal;
      child  — a TaskNode to add via graph.add_node(child, dynamic=True),
               or None when nothing may be generated (rejection reason is
               always present in events).
    """
    events: list[tuple[str, dict]] = []

    def ev(name: str, **fields) -> None:
        events.append((name, fields))

    ev("p9_decision_start", parent=parent.id, budgets={
        "nodes": len(graph.nodes), "max_nodes": graph.max_nodes,
        "spawns_used": _spawns_used(graph), "max_spawns": graph.max_spawns,
        "depth": parent.spawn_depth, "max_spawn_depth": graph.max_spawn_depth,
    })

    # T1 — only COMPLETED evidence can trigger. This is the single defense
    # against nuclei FAILED-with-partial-findings (adapters.py returns
    # findings alongside non-zero exits; those records are NOT reliable).
    status = rec.get("status")
    if status != "COMPLETED":
        ev("p9_skip", parent=parent.id,
           reason=f"parent status {status!r} is not COMPLETED")
        return events, None

    # T3 — quarantined evidence (e.g. HTTP 429) is unreliable.
    if rec.get("quarantined"):
        ev("p9_skip", parent=parent.id,
           reason="parent quarantined (e.g. HTTP 429); evidence unreliable")
        return events, None

    # T4/T5 — structural evidence validation. ANY malformed element
    # invalidates the whole record (fail-closed).
    findings = rec.get("findings")
    if not isinstance(findings, list):
        ev("p9_evidence_invalid", parent=parent.id,
           reason=f"findings must be a list, got {type(findings).__name__}")
        return events, None
    if not findings:
        ev("p9_evidence_invalid", parent=parent.id,
           reason="findings is empty — no reliable evidence to act on")
        return events, None
    for f in findings:
        if not isinstance(f, dict):
            ev("p9_evidence_invalid", parent=parent.id,
               reason=f"finding element is {type(f).__name__}, expected dict")
            return events, None
        if f.get("type") != "nuclei_finding":
            ev("p9_evidence_invalid", parent=parent.id,
               reason=f"finding type {f.get('type')!r} is not 'nuclei_finding'")
            return events, None
        if not _valid_template(f.get("template")):
            ev("p9_evidence_invalid", parent=parent.id,
               reason=f"finding template {f.get('template')!r} is not a "
                      f"valid non-empty template id")
            return events, None

    # Pick the FIRST valid template not already covered by an equivalent
    # graph node (one child per decision; duplicates never generated).
    template = None
    for f in findings:
        cand = f["template"]
        if not _equivalent_exists(graph, parent.target, cand):
            template = cand
            break
    if template is None:
        ev("p9_evidence_invalid", parent=parent.id,
           reason="all qualifying templates already covered by an "
                  "equivalent graph node; nothing new to generate")
        return events, None

    ev("p9_trigger", parent=parent.id, template=template,
       severity=findings[0].get("severity"), findings_count=len(findings))

    # ---- pre-flight checks (add_node stays authoritative) ------------------
    checks: dict = {"parent": parent.id, "template": template}
    reasons: list[str] = []

    # Risk: child (R2) vs parent's ACTUAL executed risk.
    parent_risk = rec.get("adapter_risk") or adapter_risk(parent.adapter)
    child_risk = adapter_risk("nuclei")
    risk_ok = RISK_ORDER.get(child_risk, 4) <= RISK_ORDER.get(parent_risk, 4)
    checks.update(parent_risk=parent_risk, child_risk=child_risk,
                  risk_ok=risk_ok)
    if not risk_ok:
        reasons.append(f"child risk {child_risk} exceeds parent executed "
                       f"risk {parent_risk}")

    # Mode ceiling via the EXISTING policy API.
    ceiling_err = policy.adapter_allowed(child_risk)
    checks["ceiling_ok"] = ceiling_err is None
    if ceiling_err:
        reasons.append(ceiling_err)

    # Scope re-check on the verbatim inherited target (net kind for P9-V).
    scope_err = policy.target_allowed(parent.target)
    checks["scope_ok"] = scope_err is None
    if scope_err:
        reasons.append(scope_err)

    # Timeout budget: inherit, capped; invalid budgets reject.
    timeout_ok = _valid_timeout(parent.timeout)
    child_timeout = min(parent.timeout, P9_MAX_TIMEOUT) if timeout_ok else None
    checks.update(parent_timeout=parent.timeout,
                  child_timeout=child_timeout, timeout_ok=timeout_ok)
    if not timeout_ok:
        reasons.append(f"invalid parent timeout budget: {parent.timeout!r}")

    checks["ok"] = not reasons
    ev("p9_checks", **checks)
    if reasons:
        ev("p9_spawn_rejected", parent=parent.id, template=template,
           reason="; ".join(reasons))
        return events, None

    # ---- construct the single P9-V child -----------------------------------
    child = TaskNode(
        id=f"{parent.id}-p9v-{template}",
        kind="scan",
        adapter="nuclei",
        target=parent.target,  # VERBATIM — never finding host/matched_at
        target_kind="net",
        timeout=child_timeout,
        deps=(parent.id,),
        origin=P9_ORIGIN,
        spawn_depth=parent.spawn_depth + 1,
        params={"nuclei_ids": [template], "nuclei_tags": []},
    )
    return events, child
