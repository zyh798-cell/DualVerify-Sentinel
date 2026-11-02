"""Rule-based decision engine (NOT model-driven — honestly labeled).

Every decision is a pure function of (policy, execution results, remaining
plan, budget). Rules are ordered and transparent; each decision record
captures its input evidence, policy verdicts, chosen action and reason so the
whole trajectory is auditable in the journal.

This is explicitly NOT LLM autonomous decision-making. See DELIVERY notes:
model-driven planning is marked UNIMPLEMENTED.
"""
from .adapters import adapter_risk
from .journal import utcnow
from .policy import RISK_ORDER

ACTIONS = ("RUN_NEXT", "DEGRADE", "STOP", "ASK_CONFIRM")


class DecisionEngine:
    def __init__(self, max_steps: int = 6):
        self.max_steps = max_steps

    def decide(self, policy, results: dict, pending: list[dict],
               executed_count: int, degraded: bool = False) -> dict:
        d = {
            "ts": utcnow(),
            "input": {
                "executed_steps": executed_count,
                "max_steps": self.max_steps,
                "pending": [s["id"] for s in pending],
                "last_step": _last_summary(results),
            },
            "policy_verdict": {
                "mode": policy.mode,
                "risk_ceiling": policy.risk,
                "window_ok": policy.window_ok() is None,
                "window_error": policy.window_ok(),
                "ack_ok": policy.ack_error() is None,
            },
        }

        # P0 — authorization/policy pre-checks: never run anything if broken.
        if not d["policy_verdict"]["window_ok"]:
            return _fin(d, "STOP", "authorization window invalid/not open", "authorization_window")
        if not d["policy_verdict"]["ack_ok"]:
            return _fin(d, "STOP", policy.ack_error(), "risk_acknowledgement")

        # P1 — any policy refusal or abort is terminal. Never expand scope.
        for sid, r in results.items():
            if r.get("status") in ("REFUSED", "ABORTED"):
                return _fin(
                    d, "STOP",
                    f"step {sid} {r['status']}: {r.get('reason', '')}",
                    "policy_refusal_or_abort",
                )

        # P2 — 429 quarantine: stop per backoff policy (no retry beyond).
        for sid, r in results.items():
            if r.get("quarantined"):
                return _fin(d, "STOP", f"step {sid} quarantined (e.g. HTTP 429)", "rate_limit_stop")

        # P3 — unrecoverable failure: do NOT proceed on bad evidence, do NOT
        # expand targets. (Executor already exhausted its retry budget.)
        last = _last_record(results)
        if last and last.get("status") == "CANCELLED":
            return _fin(d, "STOP", f"step {last['id']} cancelled; halt without further actions", "cancelled")
        if last and last.get("status") == "FAILED":
            return _fin(
                d, "STOP",
                f"step {last['id']} FAILED after retries: {last.get('detail', '')}",
                "unreliable_result_stop",
            )

        # P4 — timeout (any TIMEOUT_* subclass): degrade to static-only if a
        # fallback remains.
        if last and str(last.get("status", "")).startswith("TIMEOUT"):
            static_pending = [s for s in pending
                              if RISK_ORDER[adapter_risk(s["adapter"])] <= 1]
            if degraded:
                if static_pending:
                    return _fin(d, "RUN_NEXT",
                                f"degraded mode; continue with static step {static_pending[0]['id']}",
                                static_pending[0]["id"])
                return _fin(d, "STOP", "already degraded and no static steps left", "timeout_no_fallback")
            if static_pending:
                return _fin(
                    d, "DEGRADE",
                    f"dynamic step {last['id']} timed out; degrade to static-only per backoff policy",
                    "timeout_degrade",
                )
            return _fin(d, "STOP", f"step {last['id']} timed out, no static fallback", "timeout_no_fallback")

        # P5 — probe gave no service evidence: cannot judge reliably.
        probes = [r for r in results.values() if r.get("adapter") == "http_probe"
                  and r.get("status") == "COMPLETED"]
        if probes and not any(r.get("findings") for r in probes):
            return _fin(d, "ASK_CONFIRM", "probe completed but produced no service evidence",
                        "cannot_reliably_judge")

        # P6 — nothing pending: done.
        if not pending:
            return _fin(d, "STOP", "no pending steps remain", "plan_exhausted")

        # P7 — step budget.
        if executed_count >= self.max_steps:
            return _fin(d, "STOP", f"step budget exhausted ({self.max_steps})", "budget_exhausted")

        # P8 — proceed with the next pending step (executor still enforces
        # every policy check at the execution boundary).
        nxt = pending[0]
        return _fin(d, "RUN_NEXT", f"prior steps healthy; proceed to {nxt['id']}", nxt["id"])


def _last_record(results: dict) -> dict | None:
    """Completion-order last record (results dict is insertion-ordered)."""
    return list(results.values())[-1] if results else None


def _last_summary(results: dict) -> dict | None:
    r = _last_record(results)
    if not r:
        return None
    return {
        "id": r.get("id"),
        "status": r.get("status"),
        "attempts": r.get("attempts"),
        "quarantined": r.get("quarantined", False),
        "findings_count": len(r.get("findings") or []),
    }


def _fin(d: dict, action: str, reason: str, nxt) -> dict:
    d["action"] = action
    d["reason"] = reason
    d["next"] = nxt
    d["confirmation_required"] = action == "ASK_CONFIRM"
    return d
