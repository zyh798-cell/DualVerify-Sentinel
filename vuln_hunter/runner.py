"""Executor: turns a plan into journaled, policy-gated real executions.

Per-step order (fail-closed):
  0. required fields present (id/adapter/target) + duplicate-id guard
  1. cancellation check (in-process flag or <evidence_dir>/CANCEL file)
  2. dependencies COMPLETED?               -> else SKIPPED
  3. window re-check                       -> else ABORTED
  4. dependency quarantined (e.g. 429)?    -> else SKIPPED
  5. adapter risk <= mode ceiling?         -> else REFUSED
  6. target inside scope?                  -> else REFUSED
  7. adapter preflight                     -> else SKIPPED
  8. attempt loop: max 2 attempts, backoff 5s (10s after TIMEOUT),
     HTTP 429 -> no retry + quarantine. Unexpected adapter exceptions are
     bounded-recovered into an honest FAILED attempt; JOURNAL failures
     (integrity/write) are NOT masked — they propagate as audit failures.
     Timeout cleanup (D2-D-1-F1): on Windows the adapter runs taskkill /T /F
     + root kill + bounded wait and records every outcome in
     AdapterResult.meta["cleanup"] (see adapters.NucleiAdapter._run);
     tree_kill_status=SUCCESS only means taskkill returned 0, it is NOT
     proof that the whole process tree was confirmed cleaned.
"""
import time
from pathlib import Path

from .adapters import AdapterResult, GateRequired, get_adapter
from .journal import utcnow
from .policy import PolicyRefusal

STATUS_PRIORITY = [  # worst first; run summary = worst status present
    "REFUSED",
    "ABORTED",
    "CANCELLED",
    "FAILED",
    "TIMEOUT",
    "SKIPPED",
    "COMPLETED",
]


def _summary_bucket(status: str) -> str:
    """Map a step status onto summary buckets. TIMEOUT_* subclasses count as
    TIMEOUT; ANY unrecognized status is treated as FAILED (fail-closed) so a
    new status can never silently degrade a run summary to success."""
    if status in STATUS_PRIORITY:
        return status
    if status.startswith("TIMEOUT"):
        return "TIMEOUT"
    return "FAILED"


class Executor:
    def __init__(self, policy, journal, evidence_dir, sleep_fn=time.sleep,
                 max_attempts=2, synthetic_run: bool = False):
        self.policy = policy
        self.journal = journal
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.sleep_fn = sleep_fn
        self.max_attempts = max_attempts
        # D2-C0 (R3): when the operator declares a run synthetic/lab, every
        # finding of the run is explicitly marked so reports can exclude it
        # from real-vulnerability counts. Default False keeps the exact
        # pre-R3 behaviour (explicit per-finding markers still honoured).
        self.synthetic_run = synthetic_run
        self.results: dict[str, dict] = {}
        self._cancel_flag = False

    # ---- cancellation ----------------------------------------------------
    def cancel(self):
        self._cancel_flag = True

    def _cancelled(self) -> bool:
        if self._cancel_flag:
            return True
        if (self.evidence_dir / "CANCEL").exists():
            self._cancel_flag = True
        return self._cancel_flag

    # ---- single step -------------------------------------------------------
    def run_step(self, step: dict) -> dict:
        if not isinstance(step, dict):
            step = {}
        step_id = step.get("id")
        # 0a. required fields: a malformed step must produce a tracked FAILED
        # record (journaled + in results), never an untracked crash.
        missing = [k for k in ("id", "adapter", "target") if not step.get(k)]
        if missing:
            sid = str(step_id) if step_id else "<unnamed>"
            rec = {
                "id": sid,
                "adapter": str(step.get("adapter") or "<missing>"),
                "target": step.get("target"),
                "status": "FAILED",
                "reason": f"malformed step: missing or empty field(s): {', '.join(missing)}",
                "attempts": 0,
            }
            self.journal.append("step_start", **rec)
            self.results[sid] = rec
            self.journal.append("step_end", **rec)
            return rec
        step_id = str(step_id)
        # 0b. idempotency guard: a step id runs at most once per Executor —
        # re-invocation never re-executes the tool or double-books results.
        if step_id in self.results:
            self.journal.append("step_skipped_duplicate", step=step_id)
            return dict(self.results[step_id])
        try:
            adapter = get_adapter(step["adapter"], self.policy)
        except GateRequired as exc:
            rec = {
                "id": step_id, "adapter": step["adapter"],
                "target": step.get("target"), "status": "REFUSED",
                "reason": f"gate: {exc}",
            }
            self.journal.append("step_start", **rec)
            self.results[step_id] = rec
            self.journal.append("step_end", **rec)
            return rec
        except KeyError as exc:
            rec = {
                "id": step_id, "adapter": step["adapter"],
                "target": step.get("target"), "status": "FAILED",
                "reason": f"unknown adapter: {exc}",
            }
            self.journal.append("step_start", **rec)
            self.results[step_id] = rec
            self.journal.append("step_end", **rec)
            return rec
        rec = {
            "id": step_id,
            "adapter": step["adapter"],
            "adapter_risk": adapter.risk,
            "target": step["target"],
            "status": "PLANNED",
        }
        self.journal.append("step_start", **rec)
        # Register BEFORE the attempt loop: even if the adapter raises an
        # unexpected exception, the step stays tracked in results and its
        # step_end is still journaled (no dangling audit state).
        self.results[step_id] = rec

        if self._cancelled():
            rec["status"] = "CANCELLED"
            rec["reason"] = "cancellation requested"
        else:
            bad_deps = [
                d
                for d in step.get("deps", [])
                if self.results.get(d, {}).get("status") != "COMPLETED"
            ]
            if bad_deps:
                rec["status"] = "SKIPPED"
                rec["reason"] = f"dependencies not COMPLETED: {bad_deps}"
            else:
                if any(self.results.get(d, {}).get("quarantined") for d in step.get("deps", [])):
                    rec["status"] = "SKIPPED"
                    rec["reason"] = "dependency quarantined (e.g. HTTP 429)"
                else:
                    werr = self.policy.window_ok()
                    if werr:
                        rec["status"] = "ABORTED"
                        rec["reason"] = f"authorization window: {werr}"
                    else:
                        aerr = self.policy.adapter_allowed(adapter.risk)
                        if aerr:
                            rec["status"] = "REFUSED"
                            rec["reason"] = aerr
                        else:
                            # Network targets must be inside scope; filesystem
                            # targets (e.g. bandit source dirs) are local
                            # read-only paths and skip only THIS check.
                            if step.get("target_kind", "net") == "net":
                                terr = self.policy.target_allowed(step["target"])
                                if terr:
                                    rec["status"] = "REFUSED"
                                    rec["reason"] = terr
                                else:
                                    perr = adapter.preflight()
                                    if perr:
                                        rec["status"] = "SKIPPED"
                                        rec["reason"] = f"preflight: {perr}"
                                    else:
                                        rec.update(self._attempt_loop(step, adapter))
                            else:
                                perr = adapter.preflight()
                                if perr:
                                    rec["status"] = "SKIPPED"
                                    rec["reason"] = f"preflight: {perr}"
                                else:
                                    rec.update(self._attempt_loop(step, adapter))

        self.journal.append("step_end", **rec)
        return rec

    def _attempt_loop(self, step: dict, adapter) -> dict:
        rec: dict = {"status": "FAILED", "attempts": 0}
        last: dict = {}
        while rec["attempts"] < self.max_attempts:
            if self._cancelled():
                rec["status"] = "CANCELLED"
                rec["reason"] = "cancellation requested mid-step"
                break
            rec["attempts"] += 1
            n = rec["attempts"]
            log_path = self.evidence_dir / f"{step['id']}-attempt{n}.log"
            self.journal.append(
                "attempt_start", step=step["id"], attempt=n, log=str(log_path)
            )
            with open(log_path, "w", encoding="utf-8") as log:
                try:
                    # A FRESH ticket per attempt: target/window/scope-hash are
                    # re-verified at issuance AND again inside adapter.execute.
                    ticket = self.policy.issue_ticket(
                        step["target"], adapter.id,
                        target_kind=step.get("target_kind", "net"),
                    )
                except PolicyRefusal as exc:
                    log.write(f"[gate] ticket refused: {exc}\n")
                    rec["status"] = "REFUSED"
                    rec["reason"] = f"ticket: {exc}"
                    self.journal.append(
                        "attempt_end", step=step["id"], attempt=n,
                        status="REFUSED", ok=False, detail=rec["reason"], meta={},
                    )
                    return rec
                except Exception as exc:  # noqa: BLE001 - fail-closed on any gate error
                    log.write(f"[gate] ticket error: {exc.__class__.__name__}: {exc}\n")
                    rec["status"] = "REFUSED"
                    rec["reason"] = f"ticket error: {exc.__class__.__name__}"
                    self.journal.append(
                        "attempt_end", step=step["id"], attempt=n,
                        status="REFUSED", ok=False, detail=rec["reason"], meta={},
                    )
                    return rec
                res = None
                try:
                    res = adapter.execute(
                        ticket, policy=self.policy,
                        timeout=step.get("timeout", 30), log=log, step=step,
                    )
                except Exception as exc:  # noqa: BLE001 - bounded recovery:
                    # an unexpected adapter/gate crash becomes an honest FAILED
                    # attempt (never retried into a fake success). This does
                    # NOT cover journal failures — those propagate below as
                    # audit failures and are never masked as step results.
                    log.write(f"[adapter-error] {exc.__class__.__name__}: {exc}\n")
                    res = AdapterResult(
                        "FAILED", False,
                        f"adapter error: {exc.__class__.__name__}: {str(exc)[:200]}",
                    )
            journal_meta = res.meta if res.meta else {}
            self.journal.append(
                "attempt_end",
                step=step["id"],
                attempt=n,
                status=res.status,
                ok=res.ok,
                detail=res.detail,
                meta=journal_meta,
            )
            last = {
                "status": res.status,
                "detail": res.detail,
                "findings": res.findings,
                "quarantined": res.quarantine,
            }
            if res.status == "COMPLETED" or res.no_retry:
                break
            if rec["attempts"] < self.max_attempts:
                self.sleep_fn(10 if res.status.startswith("TIMEOUT") else 5)
        rec["status"] = last.get("status", rec["status"])
        rec["detail"] = last.get("detail", "")
        rec["findings"] = last.get("findings", [])
        rec["quarantined"] = last.get("quarantined", False)
        if self.synthetic_run:
            # D2-C0 (R3): structural synthetic marking at the source. The
            # field travels with the finding into journal step_end records
            # and the final report; setdefault keeps any pre-existing value.
            for f in rec["findings"]:
                if isinstance(f, dict):
                    f.setdefault("synthetic", True)
        return rec

    # ---- whole plan ---------------------------------------------------------
    def run_plan(self, plan: list[dict]) -> None:
        self.journal.append("plan_start", steps=[s["id"] for s in plan])
        for step in plan:
            self.run_step(step)
        self.journal.append("plan_end", summary=self.summary_status())

    def summary_status(self) -> str:
        buckets = [_summary_bucket(r["status"]) for r in self.results.values()]
        if not buckets:
            return "PLANNED"
        for s in STATUS_PRIORITY:
            if s in buckets:
                return s
        return buckets[0]

    def findings(self) -> list[dict]:
        out = []
        for rec in self.results.values():
            for f in rec.get("findings", []):
                out.append({"step": rec["id"], **f})
        return out
