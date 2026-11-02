"""S2 hardening tests: exception-path convergence, report<->journal anchor
linkage, ticket.mode consistency.

Run:  python tests/test_s2_hardening.py
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# make gate subprocess imports work regardless of cwd
os.environ["PYTHONPATH"] = str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")

from vuln_hunter import __main__ as cli  # noqa: E402
from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter  # noqa: E402
from vuln_hunter.journal import (  # noqa: E402
    EvidenceJournal, JournalIntegrityError, audit_status, verify,
)
from vuln_hunter.policy import PolicyEngine, RunTicket  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402

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
    d = {"client": "s2-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "s2-test"}
    d.update(kw)
    return d


class OkAdapter(ToolAdapter):
    id, risk = "s2_ok", "R1"
    calls = 0

    def _run(self, target, timeout, log, step=None):
        OkAdapter.calls += 1
        return AdapterResult("COMPLETED", True, "ok")


class ExplodingAdapter(ToolAdapter):
    id, risk = "s2_boom", "R1"

    def _run(self, target, timeout, log, step=None):
        raise RuntimeError("boom (simulated adapter crash)")


register_adapter(OkAdapter)
register_adapter(ExplodingAdapter)


def mkexec(scope=None, mode="safe_scan", journal=None):
    tmp = Path(tempfile.mkdtemp())
    j = journal or EvidenceJournal(tmp / "j.jsonl")
    return Executor(PolicyEngine(scope or base_scope(), mode), j, tmp / "ev",
                    sleep_fn=lambda s: None), j


def journal_events(jpath: Path) -> list[str]:
    return [json.loads(l)["rec"]["event"]
            for l in Path(jpath).read_text(encoding="utf-8").splitlines()
            if l.strip()]


with tempfile.TemporaryDirectory() as td:

    # ---- S2-01/02/03 malformed steps: tracked FAILED, no crash ------------
    for case, bad_step, note in [
        ("S2-01", {"adapter": "s2_ok", "target": "127.0.0.1"}, "missing id"),
        ("S2-02", {"id": "x", "target": "127.0.0.1"}, "missing adapter"),
        ("S2-03", {"id": "y", "adapter": "s2_ok"}, "missing target"),
        ("S2-03b", None, "step is not a dict"),
    ]:
        ex, j = mkexec()
        rec = ex.run_step(bad_step)
        evs = journal_events(j.path)
        ok = (rec["status"] == "FAILED"
              and "malformed step" in rec.get("reason", "")
              and "step_start" in evs and "step_end" in evs
              and rec["id"] in ex.results)
        check(case, ok, f"{note} -> FAILED tracked + journaled (no crash)")

    # ---- S2-04 adapter crash: bounded FAILED, full audit trail ------------
    ex, j = mkexec()
    rec = ex.run_step({"id": "boom1", "adapter": "s2_boom",
                       "target": "127.0.0.1", "timeout": 5})
    evs = journal_events(j.path)
    check("S2-04", rec["status"] == "FAILED"
          and "adapter error" in rec.get("detail", "")
          and "RuntimeError" in rec.get("detail", "")
          and evs.count("attempt_end") == 2 and "step_end" in evs
          and ex.results["boom1"]["status"] == "FAILED",
          "adapter crash -> FAILED step (retried to max_attempts), "
          "attempt_end x2 + step_end journaled, no crash")

    # ---- S2-05 duplicate step id never re-executes ------------------------
    ex, j = mkexec()
    OkAdapter.calls = 0
    r1 = ex.run_step({"id": "dup", "adapter": "s2_ok", "target": "127.0.0.1", "timeout": 5})
    r2 = ex.run_step({"id": "dup", "adapter": "s2_ok", "target": "127.0.0.1", "timeout": 5})
    check("S2-05", OkAdapter.calls == 1 and r1["status"] == "COMPLETED"
          and r2["status"] == "COMPLETED"
          and "step_skipped_duplicate" in journal_events(j.path),
          f"second run_step with same id returned without executing (calls={OkAdapter.calls})")

    # ---- S2-06 journal write failure propagates (never masked) ------------
    tmp = Path(tempfile.mkdtemp())
    real = EvidenceJournal(tmp / "j.jsonl")

    class AuditFailJournal:
        """Fails exactly when the audit trail must record attempt_end."""
        def __init__(self):
            self.path = real.path
            self.count = 0

        def append(self, event, **fields):
            self.count += 1
            if event == "attempt_end":
                raise OSError("disk full while writing audit record")
            return real.append(event, **fields)

    ex = Executor(PolicyEngine(base_scope(), "safe_scan"), AuditFailJournal(),
                  tmp / "ev", sleep_fn=lambda s: None)
    raised = False
    try:
        ex.run_step({"id": "af1", "adapter": "s2_ok", "target": "127.0.0.1", "timeout": 5})
    except OSError as exc:
        raised = "disk full" in str(exc)
    evs = journal_events(real.path)
    check("S2-06", raised and "step_end" not in evs and "attempt_end" not in evs,
          "audit write failure -> OSError propagates, step NOT marked finished "
          "(no fake success, no fake FAILED)")

    # ---- S2-07 CLI audit failure -> exit 3 --------------------------------
    orig = cli.EvidenceJournal

    class DeadJournal:
        def __init__(self, *a, **k):
            pass

        def append(self, *a, **k):
            raise OSError("audit sink unavailable")

    cli.EvidenceJournal = DeadJournal
    scope_file = Path(td) / "scope.json"
    scope_file.write_text(json.dumps(base_scope()), encoding="utf-8")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = cli.main(["run", "--scope", str(scope_file), "--mode", "safe_scan",
                         "--target", "127.0.0.1:9"])
    cli.EvidenceJournal = orig
    check("S2-07", code == 3 and "AUDIT FAILURE" in err.getvalue(),
          f"unwritable journal -> main() exit {code} with AUDIT FAILURE banner")

    # ---- S2-08/09 ticket.mode consistency ---------------------------------
    shared = base_scope()
    p_safe = PolicyEngine(shared, "safe_scan")
    p_vuln = PolicyEngine(shared, "vuln_validation")
    t = p_safe.issue_ticket("127.0.0.1:8080", "http_probe")
    from vuln_hunter.adapters import HTTPProbeAdapter
    probe = HTTPProbeAdapter()
    r = probe.execute(t, policy=p_vuln, timeout=5, log=io.StringIO())
    check("S2-08", r.status == "REFUSED" and "does not match policy mode" in r.detail,
          f"safe_scan ticket under vuln_validation policy -> {r.status}")

    forged = RunTicket.__new__(RunTicket)
    for k, v in {"target": "127.0.0.1:8080", "adapter_id": "http_probe",
                 "mode": "", "scope_sha256": p_safe.scope_sha256(),
                 "issued_at": "now", "window_end": None,
                 "target_kind": "net", "_token": "dvs-run-ticket-v1"}.items():
        object.__setattr__(forged, k, v)
    r = probe.execute(forged, policy=p_safe, timeout=5, log=io.StringIO())
    check("S2-09", r.status == "REFUSED" and "mode" in r.detail,
          f"ticket with empty/missing mode -> {r.status}")

    t_ok = p_safe.issue_ticket("127.0.0.1:9", "http_probe")
    r = probe.execute(t_ok, policy=p_safe, timeout=5, log=io.StringIO())
    check("S2-10", r.status in ("COMPLETED", "FAILED"),
          f"mode-consistent ticket still passes gate (status={r.status})")

    # ---- S2-11..14 report <-> journal anchor linkage (end-to-end) ---------
    workdir = Path(tempfile.mkdtemp())
    old_cwd = os.getcwd()
    os.chdir(workdir)
    try:
        evdir = workdir / "ev-main"
        code = cli.main(["run", "--scope", str(scope_file), "--mode", "safe_scan",
                         "--target", "127.0.0.1:9", "--evidence-dir", str(evdir)])
        jpath = evdir / "journal.jsonl"
        report_text = (evdir / "report.md").read_text(encoding="utf-8")
        m_head = re.search(r"链头摘要: `([0-9a-f]{64})`", report_text)
        m_count = re.search(r"记录数（截至锚点）: (\d+)", report_text)
        recs = [json.loads(l) for l in jpath.read_text(encoding="utf-8").splitlines() if l.strip()]
        ok, _, _ = verify(jpath)
        anchor_ok = (m_head and m_count
                     and recs[-1]["rec"]["event"] == "report_written"
                     and recs[-1]["rec"]["anchor"] == m_head.group(1)
                     and recs[-1]["rec"]["anchor_records"] == int(m_count.group(1))
                     and len(recs) == int(m_count.group(1)) + 1
                     and recs[-2]["h"] == m_head.group(1)
                     and recs[-2]["rec"]["event"] == "run_end"
                     and ok)
        check("S2-11", code in (0, 1, 2) and anchor_ok,
              f"report anchor == head at run_end, exactly one report_written after "
              f"(exit={code})")

        # report declares its boundaries
        check("S2-12", "仅用于**一致性核对**" in report_text
              and "不能单独证明日志未被整体重写或截断" in report_text,
              "report states anchor is consistency-only (honest boundary)")

        # ---- S2-13 tampered journal -> audit_status catches, anchor drifts
        lines = jpath.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[1])
        rec["rec"]["event"] = "FORGED_EVENT"
        lines[1] = json.dumps(rec, ensure_ascii=False)
        jpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
        st = audit_status(jpath)
        check("S2-13", st["ok"] is False and "FORGED" not in st["detail"],
              f"tampered journal: audit_status.ok=False ({st['detail'][:50]})")

        # ---- S2-14 truncated journal: verify(prefix) ok but anchor mismatch
        jpath2 = workdir / "j2.jsonl"
        jj = EvidenceJournal(jpath2)
        for i in range(4):
            jj.append("e", n=i)
        anchor_before = jj.head()
        all_lines = [l for l in jpath2.read_text(encoding="utf-8").splitlines() if l.strip()]
        jpath2.write_text("\n".join(all_lines[:2]) + "\n", encoding="utf-8")
        st2 = audit_status(jpath2)
        check("S2-14", st2["ok"] is True and st2["head"] != anchor_before
              and st2["count"] == 2,
              "truncation: in-chain verify still ok, external anchor detects drift")

        # ---- S2-15 audit verify failure at run_end -> exit 3 ----------------
        # (higher exit priority than tool/policy outcomes; report keeps the
        # real result; existing JournalIntegrityError/OSError exit-3 paths
        # are S2-06/07 and remain untouched)
        workdir2 = Path(tempfile.mkdtemp())
        os.chdir(workdir2)
        try:
            # main() imports audit_status from the journal module at call
            # time, so patching the module attribute is the correct seam.
            import vuln_hunter.journal as vj
            orig_audit = vj.audit_status
            vj.audit_status = lambda p: {"ok": False,
                                         "detail": "simulated verify failure",
                                         "head": None, "count": 0}
            evdir2 = workdir2 / "ev-auditfail"
            err2 = io.StringIO()
            with contextlib.redirect_stderr(err2):
                code2 = cli.main(["run", "--scope", str(scope_file),
                                  "--mode", "safe_scan", "--target", "127.0.0.1:9",
                                  "--evidence-dir", str(evdir2)])
            vj.audit_status = orig_audit
            report2 = (evdir2 / "report.md").read_text(encoding="utf-8")
            check("S2-15", code2 == 3 and "AUDIT FAILURE" in err2.getvalue()
                  and "NOT integrity-certified" in err2.getvalue()
                  and "FAILED" in report2,
                  f"audit verify failure overrides exit code -> {code2}, "
                  f"real run result still in report")
        finally:
            os.chdir(old_cwd)
    finally:
        os.chdir(old_cwd)

print("-" * 78)
total = 15
print(f"S2 HARDENING TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
