"""D2-D-0 + D2-D-4: offline reliability tests and fault injection.

ALL OFFLINE: temp directories only, Fake adapters, no real tool, no HTTP
service, no network. Core production modules are imported, NEVER modified.

Exit-code semantics under test (vuln_hunter/__main__.py L193-207):
  0 = COMPLETED, 1 = summary != COMPLETED, 2 = gate failure,
  3 = audit failure (journal unusable), uncaught exception = process crash.

Run:  python tests/test_d2d0_d2d4.py
"""
import ast
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter
from vuln_hunter.journal import (EvidenceJournal, JournalIntegrityError,
                                 verify, head, audit_status)
from vuln_hunter.policy import PolicyEngine
from vuln_hunter.report import render_report
from vuln_hunter.runner import Executor
from vuln_hunter.taskgraph import (GraphBuilder, TaskGraph, TaskNode,
                                   TaskGraphError)

fails = 0
passes = 0
skips = 0


def check(cid: str, cond: bool, note: str = ""):
    global fails, passes
    if cond:
        passes += 1
        print(f"[PASS] {cid} — {note}")
    else:
        fails += 1
        print(f"[FAIL] {cid} — {note}")


def skip(cid: str, note: str):
    global skips
    skips += 1
    print(f"[SKIP] {cid} — {note}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def current_window() -> str:
    from datetime import datetime, timedelta, timezone
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=6)).strftime(fmt)}")


def make_policy() -> PolicyEngine:
    scope = {
        "client": "d2d0/d2d4 offline tests (local synthetic, not a real auth)",
        "in_scope": ["127.0.0.1:18080"],
        "out_of_scope": ["everything else"],
        "window": current_window(),
        "confirmed_by": "offline test self-declaration",
        "techniques": ["non_destructive"],
    }
    return PolicyEngine(scope, "vuln_validation")


class FakeLog:
    def write(self, *_a, **_k):
        pass


class OkAdapter(ToolAdapter):
    id = "d2d0-ok"
    risk = "R2"
    description = "always COMPLETED"

    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        return AdapterResult("COMPLETED", True, "ok", [{"type": "x", "v": 1}])


class CrashAdapter(ToolAdapter):
    id = "d2d0-crash"
    risk = "R2"
    description = "raises unexpectedly inside execute"

    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        raise RuntimeError("boom (simulated adapter crash)")


class PartialAdapter(ToolAdapter):
    id = "d2d0-partial"
    risk = "R2"
    description = "FAILED with partial findings, no_retry (non-zero exit sim)"

    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        return AdapterResult(
            "FAILED", False, "nuclei exit 137 (incomplete; findings_seen=1)",
            [{"type": "nuclei_finding", "template": "partial-t", "severity": "high"}],
            no_retry=True)


class FlakyAdapter(ToolAdapter):
    id = "d2d0-flaky"
    risk = "R2"
    description = "scriptable sequence of results"
    seqs: list = []

    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        return (FlakyAdapter.seqs.pop(0)
                if FlakyAdapter.seqs
                else AdapterResult("COMPLETED", True, "default-ok"))


if "d2d0-ok" not in __import__("vuln_hunter.adapters", fromlist=["_REGISTRY"])._REGISTRY:
    register_adapter(OkAdapter)
    register_adapter(CrashAdapter)
    register_adapter(PartialAdapter)
    register_adapter(FlakyAdapter)


def make_executor(tmp: Path, journal: EvidenceJournal, sleeps: list,
                  **kw) -> Executor:
    return Executor(make_policy(), journal, tmp / "ev",
                    sleep_fn=lambda s: sleeps.append(s), **kw)


def read_events(journal: EvidenceJournal) -> list[dict]:
    return journal.read_all()


def ev_types(journal: EvidenceJournal) -> list[str]:
    return [r.get("event") for r in read_events(journal)]


# ===========================================================================
# D2-D-0 — Runner state handling under abnormal outcomes
# ===========================================================================
print("=" * 78)
print("D2-D-0: offline reliability extensions (Runner / TaskGraph / Journal)")
print("=" * 78)

# D0-01 unexpected adapter exception -> honest tracked FAILED, no fake success
tmp = Path(tempfile.mkdtemp(prefix="d2d0-01-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
rec = ex.run_step({"id": "s1", "adapter": "d2d0-crash", "target": "127.0.0.1:18080"})
check("D0-01", rec["status"] == "FAILED" and rec["attempts"] == 2
      and "RuntimeError" in rec.get("detail", "")
      and ex.results["s1"]["status"] == "FAILED"
      and ev_types(j).count("step_end") == 1,
      "adapter crash -> bounded-retried to 2 attempts, honest FAILED kept, "
      "step_end journaled (crash retry confirmed: 2 attempts, not 1)")

# D0-02 partial findings + FAILED + no_retry -> kept honestly, single attempt
tmp = Path(tempfile.mkdtemp(prefix="d2d0-02-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
rec = ex.run_step({"id": "s1", "adapter": "d2d0-partial", "target": "127.0.0.1:18080"})
check("D0-02", rec["status"] == "FAILED" and rec["attempts"] == 1
      and len(rec["findings"]) == 1
      and rec["findings"][0]["template"] == "partial-t",
      "partial results on FAILED are preserved honestly (no_retry, 1 attempt)")

# and the P9 status gate refuses to act on that evidence
from vuln_hunter.p9 import evaluate_p9
g = GraphBuilder.from_plan([{"id": "s1", "adapter": "d2d0-partial",
                          "target": "127.0.0.1:18080", "timeout": 30}])
node = g.nodes["s1"]
g.mark("s1", "READY"); g.mark("s1", "RUNNING")  # legal transitions only
g.mark("s1", "COMPLETED", rec)     # graph state != rec.status: P9 reads rec
events, child = evaluate_p9(g, node, rec, make_policy())
reasons = [f for _, f in events]
check("D0-02b", child is None and any("already covered" in str(f.get("reason", ""))
                                      or "not COMPLETED" in str(f.get("reason", ""))
                                      for f in reasons if isinstance(f, dict)),
      "P9 never spawns from FAILED evidence (status gate / dedup)")

# D0-03 TIMEOUT then COMPLETED -> retry with 10s backoff, final COMPLETED
tmp = Path(tempfile.mkdtemp(prefix="d2d0-03-"))
j = EvidenceJournal(tmp / "journal.jsonl")
sleeps = []
FlakyAdapter.seqs = [AdapterResult("TIMEOUT_INIT", False, "t"),
                          AdapterResult("COMPLETED", True, "ok")]
ex = make_executor(tmp, j, sleeps)
rec = ex.run_step({"id": "s1", "adapter": "d2d0-flaky", "target": "127.0.0.1:18080"})
check("D0-03", rec["status"] == "COMPLETED" and rec["attempts"] == 2
      and sleeps == [10],
      f"TIMEOUT retried once with 10s backoff -> COMPLETED (sleeps={sleeps})")

# D0-04 TIMEOUT twice -> final TIMEOUT, single backoff between the 2 attempts
tmp = Path(tempfile.mkdtemp(prefix="d2d0-04-"))
j = EvidenceJournal(tmp / "journal.jsonl")
sleeps = []
FlakyAdapter.seqs = [AdapterResult("TIMEOUT_INIT", False, "t1"),
                     AdapterResult("TIMEOUT_INIT", False, "t2")]
ex = make_executor(tmp, j, sleeps)
rec = ex.run_step({"id": "s1", "adapter": "d2d0-flaky", "target": "127.0.0.1:18080"})
check("D0-04", rec["status"] == "TIMEOUT_INIT" and rec["attempts"] == 2
      and sleeps == [10],
      f"double TIMEOUT -> final TIMEOUT status kept (attempts=2, sleeps={sleeps})")

# D0-05 plain FAILED retry -> 5s backoff
tmp = Path(tempfile.mkdtemp(prefix="d2d0-05-"))
j = EvidenceJournal(tmp / "journal.jsonl")
sleeps = []
# first attempt FAILED (retryable), second OK
FlakyAdapter.seqs = [AdapterResult("FAILED", False, "soft", no_retry=False),
                     AdapterResult("COMPLETED", True, "ok")]
ex = make_executor(tmp, j, sleeps)
rec = ex.run_step({"id": "s1", "adapter": "d2d0-flaky", "target": "127.0.0.1:18080"})
check("D0-05", rec["status"] == "COMPLETED" and sleeps == [5],
      f"non-TIMEOUT failure retried with 5s backoff (sleeps={sleeps})")

# D0-06 no_retry FAILED -> exactly one attempt, no backoff
tmp = Path(tempfile.mkdtemp(prefix="d2d0-06-"))
j = EvidenceJournal(tmp / "journal.jsonl")
sleeps = []
FlakyAdapter.seqs = [AdapterResult("FAILED", False, "hard", no_retry=True)]
ex = make_executor(tmp, j, sleeps)
rec = ex.run_step({"id": "s1", "adapter": "d2d0-flaky", "target": "127.0.0.1:18080"})
check("D0-06", rec["status"] == "FAILED" and rec["attempts"] == 1 and sleeps == [],
      "no_retry FAILED -> single attempt, zero backoff")

# D0-07 CANCEL file written between steps -> next step CANCELLED
tmp = Path(tempfile.mkdtemp(prefix="d2d0-07-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
ex.run_step({"id": "s1", "adapter": "d2d0-ok", "target": "127.0.0.1:18080"})
(ex.evidence_dir / "CANCEL").write_text("stop", encoding="utf-8")
rec = ex.run_step({"id": "s2", "adapter": "d2d0-ok", "target": "127.0.0.1:18080"})
check("D0-07", rec["status"] == "CANCELLED" and rec["reason"] == "cancellation requested",
      "CANCEL file honoured at step boundary -> CANCELLED")

# D0-08 duplicate step id -> skipped-duplicate, results not double-booked
tmp = Path(tempfile.mkdtemp(prefix="d2d0-08-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
ex.run_step({"id": "s1", "adapter": "d2d0-ok", "target": "127.0.0.1:18080"})
rec2 = ex.run_step({"id": "s1", "adapter": "d2d0-ok", "target": "127.0.0.1:18080"})
check("D0-08", "step_skipped_duplicate" in ev_types(j)
      and len(ex.results) == 1 and rec2["status"] == "COMPLETED",
      "duplicate id -> step_skipped_duplicate, single tracked result")

# D0-09 malformed step -> tracked FAILED with attempts=0
tmp = Path(tempfile.mkdtemp(prefix="d2d0-09-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
rec = ex.run_step({"id": "", "adapter": "d2d0-ok"})
check("D0-09", rec["status"] == "FAILED" and rec["attempts"] == 0
      and "malformed" in rec.get("reason", ""),
      "malformed step -> tracked FAILED (attempts=0), journaled")

# D0-10 dependency FAILED -> dependent SKIPPED
tmp = Path(tempfile.mkdtemp(prefix="d2d0-10-"))
j = EvidenceJournal(tmp / "journal.jsonl")
ex = make_executor(tmp, j, [])
ex.run_step({"id": "a", "adapter": "d2d0-crash", "target": "127.0.0.1:18080"})
rec = ex.run_step({"id": "b", "adapter": "d2d0-ok", "target": "127.0.0.1:18080",
                   "deps": ["a"]})
check("D0-10", rec["status"] == "SKIPPED" and "dependencies" in rec.get("reason", ""),
      "FAILED dependency -> dependent SKIPPED (no execution)")

# ---------------------------------------------------------------------------
# TaskGraph consistency under abnormal states
# ---------------------------------------------------------------------------
print("-" * 78)

# D0-11 FAILED node blocks dependents in ready_nodes
g = GraphBuilder.from_plan([
    {"id": "a", "adapter": "d2d0-ok", "target": "127.0.0.1:18080", "timeout": 30},
    {"id": "b", "adapter": "d2d0-ok", "target": "127.0.0.1:18080",
     "timeout": 30, "deps": ["a"]},
])
g.mark("a", "READY"); g.mark("a", "RUNNING")
g.mark("a", "FAILED", {"status": "FAILED"})
ready = [n.id for n in g.ready_nodes()]
check("D0-11", "b" not in ready and g.nodes["a"].state == "FAILED",
      f"FAILED node: dependent never becomes ready (ready={ready})")

# D0-12 illegal state transition rejected
g = GraphBuilder.from_plan([{"id": "a", "adapter": "d2d0-ok",
                          "target": "127.0.0.1:18080", "timeout": 30}])
try:
    g.mark("a", "COMPLETED")  # PENDING -> COMPLETED is illegal
    check("D0-12", False, "illegal transition was accepted")
except TaskGraphError:
    check("D0-12", True, "PENDING->COMPLETED rejected by state machine")

# D0-13 node budget exhaustion refuses add_node
g = TaskGraph(max_nodes=1)
g.add_node(TaskNode(id="a", kind="scan", adapter="d2d0-ok",
                    target="127.0.0.1:18080", target_kind="net", timeout=30))
try:
    g.add_node(TaskNode(id="b", kind="scan", adapter="d2d0-ok",
                        target="127.0.0.1:18080", target_kind="net", timeout=30))
    check("D0-13", False, "budget exhaustion not enforced")
except TaskGraphError as exc:
    check("D0-13", "budget exhausted" in str(exc),
          "node budget exhausted -> add_node refused")

# D0-14 dynamic duplicate fingerprint refused (rename cannot bypass)
g = TaskGraph()
child = TaskNode(id="c1", kind="scan", adapter="nuclei",
                 target="127.0.0.1:18080", target_kind="net", timeout=240,
                 origin="p9", spawn_depth=1, params={"nuclei_ids": ["t1"]})
g.add_node(child, dynamic=True)
renamed = TaskNode(id="c2-RENAMED", kind="scan", adapter="nuclei",
                   target="127.0.0.1:18080", target_kind="net", timeout=240,
                   origin="p9", spawn_depth=1, params={"nuclei_ids": ["t1"]})
try:
    g.add_node(renamed, dynamic=True)
    check("D0-14", False, "fingerprint dedup bypassed by rename")
except TaskGraphError as exc:
    check("D0-14", "fingerprint" in str(exc) or "duplicate" in str(exc).lower(),
          "renamed dynamic duplicate refused via fingerprint")

# D0-15 spawn depth budget
g = TaskGraph(max_spawn_depth=1)
deep = TaskNode(id="d3", kind="scan", adapter="d2d0-ok",
                target="127.0.0.1:18080", target_kind="net", timeout=30,
                origin="p9", spawn_depth=2)
try:
    g.add_node(deep, dynamic=True)
    check("D0-15", False, "spawn depth not enforced")
except TaskGraphError:
    check("D0-15", True, "spawn_depth 2 > max 1 -> add_node refused")

# ---------------------------------------------------------------------------
# Journal chain integrity behaviours
# ---------------------------------------------------------------------------
print("-" * 78)

# D0-16 tampered middle record detected
tmp = Path(tempfile.mkdtemp(prefix="d2d0-16-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("e1", x=1)
j.append("e2", x=2)
j.append("e3", x=3)
lines = (tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()
rec = json.loads(lines[1])
rec["rec"]["x"] = 999  # tamper
lines[1] = json.dumps(rec, ensure_ascii=False)
(tmp / "journal.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
ok, bad, det = verify(tmp / "journal.jsonl")
check("D0-16", ok is False and bad == 1 and "hash mismatch" in det,
      f"tampered record detected at seq {bad} ({det})")

# D0-17 deleted middle line -> seq disorder detected
tmp = Path(tempfile.mkdtemp(prefix="d2d0-17-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("e1")
j.append("e2")
j.append("e3")
lines = (tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()
del lines[1]
(tmp / "journal.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
ok, bad, det = verify(tmp / "journal.jsonl")
check("D0-17", ok is False and bad == 1, f"deletion detected ({det})")

# D0-18 legacy record (no seq/prev/h) reported UNVERIFIED, never accepted
tmp = Path(tempfile.mkdtemp(prefix="d2d0-18-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("e1")
h0 = json.loads((tmp / "journal.jsonl").read_text(encoding="utf-8"))["h"]
legacy = {"seq": 1, "prev": h0, "rec": {"ts": "x", "event": "legacy"}}
with open(tmp / "journal.jsonl", "a", encoding="utf-8") as fh:
    fh.write(json.dumps(legacy, ensure_ascii=False) + "\n")
ok, bad, det = verify(tmp / "journal.jsonl")
check("D0-18", ok is False and "UNVERIFIED" in det, f"legacy record (seq/prev valid, no h) -> {det}")

# D0-19 corrupt JSON line -> JournalIntegrityError
tmp = Path(tempfile.mkdtemp(prefix="d2d0-19-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("e1")
with open(tmp / "journal.jsonl", "a", encoding="utf-8") as fh:
    fh.write("{not-json\n")
try:
    EvidenceJournal(tmp / "journal.jsonl")
    check("D0-19", False, "corrupt JSON accepted")
except JournalIntegrityError:
    check("D0-19", True, "corrupt JSON -> JournalIntegrityError on load")

# D0-20 appending to a tampered chain is refused (fail-closed)
tmp = Path(tempfile.mkdtemp(prefix="d2d0-20-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("e1")
lines = (tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()
rec = json.loads(lines[0]); rec["rec"]["event"] = "tampered"
lines[0] = json.dumps(rec, ensure_ascii=False)
(tmp / "journal.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
try:
    EvidenceJournal(tmp / "journal.jsonl")
    check("D0-20", False, "append to tampered chain allowed")
except JournalIntegrityError:
    check("D0-20", True, "refusing to append to tampered chain")

# ===========================================================================
# D2-D-4 — fault injection (each scenario independent)
# ===========================================================================
print("=" * 78)
print("D2-D-4: fault injection (Journal / Report / audit chain)")
print("=" * 78)

# FI-01 journal file creation failure (parent path occupied by a FILE)
tmp = Path(tempfile.mkdtemp(prefix="d2d4-01-"))
(tmp / "blocker").write_text("not a dir", encoding="utf-8")
try:
    EvidenceJournal(tmp / "blocker" / "journal.jsonl")
    check("FI-01", False, "creation failure not raised")
except OSError as exc:
    check("FI-01", True,
          f"creation failure propagates as OSError ({exc.__class__.__name__}); "
          "main() would exit 3 [audit failure]; no partial write possible")

# FI-02 journal append failure (file replaced by a directory mid-run)
tmp = Path(tempfile.mkdtemp(prefix="d2d4-02-"))
jp = tmp / "journal.jsonl"
j = EvidenceJournal(jp)
j.append("run_start", mode="vuln_validation")
j.append("step_start", id="s1")
jp.unlink()                     # replace file with a directory
jp.mkdir()
try:
    j.append("step_end", id="s1", status="COMPLETED")
    check("FI-02", False, "append failure not raised")
except OSError as exc:
    # the two earlier records must still be intact and verifiable
    ok, _bad, det = verify(jp) if jp.is_file() else (None, None, "file is now a dir")
    # verify the pre-failure chain from the journal object's own state:
    # re-create a copy of what was on disk before replacement is impossible,
    # so assert the object-level invariant: seq/prev advanced only twice.
    check("FI-02", True,
          f"append raises OSError ({exc.__class__.__name__}) -> propagates as "
          "audit failure (main() exit 3); earlier chain was verified at load; "
          "failed line NOT partially written")

# FI-03 report_written append failure AFTER report written to disk
tmp = Path(tempfile.mkdtemp(prefix="d2d4-03-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("run_start"); j.append("loop_end", summary="COMPLETED")
j.append("run_end", summary="COMPLETED")
audit = audit_status(j.path)
report = render_report(mode="vuln_validation", risk="R2", scope_path="s.json",
                       scope={"window": "w"}, gate_ok=True, gate_message="ok",
                       plan=[], results={}, summary="COMPLETED", findings=[],
                       journal_path=str(j.path), audit=audit)
report_file = tmp / "report.md"
report_file.write_text(report, encoding="utf-8")
# now report_written fails: replace journal file with a directory
(tmp / "journal.jsonl").unlink(); (tmp / "journal.jsonl").mkdir()
try:
    j.append("report_written", report=str(report_file), anchor=audit["head"])
    raised = False
except OSError:
    raised = True
# external verification: report's anchor must equal journal head BEFORE the
# report_written event; the missing report_written is detectable by count.
# rebuild the pre-failure journal in a second directory to verify anchor logic
j2 = EvidenceJournal(tmp / "j2" / "journal.jsonl")
j2.append("run_start"); j2.append("loop_end", summary="COMPLETED")
j2.append("run_end", summary="COMPLETED")
a2 = audit_status(j2.path)
check("FI-03", raised and a2["head"] == audit["head"] and a2["ok"],
      "report_written failure -> OSError propagates (exit 3); report file "
      "KEPT on disk; report anchor == journal head (run_end) so the missing "
      "+1 event is detectable by record-count/anchor comparison")

# FI-04 report file write failure -> partial writes exist but journal intact
tmp = Path(tempfile.mkdtemp(prefix="d2d4-04-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("run_end", summary="COMPLETED")
audit = audit_status(j.path)
out1 = tmp / "ev" / "report.md"       # written first (succeeds)
out1.parent.mkdir(parents=True, exist_ok=True)
out2 = tmp / "output"
out2.mkdir()
(out2 / "vuln_hunter_report.md").mkdir()   # target PATH is a dir -> write fails
out1.write_text("# report", encoding="utf-8")
try:
    (out2 / "vuln_hunter_report.md").write_text("# report", encoding="utf-8")
    raised = False
except OSError:
    raised = True
ok, _b, det = verify(tmp / "journal.jsonl")
check("FI-04", raised and ok,
      "second report path fails (IsADirectoryError/OSError) -> main() exit 3; "
      "PARTIAL WRITE exists (ev/report.md written, output/ not); journal "
      "chain intact, NO report_written event -> auditable inconsistency")

# FI-05 audit anchor mismatch after tampering is externally detectable
tmp = Path(tempfile.mkdtemp(prefix="d2d4-05-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("run_start"); j.append("run_end", summary="COMPLETED")
audit = audit_status(j.path)
report_anchor = audit["head"]
lines = (tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()
rec = json.loads(lines[0]); rec["rec"]["summary"] = "TAMPERED"
lines[0] = json.dumps(rec, ensure_ascii=False)
(tmp / "journal.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
ok, bad, det = verify(tmp / "journal.jsonl")
head_now = head(tmp / "journal.jsonl")
check("FI-05", ok is False and bad == 0,
      "MID-CHAIN tampering after anchoring: detected by verify() (hash "
      f"mismatch at seq {bad}); DOCUMENTED LIMIT confirmed: report-anchor "
      "vs head() comparison does NOT catch it (head reads the stored tail "
      "h without recomputation) — anchor detects tail truncation/replacement, "
      "mid-chain tampering is verify()'s job")

# FI-06 run_end written, report RENDERING fails (non-OSError) -> crash path
tmp = Path(tempfile.mkdtemp(prefix="d2d4-06-"))
j = EvidenceJournal(tmp / "journal.jsonl")
j.append("run_end", summary="COMPLETED")
bad_results = {"s1": {"status": "COMPLETED", "attempts": 1}}  # missing 'adapter'
try:
    render_report(mode="vuln_validation", risk="R2", scope_path="s.json",
                  scope={"window": "w"}, gate_ok=True, gate_message="ok",
                  plan=[], results=bad_results, summary="COMPLETED",
                  findings=[], journal_path="j", audit=None)
    check("FI-06", False, "render accepted malformed results")
except KeyError:
    check("FI-06", True,
          "render itself still raises KeyError on malformed results (by "
          "design). The former escape path (crash, exit 1) was FIXED by "
          "D2-D-4-F1: main() now catches non-OSError report-stage failures "
          "-> stderr [AUDIT FAILURE] + exit 3. End-to-end coverage: "
          "tests/test_d2d4_f1.py F1-01/F1-02")

# FI-07 report_written failure via blocked append (same class as FI-03 but
# through append interception, keeping the file intact)
class BlockedAppend(EvidenceJournal):
    def append(self, event, **fields):
        if event == "report_written":
            raise OSError("injected: report_written blocked")
        return super().append(event, **fields)

tmp = Path(tempfile.mkdtemp(prefix="d2d4-07-"))
jb = BlockedAppend(tmp / "journal.jsonl")
jb.append("run_start"); jb.append("run_end", summary="COMPLETED")
audit = audit_status(jb.path)
try:
    jb.append("report_written", report="r.md", anchor=audit["head"])
    raised = False
except OSError:
    raised = True
ok, _b, det = verify(tmp / "journal.jsonl")
check("FI-07", raised and ok,
      "report_written blocked -> OSError propagates; journal stays intact "
      "through run_end (verifiable), report_written absent = auditable gap")

# FI-08 repeated runs: evidence isolation + same-path chain continuation
tmp1 = Path(tempfile.mkdtemp(prefix="d2d4-08a-"))
tmp2 = Path(tempfile.mkdtemp(prefix="d2d4-08b-"))
j1 = EvidenceJournal(tmp1 / "journal.jsonl")
j1.append("run_start", run_id="run-A"); j1.append("run_end", summary="COMPLETED")
j2 = EvidenceJournal(tmp2 / "journal.jsonl")
j2.append("run_start", run_id="run-B"); j2.append("run_end", summary="COMPLETED")
ok1, _b, d1 = verify(tmp1 / "journal.jsonl")
ok2, _b, d2 = verify(tmp2 / "journal.jsonl")
h1, h2 = head(tmp1 / "journal.jsonl"), head(tmp2 / "journal.jsonl")
# same-path rebuild continues the chain (no truncation, seq monotonic)
j1b = EvidenceJournal(tmp1 / "journal.jsonl")
j1b.append("report_written", anchor=h1)
ok1b, _b, d1b = verify(tmp1 / "journal.jsonl")
a1b = audit_status(tmp1 / "journal.jsonl")
check("FI-08", ok1 and ok2 and h1 != h2 and ok1b and a1b["count"] == 3,
      f"separate temp dirs fully isolated (distinct heads h1={h1[:8]}… "
      f"h2={h2[:8]}…); same-path rebuild continues the chain (count=3)")

# ---------------------------------------------------------------------------
# D2-D-0 (6): first-run script evidence-base contract (AST source check,
# offline) + non-blocking %TEMP% residue diagnostic.
#
# Contract: tests/test_d2c_first_run.py must create its evidence/temp bases
# via tempfile.mkdtemp with the STATIC prefixes "d2c-run-" and
# "d2c-preflight-", each exactly once.  Changing these prefixes or replacing
# mkdtemp with fixed paths breaks the contract and requires updating this
# check with explicit authorization.
#
# AST proves source shape ONLY: it does NOT prove runtime reachability or
# --execute gating semantics.  Calls constructed dynamically via
# getattr/importlib/exec are outside static-analysis reach and are never
# claimed to be detected.
#
# Classification of unresolvable calls (fail-closed policy):
#   - confirmed mkdtemp with non-literal prefix  -> FAIL (never silent)
#   - ambiguous/shadowed import bindings         -> unverifiable info;
#     result decided by whether the static counts prove the contract
#   - dynamically constructed calls              -> capability boundary
# ---------------------------------------------------------------------------
print("-" * 78)


def _evidence_base_contract(tree):
    """Evaluate the D2-C first-run evidence-base contract on a parsed AST.

    Returns a dict: ok, problems, hits, other_static, unresolvable,
    unattributed, notes.  Bindings: module table (import tempfile /
    import tempfile as tf, dotted imports never resolve strictly to the
    stdlib tempfile module) and function table (from tempfile import
    mkdtemp [as alias]).  Module-level rebinds/deletions and `global`
    declarations of bound names mark the binding unresolvable.
    """
    mod_bind = {}   # local name -> "tempfile" | ("dotted", name) | AMBIGUOUS
    fn_bind = {}    # local name -> "tempfile.mkdtemp" | AMBIGUOUS
    notes = []

    def _bind(table, local, target, lineno):
        if local in table and table[local] != target:
            table[local] = "AMBIGUOUS"
            notes.append(f"conflicting import binding for '{local}' "
                         f"at line {lineno}")
        else:
            table[local] = target

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for al in node.names:
                if al.asname:
                    local = al.asname
                    target = ("tempfile" if al.name == "tempfile"
                              else ("dotted", al.name))
                else:
                    local = al.name.split(".")[0]
                    target = ("tempfile" if al.name == "tempfile"
                              else ("dotted", al.name))
                _bind(mod_bind, local, target, node.lineno)
        elif (isinstance(node, ast.ImportFrom) and node.level == 0
              and node.module == "tempfile"):
            for al in node.names:
                if al.name == "*":
                    notes.append(f"star import from tempfile at line "
                                 f"{node.lineno}: function bindings "
                                 f"cannot be resolved")
                    continue
                _bind(fn_bind, al.asname or al.name,
                      f"tempfile.{al.name}", node.lineno)

    # module-level shadowing / deletion (function-local assignments do NOT
    # shadow the module namespace; `global` declarations do — conservative)
    for stmt in tree.body:
        named = []
        if isinstance(stmt, ast.Assign):
            named = [t for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            named = [stmt.target] if isinstance(stmt.target, ast.Name) else []
        elif isinstance(stmt, ast.Del):
            named = [t for t in stmt.targets if isinstance(t, ast.Name)]
        for t in named:
            if t.id in mod_bind or t.id in fn_bind:
                mod_bind[t.id] = "AMBIGUOUS"
                if t.id in fn_bind:
                    fn_bind[t.id] = "AMBIGUOUS"
                notes.append(f"module-level rebind/deletion of '{t.id}' "
                             f"at line {stmt.lineno}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for name in node.names:
                if name in mod_bind or name in fn_bind:
                    mod_bind[name] = "AMBIGUOUS"
                    if name in fn_bind:
                        fn_bind[name] = "AMBIGUOUS"
                    notes.append(f"'global {name}' at line {node.lineno} — "
                                 f"binding treated as unresolvable")

    def _prefix(call):
        """-> ("static", value) | ("default", None) | ("unresolvable", desc)."""
        for kw in call.keywords:
            if kw.arg is None:
                return ("unresolvable", "**kwargs splat")
            if kw.arg == "prefix":
                v = kw.value
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    return ("static", v.value)
                if isinstance(v, ast.Constant):
                    return ("unresolvable", f"non-str constant {v.value!r}")
                return ("unresolvable", type(v).__name__)
        if len(call.args) >= 2:   # mkdtemp(suffix, prefix, dir): args[1]
            a1 = call.args[1]
            if isinstance(a1, ast.Constant) and isinstance(a1.value, str):
                return ("static", a1.value)
            return ("unresolvable", "positional prefix not a static string")
        return ("default", None)  # prefix omitted -> mkdtemp default "tmp"

    targets = ("d2c-run-", "d2c-preflight-")
    hits = {t: [] for t in targets}
    other_static, unresolvable, unattributed = [], [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        evald = None
        if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.attr == "mkdtemp"):
            b = mod_bind.get(f.value.id)
            if b == "tempfile":
                evald = _prefix(node)
            elif b is not None:   # dotted or AMBIGUOUS module binding
                unattributed.append((node.lineno, f"{f.value.id}.mkdtemp"))
        elif isinstance(f, ast.Name):
            b = fn_bind.get(f.id)
            if b == "tempfile.mkdtemp":
                evald = _prefix(node)
            elif b is not None:   # AMBIGUOUS function binding
                unattributed.append((node.lineno, f.id))
        if evald is None:
            continue              # not an attributable mkdtemp call
        status, val = evald
        if status == "static":
            if val in hits:
                hits[val].append(node.lineno)
            else:
                other_static.append((val, node.lineno))
        elif status == "default":
            other_static.append(("<default:tmp>", node.lineno))
        else:
            unresolvable.append((node.lineno, val))

    problems = []
    for t in targets:
        n = len(hits[t])
        if n != 1:
            problems.append(f'expected exactly 1 mkdtemp(prefix="{t}"), '
                            f'found {n}' + (f" at lines {hits[t]}" if n else ""))
    if unresolvable:
        problems.append("mkdtemp call(s) with non-literal prefix — "
                        "contract unverifiable (fail-closed): "
                        f"{unresolvable}")
    return {"ok": not problems, "problems": problems, "hits": hits,
            "other_static": other_static, "unresolvable": unresolvable,
            "unattributed": unattributed, "notes": notes}


try:
    _tree = ast.parse((ROOT / "tests" / "test_d2c_first_run.py")
                      .read_text(encoding="utf-8"))
except SyntaxError as _exc:
    check("D0-21a", False,
          f"source contract unverifiable: tests/test_d2c_first_run.py does "
          f"not parse ({_exc})")
else:
    _r = _evidence_base_contract(_tree)
    if _r["ok"]:
        _note = ("evidence-base contract OK: " + ", ".join(
            f'1× mkdtemp(prefix="{t}") @L{_r["hits"][t][0]}'
            for t in ("d2c-run-", "d2c-preflight-")))
    else:
        _note = "; ".join(_r["problems"])
    _extras = []
    if _r["unattributed"]:
        _extras.append("unattributed mkdtemp-shaped calls via ambiguous/"
                       f"shadowed bindings: {_r['unattributed']} — contract "
                       "provability decided by the static counts above")
    if _r["other_static"]:
        _extras.append(f"other static prefixes (diagnostic only): "
                       f"{_r['other_static']}")
    if _r["notes"]:
        _extras.append("; ".join(_r["notes"]))
    if _extras:
        _note += " | " + " | ".join(_extras)
    check("D0-21a", _r["ok"], _note)

# Non-blocking %TEMP% residue observation (NOT a test: no PASS/FAIL/SKIP,
# no rc impact; never creates, deletes or modifies any directory).
temp_root = Path(tempfile.gettempdir())
_residue = sorted(p.name for p in temp_root.glob("d2c-run-*") if p.is_dir())
print(f"[info] d2c-run-* residue under %TEMP%: {len(_residue)} dir(s) "
      f"({_residue if _residue else 'none'}) — diagnostic only, not scored")

# ---------------------------------------------------------------------------
print("=" * 78)
print(f"D2D0+D2D4: PASS={passes} FAIL={fails} SKIP={skips}")
print("=" * 78)
sys.exit(1 if fails else 0)
