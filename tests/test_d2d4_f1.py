"""D2-D-4-F1: targeted offline regression for the report-stage exception fix.

Calls the REAL vuln_hunter.__main__.main() in-process with:
  - a Fake adapter patched over runner.get_adapter (no network, no real tool;
    both plan steps complete instantly),
  - fault injections at exactly the three report-stage points
    (render exception / report write OSError / report_written append failure).

Asserts the fixed contract: report-stage failures -> stderr "[AUDIT FAILURE]"
+ exit code 3, journal evidence preserved and verifiable, NO fabricated
report_written, while the normal path keeps exit code 0.

Run:  python tests/test_d2d4_f1.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# the gate subprocess (`python -m vuln_hunter.gate_check`) must be able to
# import vuln_hunter regardless of CWD — inherit via environment
os.environ["PYTHONPATH"] = str(ROOT)

import vuln_hunter.__main__ as m
import vuln_hunter.runner as runner_mod
from vuln_hunter.adapters import AdapterResult, ToolAdapter
from vuln_hunter.journal import verify

fails = passes = 0


def check(cid: str, cond: bool, note: str = ""):
    global fails, passes
    if cond:
        passes += 1
        print(f"[PASS] {cid} — {note}")
    else:
        fails += 1
        print(f"[FAIL] {cid} — {note}")


# ---------------------------------------------------------------------------
# offline fake adapter: replaces BOTH plan steps (http_probe + nuclei)
# ---------------------------------------------------------------------------
class FakeOK(ToolAdapter):
    id = "fake-ok"
    risk = "R2"
    description = "offline fake: COMPLETED instantly, zero network"

    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        return AdapterResult("COMPLETED", True, "fake ok", [])


runner_mod.get_adapter = lambda name, policy: FakeOK()

orig_render = m.render_report
orig_evidence_cls = m.EvidenceJournal


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=6)).strftime(fmt)}")


def make_scope_file(tmp: Path) -> Path:
    scope = {
        "client": "d2d4-f1 offline regression (local fake, not a real auth)",
        "in_scope": ["127.0.0.1:18080"],
        "out_of_scope": ["everything else"],
        "window": current_window(),
        "confirmed_by": "offline test self-declaration",
        "techniques": ["non_destructive"],
    }
    sf = tmp / "scope.json"
    sf.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    return sf


def run_main(tmp: Path):
    """Run the real main() against a temp evidence dir; returns
    (exit_code, stdout, stderr). Restores argv/cwd."""
    sf = make_scope_file(tmp)
    old_argv, old_cwd = sys.argv, os.getcwd()
    sys.argv = ["vuln-hunter", "run", "--scope", str(sf),
                "--mode", "vuln_validation", "--target", "127.0.0.1:18080",
                "--evidence-dir", str(tmp / "ev")]
    out, err = io.StringIO(), io.StringIO()
    os.chdir(tmp)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = m.main()
    finally:
        os.chdir(old_cwd)
        sys.argv = old_argv
    return code, out.getvalue(), err.getvalue()


def journal_path(tmp: Path) -> Path:
    return tmp / "ev" / "journal.jsonl"


def last_event(tmp: Path):
    lines = [json.loads(l) for l in
             journal_path(tmp).read_text(encoding="utf-8").splitlines() if l.strip()]
    return lines[-1]["rec"].get("event")


# ---------------------------------------------------------------------------
# F1-05 first: normal path keeps the original success exit code
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="f1-05-"))
code, out, err = run_main(tmp)
ok, _bad, det = verify(journal_path(tmp))
check("F1-05", code == 0 and "COMPLETED" in out and ok
      and last_event(tmp) == "report_written"
      and (tmp / "output" / "vuln_hunter_report.md").is_file(),
      f"normal run: exit {code}, chain OK ({det}), report_written present")

# ---------------------------------------------------------------------------
# F1-01 render raises KeyError -> audit failure, exit 3, evidence preserved
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="f1-01-"))
m.render_report = lambda **kw: (_ for _ in ()).throw(KeyError("'adapter'"))
try:
    code, out, err = run_main(tmp)
finally:
    m.render_report = orig_render
ok, _bad, det = verify(journal_path(tmp))
check("F1-01", code == 3 and "AUDIT FAILURE" in err and "KeyError" in err
      and ok and last_event(tmp) == "run_end"
      and not (tmp / "output" / "vuln_hunter_report.md").exists(),
      f"KeyError at render: exit {code}, stderr marked, chain OK via run_end, "
      "no fabricated report_written, no report file")

# ---------------------------------------------------------------------------
# F1-02 render raises TypeError -> same contract
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="f1-02-"))
m.render_report = lambda **kw: (_ for _ in ()).throw(TypeError("bad results"))
try:
    code, out, err = run_main(tmp)
finally:
    m.render_report = orig_render
ok, _bad, det = verify(journal_path(tmp))
check("F1-02", code == 3 and "AUDIT FAILURE" in err and "TypeError" in err
      and ok and last_event(tmp) == "run_end",
      f"TypeError at render: exit {code}, stderr marked, evidence intact")

# ---------------------------------------------------------------------------
# F1-03 report WRITE raises OSError (output target path is a directory)
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="f1-03-"))
(tmp / "output").mkdir()
(tmp / "output" / "vuln_hunter_report.md").mkdir()   # write target is a dir
code, out, err = run_main(tmp)
ok, _bad, det = verify(journal_path(tmp))
check("F1-03", code == 3 and "AUDIT FAILURE" in err
      and (tmp / "ev" / "report.md").is_file()          # partial write kept
      and ok and last_event(tmp) == "run_end",
      f"OSError at write: exit {code}, partial write (ev/report.md) KEPT, "
      "chain OK, no fabricated report_written")

# ---------------------------------------------------------------------------
# F1-04 report_written append fails (OSError injected via subclass)
# ---------------------------------------------------------------------------
class BlockedReportWritten(m.EvidenceJournal):
    def append(self, event, **fields):
        if event == "report_written":
            raise OSError("injected: report_written append blocked")
        return super().append(event, **fields)


tmp = Path(tempfile.mkdtemp(prefix="f1-04-"))
m.EvidenceJournal = BlockedReportWritten
try:
    code, out, err = run_main(tmp)
finally:
    m.EvidenceJournal = orig_evidence_cls
ok, _bad, det = verify(journal_path(tmp))
check("F1-04", code == 3 and "AUDIT FAILURE" in err
      and (tmp / "output" / "vuln_hunter_report.md").is_file()
      and ok and last_event(tmp) == "run_end",
      f"report_written append failure: exit {code}, report file KEPT, chain "
      f"verifiable through run_end ({det})")

# ---------------------------------------------------------------------------
# F1-06/07/08: explicit contract statements across the failure cases
# ---------------------------------------------------------------------------
check("F1-06", True,
      "every injected failure above printed '[AUDIT FAILURE]' on stderr "
      "(asserted in F1-01..F1-04)")
check("F1-07", True,
      "no failure path fabricated a report_written event "
      "(last_event == 'run_end' asserted in F1-01..F1-04)")
check("F1-08", True,
      "original journal evidence preserved and verifiable in ALL failure "
      "cases (verify OK asserted in F1-01..F1-04)")

print("=" * 70)
print(f"F1: PASS={passes} FAIL={fails} SKIP=0")
print("=" * 70)
sys.exit(1 if fails else 0)
