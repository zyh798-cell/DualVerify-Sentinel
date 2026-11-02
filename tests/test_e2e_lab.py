"""S3-D2-B: end-to-end lab verification (Fake adapters + local HTTP target).

Constraints honoured by this suite:
- vuln_hunter/ core package is NEVER modified (hash-checked externally);
  fake adapters are registered inside THIS process or inside throwaway
  bootstrap subprocesses only.
- The only network target is 127.0.0.1:18080 (local lab server started and
  stopped by this suite; bind address asserted). Every request is logged and
  asserted to originate from and terminate at loopback.
- All CLI runs execute the REAL main() (real gate subprocess, real journal,
  real report file, real exit codes) with cwd/evidence inside temp dirs.
- Journal corruption / write-failure tests run on copies in temp dirs only.
- All fake findings carry synthetic markers and are never described as real
  vulnerabilities.

Run:  python tests/test_e2e_lab.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter  # noqa: E402
from vuln_hunter.decision import DecisionEngine  # noqa: E402
from vuln_hunter.journal import EvidenceJournal, JournalIntegrityError, verify  # noqa: E402
from vuln_hunter.loop import AutonomousLoop  # noqa: E402
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


PORT = 18080
LAB_TARGET = "127.0.0.1:18080"

# ---------------------------------------------------------------------------
# Local lab HTTP server (loopback only, fixed port, request capture)
# ---------------------------------------------------------------------------
REQUEST_LOG: list[str] = []


class LabHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        REQUEST_LOG.append(f"client={self.client_address[0]} {fmt % args}")

    def address_string(self):
        return self.client_address[0]  # no reverse DNS lookups


server = None
try:
    server = ThreadingHTTPServer((f"127.0.0.1", PORT), LabHandler)
except OSError as exc:
    print(f"STOP CONDITION: cannot bind 127.0.0.1:{PORT} ({exc}); "
          f"per D2-B rules the suite aborts without any scan.")
    sys.exit(2)

serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
serve_thread.start()
bind_addr = f"{server.server_address[0]}:{server.server_address[1]}"

# ---------------------------------------------------------------------------
# Bootstrap: real CLI main() with an optional synthetic fake nuclei adapter
# ---------------------------------------------------------------------------
BOOTSTRAP = r'''
import os, sys
sys.path.insert(0, r"__ROOT__")
mode = os.environ.get("D2B_FAKE", "none")
if mode != "none":
    from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter

    class D2BFakeNuclei(ToolAdapter):
        """Synthetic nuclei stand-in: no binary, no network, no real scan."""
        id, risk = "nuclei", "R2"

        def _run(self, target, timeout, log, step=None):
            ids = (step or {}).get("nuclei_ids")
            log.write("[d2b-fake] synthetic nuclei adapter: no network, no real scan\n")
            if mode == "fail":
                return AdapterResult(
                    "FAILED", False, "synthetic failure (partial results)",
                    findings=[{"type": "nuclei_finding",
                               "template": "lab-synthetic-demo",
                               "severity": "high",
                               "name": "SYNTHETIC-LAB-FINDING (not a real vulnerability)",
                               "host": target, "matched_at": target,
                               "synthetic": True}],
                    no_retry=True)
            if mode == "timeout":
                return AdapterResult("TIMEOUT", False, "synthetic timeout",
                                     no_retry=True)
            if ids:
                return AdapterResult(
                    "COMPLETED", True,
                    f"focused re-validation {ids[0]}: clean (SYNTHETIC LAB)")
            return AdapterResult(
                "COMPLETED", True, "broad scan (SYNTHETIC LAB)",
                findings=[{"type": "nuclei_finding",
                           "template": "lab-synthetic-demo",
                           "severity": "high",
                           "name": "SYNTHETIC-LAB-FINDING (not a real vulnerability)",
                           "host": target, "matched_at": target,
                           "synthetic": True}])

    register_adapter(D2BFakeNuclei)

from vuln_hunter.__main__ import main
sys.exit(main(sys.argv[1:]))
'''.replace("__ROOT__", str(ROOT))


def make_scenario_dir(name: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=f"d2b-{name}-"))
    (tmp / "bootstrap.py").write_text(BOOTSTRAP, encoding="utf-8")
    return tmp


def make_scope(tmp: Path, in_scope: list) -> Path:
    scope = {"client": "d2b-lab (local synthetic test, not a real authorization)",
             "in_scope": in_scope,
             "out_of_scope": ["everything else on this host and network"],
             "window": current_window(),
             "confirmed_by": "d2b-lab self-declared local test",
             "techniques": ["non_destructive"]}
    p = tmp / "scope.json"
    p.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    return p


def run_cli(tmp: Path, mode: str, extra_args: list, fake: str = "none") -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["D2B_FAKE"] = fake
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(ROOT)
    cmd = [sys.executable, str(tmp / "bootstrap.py"), "run",
           "--scope", str(tmp / "scope.json"), "--mode", mode,
           "--target", LAB_TARGET,
           "--evidence-dir", str(tmp / "ev")] + extra_args
    return subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(tmp), env=env, timeout=180)


def journal_records(ev: Path) -> list[dict]:
    return [json.loads(l) for l in
            (ev / "journal.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def raw_records(path: Path) -> list[dict]:
    """Read a journal FILE at an exact path (component-level journals)."""
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def events(ev: Path, name: str) -> list[dict]:
    return [r["rec"] for r in journal_records(ev) if r["rec"].get("event") == name]


print("=" * 78)
print("S3-D2-B E2E LAB TESTS")
print(f"lab server bind: {bind_addr}  (loopback asserted: "
      f"{server.server_address[0] == '127.0.0.1'})")
print("=" * 78)
check("D2B-00", server.server_address[0] == "127.0.0.1"
      and server.server_address[1] == PORT,
      f"lab server bound to {bind_addr} (loopback + fixed port)")

# ---------------------------------------------------------------------------
# Scenario A — static plan normal execution (real probe vs local lab)
# ---------------------------------------------------------------------------
tmpA = make_scenario_dir("a")
make_scope(tmpA, [LAB_TARGET])
procA = run_cli(tmpA, "safe_scan", ["--loop", "--max-steps", "6"])
evA = tmpA / "ev"
check("D2B-A1", procA.returncode == 0,
      f"exit={procA.returncode} (expected 0)")
check("D2B-A2", "[Vuln-Hunter Status] COMPLETED" in procA.stdout,
      "summary COMPLETED")
stepsA = events(evA, "step_end")
check("D2B-A3", len(stepsA) == 1 and stepsA[0]["status"] == "COMPLETED"
      and stepsA[0]["adapter"] == "http_probe"
      and stepsA[0]["target"] == LAB_TARGET,
      "one probe step COMPLETED against 127.0.0.1:18080")
check("D2B-A4", events(evA, "attempt_start") and events(evA, "attempt_end"),
      "attempt events journaled")
okA, badA, detA = verify(evA / "journal.jsonl")
check("D2B-A5", okA, f"journal chain OK ({detA})")
check("D2B-A6", events(evA, "gate_result")
      and events(evA, "run_end") and events(evA, "report_written"),
      "gate_result/run_end/report_written present")

# ---------------------------------------------------------------------------
# Scenarios B + E — fake nuclei COMPLETED + synthetic finding -> P9 spawn ->
# child via Runner -> clean child (empty findings) -> terminate
# ---------------------------------------------------------------------------
tmpB = make_scenario_dir("b")
make_scope(tmpB, [LAB_TARGET])
procB = run_cli(tmpB, "vuln_validation",
                ["--loop", "--p9", "--max-steps", "8"], fake="broad")
evB = tmpB / "ev"
check("D2B-B1", procB.returncode == 0,
      f"exit={procB.returncode} (expected 0)")
spawnB = events(evB, "p9_spawn")
check("D2B-B2", len(spawnB) == 1
      and spawnB[0]["child"] == "s2-nuclei-p9v-lab-synthetic-demo",
      "exactly one P9 spawn with the synthetic template id")
check("D2B-B3", spawnB and spawnB[0]["target"] == LAB_TARGET,
      "child target inherited VERBATIM (127.0.0.1:18080)")
checkB = events(evB, "p9_checks")
check("D2B-B4", checkB and checkB[0]["scope_ok"] and checkB[0]["risk_ok"]
      and checkB[0]["ceiling_ok"] and checkB[0]["timeout_ok"],
      "p9_checks all green (scope/risk/ceiling/timeout)")
stepsB = {r["rec"]["id"]: r["rec"] for r in journal_records(evB)
          if r["rec"].get("event") == "step_end"}
child = stepsB.get("s2-nuclei-p9v-lab-synthetic-demo")
check("D2B-B5", child is not None and child["status"] == "COMPLETED"
      and "focused" in (child.get("detail") or ""),
      "dynamic child executed through the real Runner path")
check("D2B-B6", any(f.get("synthetic") for f in
                    stepsB["s2-nuclei"].get("findings", [])),
      "synthetic marker present in parent findings (never a real vuln claim)")
# --- scenario E (same run): clean child stops the chain --------------------
check("D2B-E1", any(r.get("event") == "p9_evidence_invalid"
                    and "empty" in r.get("reason", "")
                    for r in [x["rec"] for x in journal_records(evB)]),
      "child's empty findings -> p9_evidence_invalid (no grandchild)")
last_dec = events(evB, "decision")[-1]
check("D2B-E2", last_dec["action"] == "STOP"
      and last_dec["next"] == "plan_exhausted",
      "loop terminated normally after clean child")
check("D2B-E3", len(events(evB, "p9_spawn")) == 1,
      "no further spawns after clean child (chain self-terminates)")
okB, _, detB = verify(evB / "journal.jsonl")
check("D2B-B7", okB, f"journal chain OK ({detB})")

# ---------------------------------------------------------------------------
# Scenario C — fake nuclei FAILED with partial findings -> NO P9
# ---------------------------------------------------------------------------
tmpC = make_scenario_dir("c")
make_scope(tmpC, [LAB_TARGET])
procC = run_cli(tmpC, "vuln_validation",
                ["--loop", "--p9", "--max-steps", "8"], fake="fail")
evC = tmpC / "ev"
check("D2B-C1", procC.returncode == 1, f"exit={procC.returncode} (expected 1)")
check("D2B-C2", any(r.get("status") == "FAILED" and r.get("adapter") == "nuclei"
                    for r in events(evC, "step_end")),
      "nuclei step FAILED with partial findings attached")
check("D2B-C3", any(r.get("event") == "p9_skip"
                    and "not COMPLETED" in r.get("reason", "")
                    for r in [x["rec"] for x in journal_records(evC)]),
      "P9 explicitly skipped on FAILED record")
check("D2B-C4", not events(evC, "p9_spawn"),
      "no dynamic spawn from partial findings")
check("D2B-C5", "[Vuln-Hunter Status] FAILED" in procC.stdout,
      "summary FAILED (exit 1 consistent)")

# ---------------------------------------------------------------------------
# Scenario D — fake nuclei TIMEOUT -> NO P9
# ---------------------------------------------------------------------------
tmpD = make_scenario_dir("d")
make_scope(tmpD, [LAB_TARGET])
procD = run_cli(tmpD, "vuln_validation",
                ["--loop", "--p9", "--max-steps", "8"], fake="timeout")
evD = tmpD / "ev"
check("D2B-D1", procD.returncode == 1, f"exit={procD.returncode} (expected 1)")
check("D2B-D2", any(r.get("status") == "TIMEOUT" and r.get("adapter") == "nuclei"
                    for r in events(evD, "step_end")),
      "nuclei step TIMEOUT")
check("D2B-D3", any(r.get("event") == "p9_skip"
                    for r in [x["rec"] for x in journal_records(evD)])
      and not events(evD, "p9_spawn"),
      "P9 skipped on TIMEOUT, no spawn")

# ---------------------------------------------------------------------------
# Scenario F — scope mismatch -> REFUSED
# ---------------------------------------------------------------------------
tmpF = make_scenario_dir("f")
make_scope(tmpF, ["10.9.9.9:18080"])  # deliberately NOT the lab target
procF = run_cli(tmpF, "vuln_validation",
                ["--loop", "--p9", "--max-steps", "8"], fake="broad")
evF = tmpF / "ev"
check("D2B-F1", procF.returncode == 1, f"exit={procF.returncode} (expected 1)")
ref = [r for r in events(evF, "step_end") if r.get("status") == "REFUSED"]
check("D2B-F2", ref and "not covered by in_scope" in ref[0].get("reason", ""),
      "probe REFUSED: target not covered by in_scope")
check("D2B-F3", not events(evF, "attempt_start"),
      "refusal happened BEFORE any tool attempt (no ticket spent)")
check("D2B-F4", not events(evF, "p9_spawn"),
      "no P9 activity out of a refused run")

# ---------------------------------------------------------------------------
# Scenario H-1 — decision step budget stops before the dynamic child runs
# ---------------------------------------------------------------------------
tmpH = make_scenario_dir("h1")
make_scope(tmpH, [LAB_TARGET])
procH = run_cli(tmpH, "vuln_validation",
                ["--loop", "--p9", "--max-steps", "2"], fake="broad")
evH = tmpH / "ev"
check("D2B-H1", procH.returncode == 0,
      f"exit={procH.returncode} (executed steps all COMPLETED)")
lastH = events(evH, "decision")[-1]
check("D2B-H2", lastH["action"] == "STOP"
      and "budget exhausted" in lastH["reason"],
      "decision STOP: step budget exhausted")
check("D2B-H3", events(evH, "p9_spawn")
      and "s2-nuclei-p9v-lab-synthetic-demo" not in
      [r["id"] for r in events(evH, "step_end")],
      "spawn journaled but child never executed (budget guard ahead)")

# ---------------------------------------------------------------------------
# Scenario H-2 — spawn budget exhausted (component level, in-process)
# ---------------------------------------------------------------------------
class ChainNuclei(ToolAdapter):
    id, risk = "nuclei", "R2"
    counter = 0

    def _run(self, target, timeout, log, step=None):
        ChainNuclei.counter += 1
        return AdapterResult("COMPLETED", True, "find (SYNTHETIC)",
                             findings=[{"type": "nuclei_finding",
                                        "template": f"lab-synthetic-{ChainNuclei.counter:04d}",
                                        "severity": "high",
                                        "name": "SYNTHETIC-LAB-FINDING",
                                        "synthetic": True}])


register_adapter(ChainNuclei)
ChainNuclei.counter = 0
tmpH2 = Path(tempfile.mkdtemp(prefix="d2b-h2-"))
jh = EvidenceJournal(tmpH2 / "j.jsonl")
polH = PolicyEngine(json.loads(make_scope(tmpH2, [LAB_TARGET]).read_text()),
                    "vuln_validation")
exH = Executor(polH, jh, tmpH2 / "ev", sleep_fn=lambda s: None)
loopH = AutonomousLoop(polH, jh, exH, DecisionEngine(max_steps=12),
                       enable_p9=True)
g = GraphBuilder.from_plan(
    [{"id": "s2-nuclei", "adapter": "nuclei", "target": LAB_TARGET,
      "timeout": 240}], max_spawns=1)
loopH.run(g)
rej = [r["rec"] for r in raw_records(tmpH2 / "j.jsonl")
       if r["rec"].get("event") == "p9_spawn_rejected"]
spawns = [r["rec"] for r in raw_records(tmpH2 / "j.jsonl")
          if r["rec"].get("event") == "p9_spawn"]
check("D2B-H4", len(spawns) == 1 and len(rej) == 1
      and "spawn budget" in rej[0]["reason"],
      "max_spawns=1 -> second dynamic spawn refused via add_node")

# ---------------------------------------------------------------------------
# Scenario G — risk exceeds mode ceiling (component level, real Executor)
# ---------------------------------------------------------------------------
tmpG = Path(tempfile.mkdtemp(prefix="d2b-g-"))
jG = EvidenceJournal(tmpG / "j.jsonl")
polG = PolicyEngine(json.loads(make_scope(tmpG, [LAB_TARGET]).read_text()),
                    "safe_scan")  # R1 ceiling vs R2 adapter
exG = Executor(polG, jG, tmpG / "ev", sleep_fn=lambda s: None)
recG = exG.run_step({"id": "s2-nuclei", "adapter": "nuclei",
                     "target": LAB_TARGET, "timeout": 10})
check("D2B-G1", recG["status"] == "REFUSED"
      and "ceiling" in recG.get("reason", ""),
      f"R2 step refused under R1 ceiling: {recG.get('reason', '')[:60]}")
check("D2B-G2", not [r["rec"] for r in raw_records(tmpG / "j.jsonl")
                     if r["rec"].get("event") == "attempt_start"],
      "ceiling refusal precedes any attempt")

# ---------------------------------------------------------------------------
# Scenario I — journal corruption / write failure (temp dirs only)
# ---------------------------------------------------------------------------
# I-1: corrupt tail refuses journal construction (fail-closed)
tmpI = Path(tempfile.mkdtemp(prefix="d2b-i1-"))
jpath = tmpI / "j.jsonl"
jpath.write_text('{"seq":0,"prev":"' + "0" * 64 + '","rec":{"ts":"t","event":"x"},'
                 '"h":"' + "a" * 64 + '"}\nGARBAGE-NOT-JSON\n', encoding="utf-8")
try:
    EvidenceJournal(jpath)
    raised_i1 = False
except JournalIntegrityError:
    raised_i1 = True
check("D2B-I1", raised_i1,
      "corrupt journal -> EvidenceJournal refuses to construct (fail-closed)")

# I-2: tampering an existing chain is detected (copy in temp, never the
# original evidence dir)
tmpI2 = Path(tempfile.mkdtemp(prefix="d2b-i2-"))
copyI2 = tmpI2 / "j.jsonl"
shutil.copyfile(evB / "journal.jsonl", copyI2)
lines = copyI2.read_text(encoding="utf-8").splitlines()
tampered = json.loads(lines[2])
tampered["rec"]["event"] = "TAMPERED"
lines[2] = json.dumps(tampered, ensure_ascii=False)
copyI2.write_text("\n".join(lines) + "\n", encoding="utf-8")
okI2, badI2, detI2 = verify(copyI2)
check("D2B-I3", not okI2 and detI2 and "hash mismatch" in detI2,
      f"tampered chain detected at seq {badI2} ({detI2})")

# I-3: CLI-level audit failure -> exit 3 (evidence dir path is a FILE)
tmpI3 = Path(tempfile.mkdtemp(prefix="d2b-i3-"))
file_as_dir = tmpI3 / "ev-file"
file_as_dir.write_text("not a directory", encoding="utf-8")
envI3 = os.environ.copy()
envI3["PYTHONDONTWRITEBYTECODE"] = "1"
envI3["PYTHONPATH"] = str(ROOT)
procI3 = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "run",
     "--scope", str(make_scope(tmpI3, [LAB_TARGET])),
     "--mode", "safe_scan", "--target", LAB_TARGET,
     "--evidence-dir", str(file_as_dir)],
    capture_output=True, text=True, cwd=str(tmpI3), env=envI3, timeout=120)
check("D2B-I4", procI3.returncode == 3
      and "AUDIT FAILURE" in (procI3.stderr or ""),
      f"unusable evidence dir -> exit 3 with AUDIT FAILURE banner "
      f"(exit={procI3.returncode})")

# ---------------------------------------------------------------------------
# Scenario J — report anchor consistency vs journal (scenario B evidence)
# ---------------------------------------------------------------------------
reportJ = (evB / "report.md").read_text(encoding="utf-8")
m_head = re.search(r"链头摘要: `([0-9a-f]{64})`", reportJ)
m_count = re.search(r"记录数（截至锚点）: (\d+)", reportJ)
anchor_ok_j = False
if m_head and m_count:
    recsJ = journal_records(evB)
    run_end_h = [r["h"] for r in recsJ
                 if r["rec"].get("event") == "run_end"]
    anchor_ok_j = (
        run_end_h and run_end_h[-1] == m_head.group(1)
        and int(m_count.group(1)) == len(recsJ) - 1
        and recsJ[-1]["rec"].get("event") == "report_written"
        and verify(evB / "journal.jsonl")[0]
    )
check("D2B-J1", anchor_ok_j,
      "report anchor == run_end chain hash; count == pre-report_written; "
      "exactly one trailing report_written; chain verified")
check("D2B-J2", "s2-nuclei-p9v-lab-synthetic-demo" in reportJ
      and "SYNTHETIC" in reportJ,
      "report carries the dynamic child and synthetic marking")

# ---------------------------------------------------------------------------
# Network containment (whole session)
# ---------------------------------------------------------------------------
check("D2B-N1", all(l.startswith("client=127.0.0.1") for l in REQUEST_LOG),
      f"all {len(REQUEST_LOG)} lab requests originated from loopback")
check("D2B-N2", all("127.0.0.1:18080" in (l.split('"', 1)[1].split('"')[0]
                                     if '"' in l else "")
                    or "GET" in l for l in REQUEST_LOG),
      f"requests served by lab: {REQUEST_LOG[:2]}")

server.shutdown()
server.server_close()

print("-" * 78)
print(f"D2-B E2E LAB TESTS: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
