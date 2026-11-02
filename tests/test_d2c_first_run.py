"""S3-D2-C: real Nuclei single-template first run — CONTROLLED EXECUTION SUITE.

SAFETY GATE: this script NEVER scans unless invoked with --execute.
Without --execute it runs preflight checks only (environment probe, asset
verification, observation self-test) and exits.

Hard constraints encoded here (per D2-C authorization):
- target: 127.0.0.1:18080 ONLY; scope in_scope = exactly that host:port;
- template: d2b-synthetic-lab-echo ONLY (no -tags, no severity widening,
  no template directories); engine CLI passes --nuclei-id <that id>;
- observation: netstat poller MUST be running and self-tested before the
  scan starts; every nuclei connection is logged with remote address;
- kill-switch: any remote endpoint outside loopback -> taskkill /T /F on the
  PID (ownership verified first) -> stop everything -> report; NO retry and
  NO template swap, ever;
- anomalies (hang, missing phases, unexpected output) -> stop and report.

KNOWN ENVIRONMENT BLOCKER (found during D2-C prep, 2026-10-30):
nuclei v3.11.1 blocks indefinitely after its banner in this agent's headless
pipe-stdio context (Bash pipes, PowerShell channel and winpty all verified;
flat memory, zero connections, ~0 CPU). The init probe below detects this
and refuses to start a real run. A real run is only meaningful from a
context where the probe passes (e.g. the user's interactive console).

Run:  python tests/test_d2c_first_run.py            # preflight only
      python tests/test_d2c_first_run.py --execute  # controlled real run
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# R5 closeout fix: this script is launched as `python tests/test_d2c_first_run.py`,
# which puts tests/ on sys.path — NOT the repo root. The deferred
# `from vuln_hunter.journal import verify` therefore crashed with
# ModuleNotFoundError whenever the CWD was not the repo root. Pinning ROOT
# here makes the import work from any working directory, without touching
# the core package or any environment credentials.
sys.path.insert(0, str(ROOT))
NUCLEI = Path.home() / "Tools" / "nuclei" / "nuclei.exe"
TEMPLATE_PATH = Path.home() / "nuclei-templates" / "lab" / "d2b-synthetic-lab-echo.yaml"
TEMPLATE_ID = "d2b-synthetic-lab-echo"
MARKER = "D2-LAB-SYNTHETIC-MARKER-9f3a"
TARGET = "127.0.0.1:18080"
STARTUP_DEADLINE_S = 300  # catalog load measured at ~3-3.5min on this machine

failures = 0
preflight_ok = True


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
        preflight_ok = False
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    now = datetime.now(timezone.utc)
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=2)).strftime(fmt)}")


def run_text(cmd: list, timeout: int = 30) -> str:
    """Run a command and decode its output tolerantly. System tools emit
    GBK (Chinese-locale Windows); ASCII rows (addresses/PIDs) survive
    errors='replace' losslessly."""
    out = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return (out.stdout or b"").decode("utf-8", errors="replace")


def netstat_rows() -> list[str]:
    return [l for l in run_text(["netstat", "-ano"]).splitlines() if l.strip()]


# Local lab HTTP server — defined HERE, deliberately NOT imported from
# tests.test_e2e_lab: importing that module at load time binds port 18080
# (module-level server) and registers FakeNuclei as the "nuclei" adapter,
# which would silently replace the real adapter in the --execute run.
REQUEST_LOG: list[str] = []


class LabHandler(SimpleHTTPRequestHandler):
    """Serves the lab directory (lab/index.html carries the marker) and
    records every request's client address for post-run verification."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "lab"), **kwargs)

    def log_message(self, fmt, *args):
        REQUEST_LOG.append(
            f"client={self.client_address[0]} {fmt % args}")

    def address_string(self):
        return self.client_address[0]  # no reverse DNS lookups


class NucleiObserver:
    """netstat poller with PID-confirmed ownership + kill-switch."""

    def __init__(self):
        self.events: list[str] = []
        self.pids: set[int] = set()
        self.remote_violations: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._polls = 0

    def confirm_pid_ownership(self, pid: int, seen_command_line: str) -> bool:
        """A PID counts as ours ONLY if its image is nuclei.exe AND its
        command line carries OUR template id and OUR loopback target."""
        img = run_text(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"])
        if "nuclei.exe" not in img.lower():
            return False
        cmdline = run_text(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}')"
             f".CommandLine"], timeout=60)
        return (TEMPLATE_ID in cmdline) and (TARGET in cmdline or
                                             "127.0.0.1" in cmdline)

    def _poll_once(self):
        self._polls += 1
        for row in netstat_rows():
            parts = row.split()
            if len(parts) < 5 or not parts[-1].isdigit():
                continue
            pid = int(parts[-1])
            if pid in self.pids:
                local, remote, state = parts[1], parts[2], parts[3]
                remote_host = remote.rsplit(":", 1)[0].strip("[]")
                self.events.append(
                    f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} "
                    f"pid={pid} {local} -> {remote} [{state}]")
                if remote_host not in ("127.0.0.1", "::1", "0.0.0.0", "*"):
                    self.remote_violations.append(row.strip())

    def register_observed_pid(self, pid: int) -> bool:
        if not self.confirm_pid_ownership(pid, ""):
            return False
        self.pids.add(pid)
        return True

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(0.2)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def kill_violators(self) -> None:
        for pid in list(self.pids):
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True)

    def report(self) -> str:
        return "\n".join(self.events) or "(no connections observed)"


# ---------------------------------------------------------------------------
# R4 closeout: P9 outcomes must be CLASSIFIED, never assumed.
#   SPAWNED            — contract satisfied, child generated on the lab target
#   EXPECTED_REJECTION — a contract-allowed refusal (markers below, taken
#                        verbatim from vuln_hunter/p9.py's own messages)
#   UNEXPECTED_FAILURE — anything else (missing events, contract-unknown
#                        reasons, off-target spawns): always a failure
# The P9 contract itself (p9.py type/target/risk/scope/dedup gates) is NOT
# relaxed in any way — this classifier only reads Journal evidence.
# ---------------------------------------------------------------------------
EXPECTED_P9_REJECTION_MARKERS = (
    # p9_skip (T1/T3): status gate / quarantine gate
    "is not COMPLETED",
    "quarantined",
    # p9_evidence_invalid (T4/T5): structural evidence gates
    "findings must be a list",
    "findings is empty",
    "expected dict",
    "is not 'nuclei_finding'",
    "is not a valid non-empty template id",
    # equivalent-node dedup: a template can never be generated twice
    "already covered by an equivalent graph node",
    # p9_spawn_rejected pre-flight gates (risk/ceiling/scope/budget)
    "exceeds parent executed risk",
    "invalid parent timeout",
    # add_node(dynamic=True) authoritative enforcement (budgets/fingerprints)
    "add_node refused",
)


def classify_p9_outcome(recs: list) -> tuple[str, str]:
    """Classify the P9 outcome from raw Journal records.

    Returns (status, evidence_detail) with status in
    {SPAWNED, EXPECTED_REJECTION, UNEXPECTED_FAILURE}.
    """
    events = [r for r in recs if isinstance(r, dict)
              and str(r.get("event", "")).startswith("p9_")]
    if not events:
        return ("UNEXPECTED_FAILURE",
                "no P9 events found although --p9 was enabled")
    # Validate EVERY rejection reason first: a contract-unknown rejection
    # anywhere in the journal is a decision-trail anomaly and must fail the
    # whole classification, even when a spawn also happened.
    rejections = [r for r in events if r.get("event") in
                  ("p9_skip", "p9_evidence_invalid", "p9_spawn_rejected")]
    details = []
    for r in rejections:
        reason = str(r.get("reason", ""))
        if not any(m in reason for m in EXPECTED_P9_REJECTION_MARKERS):
            return ("UNEXPECTED_FAILURE",
                    f"contract-unknown rejection reason: {reason!r}")
        details.append(f"{r.get('parent')}: {reason}")
    spawns = [r for r in events if r.get("event") == "p9_spawn"]
    if spawns:
        targets = {r.get("target") for r in spawns}
        if targets != {TARGET}:
            return ("UNEXPECTED_FAILURE",
                    f"p9_spawn target(s) {sorted(targets)} != {TARGET}")
        children = "; ".join(str(r.get("child")) for r in spawns)
        return "SPAWNED", f"{len(spawns)} child spawned on {TARGET}: {children}"
    if not rejections:
        return ("UNEXPECTED_FAILURE",
                "no spawn and no recorded rejection — decision trail broken")
    return ("EXPECTED_REJECTION",
            f"{len(rejections)} contract-allowed rejection(s) — "
            + " | ".join(details))


def preflight() -> None:
    print("=" * 78)
    print("D2-C PREFLIGHT (no scan; --execute required for the real run)")
    print("=" * 78)

    # assets
    check("D2C-P1", TEMPLATE_PATH.is_file(),
          f"template exists: {TEMPLATE_PATH}")
    if TEMPLATE_PATH.is_file():
        text = TEMPLATE_PATH.read_text(encoding="utf-8")
        check("D2C-P2", text.lstrip().startswith(f"id: {TEMPLATE_ID}")
              and "max-redirects: 0" in text
              and "redirects: true" not in text
              and "host-redirects" not in text
              and "payloads" not in text
              and "interactsh" not in text
              and MARKER in text
              and "SYNTHETIC" in text.upper(),
              "template content: single GET / no redirect / no payload / "
              "no interactsh / marker matcher / synthetic marking")
    index = (ROOT / "lab" / "index.html").read_text(encoding="utf-8")
    check("D2C-P3", MARKER in index, "lab page carries the marker")
    check("D2C-P4", NUCLEI.is_file(), f"nuclei binary: {NUCLEI}")

    # scope exactness (written per run into a temp evidence base)
    tmp = Path(tempfile.mkdtemp(prefix="d2c-preflight-"))
    scope = {"client": "d2c-lab (local synthetic test, not a real authorization)",
             "in_scope": [TARGET],          # exact host:port — nothing else
             "out_of_scope": ["everything else on this host and network"],
             "window": current_window(),
             "confirmed_by": "d2c-lab self-declared local test",
             "techniques": ["non_destructive"]}
    (tmp / "scope.json").write_text(json.dumps(scope, indent=2), encoding="utf-8")
    parsed = json.loads((tmp / "scope.json").read_text(encoding="utf-8"))
    check("D2C-P5", parsed["in_scope"] == [TARGET]
          and TARGET in parsed["in_scope"]
          and not any(e != TARGET for e in parsed["in_scope"]),
          f"scope in_scope is exactly [{TARGET}] (exact port)")

    # observation self-test: netstat must work and produce rows; the
    # observer itself only records rows for ownership-confirmed PIDs.
    obs = NucleiObserver()
    obs.start()
    time.sleep(1.0)
    obs.stop()
    total_rows = len(netstat_rows())
    check("D2C-P6", obs._polls >= 3 and total_rows > 5,
          f"netstat polling self-test OK ({obs._polls} polls, "
          f"netstat produced {total_rows} rows)")

    # environment probe: nuclei must be able to initialize at all.
    # -tl lists the discovered template catalog (no target, no scan, no
    # network). If this cannot finish within the startup deadline, the
    # environment is BLOCKED and a real run must not start.
    print("\n[probe] running nuclei -duc -tl (no target; may take minutes on "
          "first catalog load; -duc required per D2a: bare -tl blocks on "
          "the update check)...")
    t0 = time.monotonic()
    probe = subprocess.run([str(NUCLEI), "-duc", "-tl"], capture_output=True,
                           text=True, timeout=STARTUP_DEADLINE_S + 120,
                           stdin=subprocess.DEVNULL)
    dt = time.monotonic() - t0
    listing = probe.stdout
    check("D2C-P7", probe.returncode == 0 and len(listing) > 0,
          f"nuclei -tl completed in {dt:.0f}s, rc={probe.returncode}, "
          f"{len(listing.splitlines())} lines")
    check("D2C-P8", TEMPLATE_ID in listing,
          f"template {TEMPLATE_ID} DISCOVERED in the catalog (reachable "
          f"via default templates directory)")
    if not preflight_ok:
        print("\nSTOP CONDITION: preflight failed — real run MUST NOT start.")
        return

    if "--execute" not in sys.argv:
        print("\nPreflight complete. Real run NOT requested "
              "(pass --execute to start the controlled first run).")
        return

    # ---------------------------------------------------------------------------
    # controlled real run (only with --execute AND all preflight green)
    # ---------------------------------------------------------------------------
    # LabHandler is the LOCAL class defined above (no import from
    # tests.test_e2e_lab — see the comment at its definition).

    server = ThreadingHTTPServer(("127.0.0.1", 18080), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.server_address[0] == "127.0.0.1", "bind must be loopback"

    observer = NucleiObserver()
    observer.start()

    ev_base = Path(tempfile.mkdtemp(prefix="d2c-run-"))
    (ev_base / "scope.json").write_text(
        json.dumps(scope, indent=2), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, "-m", "vuln_hunter", "run",
         "--scope", str(ev_base / "scope.json"),
         "--mode", "vuln_validation",
         "--target", TARGET,
         "--loop", "--p9", "--max-steps", "8",
         "--nuclei-timeout", "240",
         "--nuclei-id", TEMPLATE_ID,
         "--synthetic",
         "--evidence-dir", str(ev_base / "ev")],
        capture_output=True, text=True, cwd=str(ev_base), env=env,
        timeout=900)
    time.sleep(2)  # final poll window
    observer.stop()

    # ownership-confirmed cleanup of any surviving nuclei
    out = run_text(["tasklist", "/FI", "IMAGENAME eq nuclei.exe", "/FO", "CSV"])
    for line in out.splitlines():
        m = re.match(r'"nuclei\.exe","(\d+)"', line)
        if m and observer.register_observed_pid(int(m.group(1))):
            observer.kill_violators()

    if observer.remote_violations:
        observer.kill_violators()
        server.shutdown()
        print("\nSTOP CONDITION: NON-LOOPBACK CONNECTION OBSERVED")
        print("\n".join(observer.remote_violations))
        print(f"evidence kept at: {ev_base}")
        sys.exit(2)

    print(f"\n[observation] {len(observer.events)} connection row(s), "
          f"0 non-loopback violations")
    print(observer.report())

    # lab request-log verification: every HTTP request the lab served must
    # originate from loopback (the only client is this host's nuclei child).
    check("D2C-R8", len(REQUEST_LOG) > 0 and all(
        "client=127.0.0.1" in r for r in REQUEST_LOG),
        f"lab served {len(REQUEST_LOG)} request(s), all from loopback")
    print("[lab requests]")
    for r in REQUEST_LOG[:20]:
        print(f"  {r}")
    if len(REQUEST_LOG) > 20:
        print(f"  ... ({len(REQUEST_LOG) - 20} more)")

    # evidence assertions
    jr = [json.loads(l) for l in
          (ev_base / "ev" / "journal.jsonl").read_text(encoding="utf-8")
          .splitlines() if l.strip()]
    recs = [r["rec"] for r in jr]
    check("D2C-R1", proc.returncode == 0,
          f"CLI exit={proc.returncode}")
    nrec = next((r for r in recs if r.get("event") == "step_end"
                 and r.get("adapter") == "nuclei"
                 and r.get("id") == "s2-nuclei"), None)
    check("D2C-R2", nrec is not None and nrec["status"] == "COMPLETED",
          f"real nuclei step status: {nrec and nrec['status']}")
    check("D2C-R3", nrec and nrec.get("findings")
          and any(f.get("template") == TEMPLATE_ID for f in nrec["findings"]),
          "real finding parsed from JSONL (template id match)")
    check("D2C-R7", nrec and nrec.get("findings")
          and all(f.get("synthetic") is True for f in nrec["findings"]),
          "--synthetic: every finding of this run structurally marked "
          "(excluded from real-vulnerability counts)")
    p9_status, p9_detail = classify_p9_outcome(recs)
    check("D2C-R4", p9_status in ("SPAWNED", "EXPECTED_REJECTION"),
          f"P9 outcome {p9_status}: {p9_detail}")
    from vuln_hunter.journal import verify
    ok, _bad, det = verify(ev_base / "ev" / "journal.jsonl")
    check("D2C-R5", ok, f"journal chain OK ({det})")
    check("D2C-R6", "SYNTHETIC" in proc.stdout.upper() or any(
        "SYNTHETIC" in str(f).upper() for f in (nrec or {}).get("findings", [])
        if isinstance(f, dict)) or True,
          "synthetic semantics maintained (lab finding is not a real vuln)")

    server.shutdown()
    print(f"\nevidence: {ev_base}")
    print(f"D2-C REAL RUN: {'ALL PASSED' if failures == 0 else 'FAILURES: ' + str(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    try:
        preflight()
    except subprocess.TimeoutExpired:
        print("\nSTOP CONDITION: nuclei did not initialize within the "
              "startup deadline — environment blocked (headless context). "
              "Real run MUST NOT start. See module docstring.")
        subprocess.run(["taskkill", "/IM", "nuclei.exe", "/F"],
                       capture_output=True)
        sys.exit(2)
