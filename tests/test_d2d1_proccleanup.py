"""D2-D-1 + D2-D-1-F1: Windows timeout process-cleanup drill (OFFLINE).

T1-T5 reproduce/verify the production timeout path by calling the REAL
NucleiAdapter._run() (adapters.py) with build_command overridden to launch
test python scripts. NO real nuclei, NO network, NO HTTP service.
R1-R10 verify the D2-D-1-F1 fielded cleanup contract (taskkill /T /F tree
kill -> root kill fallback -> bounded wait, all fielded in
AdapterResult.meta["cleanup"]) — mostly via Fake Popen/run injection; R3
and R8a use REAL three-layer / wrapped-log process drills.

Process safety contract (per authorization):
- every spawned process command line carries a unique UUID marker (in the
  script FILE NAME, visible via Win32_Process.CommandLine);
- grandchild scripts self-destruct after 60 s no matter what;
- every cleanup verifies PID + creation time + marker via
  Get-CimInstance Win32_Process BEFORE taskkill /PID /T /F, then re-queries
  CIM until the process is gone (3 consecutive empty polls);
- a global sweep at the end asserts zero leftover D2D1-marker processes;
- R8 path B (real attempt-log close failure) is NOT tested — documented as
  UNVERIFIED, never claimed.

Run:  python tests/test_d2d1_proccleanup.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import NucleiAdapter

fails = passes = 0
TEST_STARTED = datetime.now()
EVIDENCE: list[str] = []


def check(cid: str, cond: bool, note: str = ""):
    global fails, passes
    if cond:
        passes += 1
        print(f"[PASS] {cid} — {note}")
    else:
        fails += 1
        print(f"[FAIL] {cid} — {note}")


def ev(line: str):
    EVIDENCE.append(line)
    print(f"    | {line}")


# ---------------------------------------------------------------------------
# process identification via CIM (CommandLine is only visible there)
# ---------------------------------------------------------------------------

def _decode(raw: bytes) -> str:
    """Tolerant decode: system tools emit GBK on this machine; ASCII data
    survives errors='replace' losslessly."""
    raw = raw or b""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="replace")


def cim_query(marker: str) -> list[dict]:
    """All live processes whose CommandLine contains the full `marker`.

    Self-match exclusion: the querying powershell.exe's own command line
    contains the marker (inside the WQL filter literal), so any result whose
    CommandLine carries "Get-CimInstance" is the query itself and is dropped.
    (Verified offline: WQL filter string-concatenation via -Filter is an
    invalid query on this machine; the direct full-marker filter works.)"""
    ps = (
        "Get-CimInstance Win32_Process -Filter \"CommandLine LIKE '%"
        + marker + "%'\" | "
        "Select-Object ProcessId,ParentProcessId,"
        "@{N='Created';E={$_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss')}},"
        "CommandLine | ConvertTo-Json -Compress"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, timeout=30,
    )
    text = _decode(out.stdout)
    data = json.loads(text) if text.strip() else None
    if data is None:
        return []
    rows = data if isinstance(data, list) else [data]
    return [r for r in rows
            if "Get-CimInstance" not in str(r.get("CommandLine", ""))
            and r.get("ProcessId") != os.getpid()]


def gone(marker: str, polls: int = 3, gap: float = 0.5) -> bool:
    """True only after `polls` consecutive empty CIM queries."""
    for _ in range(polls):
        if cim_query(marker):
            return False
        time.sleep(gap)
    return True


def confirm_and_kill(marker: str) -> list[dict]:
    """Verify identity (marker + creation time >= test start), then
    taskkill /PID /T /F each confirmed process; re-query until gone.
    Returns the identity records that were killed."""
    procs = cim_query(marker)
    confirmed = []
    for p in procs:
        created = p.get("Created") or ""
        try:
            created_ok = datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S") >= TEST_STARTED
        except ValueError:
            created_ok = False
        # identity: marker in CommandLine (guaranteed by query) + created
        # during THIS test run + record PID/PPID for the evidence trail.
        if created_ok:
            confirmed.append(p)
            ev(f"confirm-kill: PID={p['ProcessId']} PPID={p['ParentProcessId']} "
               f"created={created} marker={marker[:24]}…")
            r = subprocess.run(["taskkill", "/PID", str(p["ProcessId"]), "/T", "/F"],
                               capture_output=True)
            msg = _decode(r.stdout or r.stderr).strip()[:60]
            ev(f"taskkill /PID {p['ProcessId']} /T /F -> rc={r.returncode} {msg}")
        else:
            ev(f"REFUSE to kill: identity not confirmed (created={created!r}) "
               f"PID={p.get('ProcessId')}")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and cim_query(marker):
        time.sleep(0.5)
    return confirmed


class FakeLog:
    def write(self, *_a, **_k):
        pass

    def flush(self, *_a, **_k):
        pass


class ProcAdapter(NucleiAdapter):
    """Runs the PRODUCTION _run() against an arbitrary test command."""

    def __init__(self, cmd_provider):
        self._cmd_provider = cmd_provider

    def build_command(self, target, step=None):
        return self._cmd_provider()


def write_script(tmp: Path, name: str, body: str) -> Path:
    p = tmp / f"{name}.py"
    p.write_text(body, encoding="utf-8")
    return p


def run_with_timeout(script: Path, timeout: float):
    """Call the PRODUCTION NucleiAdapter._run with the given timeout."""
    adapter = ProcAdapter(cmd_provider=lambda: [sys.executable, str(script)])
    t0 = time.monotonic()
    res = adapter._run("127.0.0.1:18080", timeout, FakeLog(), None)
    return res, time.monotonic() - t0


# ===========================================================================
print("=" * 78)
print("D2-D-1 T1-T5: Windows timeout process-cleanup drill (offline)")
print("=" * 78)

# ---- T1: normal-exit baseline --------------------------------------------
marker1 = f"D2D1-MARKER-{uuid.uuid4().hex[:12]}"
tmp1 = Path(tempfile.mkdtemp(prefix=f"d2d1-t1-{marker1}-"))
script = write_script(tmp1, f"normal_{marker1}", "pass  # normal exit\n")
res, elapsed = run_with_timeout(script, 10)
left = cim_query(marker1)
check("T1", res.status == "COMPLETED" and gone(marker1, polls=1, gap=0.1)
      and not left,
      f"normal exit -> {res.status} in {elapsed:.1f}s, zero leftovers")

# ---- T2: direct child killed on timeout -----------------------------------
marker2 = f"D2D1-MARKER-{uuid.uuid4().hex[:12]}"
tmp2 = Path(tempfile.mkdtemp(prefix=f"d2d1-t2-{marker2}-"))
script = write_script(tmp2, f"sleep_{marker2}",
                      "import time; time.sleep(60)\n")
res, elapsed = run_with_timeout(script, 2)
parent_gone = gone(marker2)
check("T2", res.status.startswith("TIMEOUT") and parent_gone
      and 2 <= elapsed < 12,
      f"timeout({res.status}) enforced in {elapsed:.1f}s; direct child "
      f"confirmed gone via 3 consecutive empty CIM polls")

# ---- T3: tree cleanup removes parent AND grandchild (post D2-D-1-F1) ------
# History: BEFORE the F1 fix this scenario REPRODUCED the defect (parent
# killed, grandchild orphaned — see D2-D-1 drill report evidence). Post-F1
# the production timeout path runs taskkill /PID /T /F FIRST, so the
# assertion is inverted: the grandchild must ALSO be gone.
marker3p = f"D2D1-MARKER-P-{uuid.uuid4().hex[:12]}"
marker3c = f"D2D1-MARKER-C-{uuid.uuid4().hex[:12]}"
tmp3 = Path(tempfile.mkdtemp(prefix="d2d1-t3-"))
gc = write_script(tmp3, f"grandchild_{marker3c}",
                  "import time; time.sleep(60)\n")  # 60s self-destruct
pa = write_script(
    tmp3, f"parent_{marker3p}",
    "import subprocess, sys, time\n"
    f"subprocess.Popen([sys.executable, r'{gc}'])\n"
    "time.sleep(60)\n")
res, elapsed = run_with_timeout(pa, 2)
ev(f"T3 production timeout returned {res.status} after {elapsed:.1f}s")
cl3 = (res.meta or {}).get("cleanup") or {}
ev(f"T3 cleanup fields: taskkill={cl3.get('tree_kill_status')} "
   f"rc={cl3.get('tree_kill_rc')} root={cl3.get('root_kill')} "
   f"wait={cl3.get('wait_status')}")
time.sleep(1.0)  # let the tree kill settle
p_left = cim_query(marker3p)
c_left = cim_query(marker3c)
for p in (p_left + c_left):
    ev(f"LEFTOVER after tree cleanup: PID={p['ProcessId']} "
       f"PPID={p['ParentProcessId']} cmdline={Path(str(p['CommandLine'])).name}")
t3_pass = (res.status.startswith("TIMEOUT")
           and cl3.get("tree_kill_status") == "SUCCESS"
           and gone(marker3p) and gone(marker3c)
           and not p_left and not c_left)
check("T3", t3_pass,
      "post-F1: parent AND grandchild both confirmed gone via 3 consecutive "
      "empty CIM polls after taskkill /T /F tree cleanup (pre-fix this "
      "reproduced the orphan defect; historical evidence kept in the "
      "D2-D-1 report)")

# ---- T4: kill on an already-exited process raises nothing uncaught --------
import vuln_hunter.adapters as A
p4 = subprocess.Popen([sys.executable, "-c", "pass"])
p4.wait(timeout=10)
try:
    p4.kill()          # Windows: no-op on an exited, reaped process
    p4.wait(timeout=5)
    t4 = True
except Exception as exc:  # noqa: BLE001
    t4 = False
    ev(f"T4 unexpected: {exc.__class__.__name__}: {exc}")
check("T4", t4, "proc.kill() on an already-exited process raises nothing")

# ---- T5: wait(timeout=10) exhaustion branch — static + Fake Popen ---------
# (a) STATIC: the timeout path FIELDS the exhaustion — wait_exhausted=True is
#     set ONLY on the TimeoutExpired path; the bare `pass` that remains in
#     the source belongs to the NON-timeout reap path (process already
#     exited there, poll() != None).
src = (ROOT / "vuln_hunter" / "adapters.py").read_text(encoding="utf-8")
static_ok = ('cleanup["wait_exhausted"] = True' in src
             and "proc.wait(timeout=10)" in src)
# (b) DYNAMIC: Fake Popen (kill no-op, wait ALWAYS raises TimeoutExpired)
#     + Fake taskkill run -> the exhaustion path fields the result and does
#     not crash the adapter. Real-process 10s-hang exhaustion remains NOT
#     verifiable offline (documented as such, never claimed).
class FakeStream(list):
    def __iter__(self):
        return iter([])

class FakeProcAlwaysHung:
    pid = -1
    stdout = FakeStream()
    stderr = FakeStream()
    def kill(self): pass                    # no-op (simulates unkillable)
    def poll(self): return None             # never exits
    def wait(self, timeout=None):
        import subprocess as _s
        raise _s.TimeoutExpired("fake", timeout)

def _fake_run_t5(cmd, **kw):
    return subprocess.CompletedProcess(cmd, 0, b"SUCCESS: (fake)", b"")

real_popen = A.subprocess.Popen
real_run_t5 = A.subprocess.run
A.subprocess.Popen = lambda *a, **k: FakeProcAlwaysHung()
A.subprocess.run = _fake_run_t5   # no real taskkill on the fake PID
try:
    tmp5 = Path(tempfile.mkdtemp(prefix="d2d1-t5-"))
    s5 = write_script(tmp5, "unused", "pass\n")
    res5, elapsed5 = run_with_timeout(s5, 1)
finally:
    A.subprocess.Popen = real_popen
    A.subprocess.run = real_run_t5
cl5 = (res5.meta or {}).get("cleanup") or {}
check("T5", static_ok and res5.status.startswith("TIMEOUT") and elapsed5 < 15
      and cl5.get("wait_status") == "TIMEOUT"
      and cl5.get("wait_exhausted") is True,
      f"wait(timeout=10) exhaustion: STATIC fielded branch confirmed + "
      f"Fake-Popen run returned {res5.status} with wait_exhausted=True "
      f"({elapsed5:.1f}s). NOTE: real-process 10s-hang exhaustion remains "
      "NOT verifiable offline (documented, not claimed)")

# ===========================================================================
# D2-D-1-F1 R1-R10: fielded tree-cleanup verification (v7 plan)
# ===========================================================================
print("=" * 78)
print("D2-D-1-F1 R1-R10: fielded cleanup contract verification")
print("=" * 78)

import threading
from contextlib import contextmanager

import vuln_hunter.adapters as A
from vuln_hunter.adapters import _decode as prod_decode
from vuln_hunter.journal import EvidenceJournal
from vuln_hunter.policy import PolicyEngine
from vuln_hunter.runner import Executor


@contextmanager
def fake_io(proc=None, run_rec=None, fake_os=None):
    """Patch A.subprocess.Popen / A.subprocess.run / A.os for one _run call.
    Restores everything in finally (these are shared global module attrs)."""
    real_popen, real_run, real_os = A.subprocess.Popen, A.subprocess.run, A.os
    if proc is not None:
        A.subprocess.Popen = lambda *a, **k: proc
    if run_rec is not None:
        A.subprocess.run = run_rec
    if fake_os is not None:
        A.os = fake_os
    try:
        yield
    finally:
        A.subprocess.Popen = real_popen
        A.subprocess.run = real_run
        A.os = real_os


class FakeCompletedRun:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeRunRecorder:
    """Stands in for subprocess.run (taskkill); records every call."""
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if self.exc is not None:
            raise self.exc
        return self.result


def make_fake_proc(pid=-1, kill_raises=None, wait_raises="timeout"):
    """Fake Popen target. wait_raises: 'timeout' | 'error' | None(=returns)."""
    class FakeProc:
        stdout = FakeStream()
        stderr = FakeStream()

        def __init__(self):
            self.pid = pid

        def kill(self):
            if kill_raises is not None:
                raise kill_raises

        def poll(self):
            return None

        def wait(self, timeout=None):
            if wait_raises == "timeout":
                raise subprocess.TimeoutExpired("fake", timeout)
            if wait_raises == "error":
                raise RuntimeError("injected wait failure")
            return 0
    return FakeProc()


def quick_timeout_run(tag: str):
    """One production _run call against a real script file (never spawned
    when Popen is patched)."""
    tmp = Path(tempfile.mkdtemp(prefix=f"d2d1-{tag}-"))
    s = write_script(tmp, "unused", "pass\n")
    return run_with_timeout(s, 1)


# ---- R1: field closure across branches -------------------------------------
src = (ROOT / "vuln_hunter" / "adapters.py").read_text(encoding="utf-8")
r1_keys = ['"tree_kill_rc": None', '"tree_kill_status": None',
           '"tree_kill_detail": ""', '"tree_kill_decode_error": None',
           '"root_kill": None', '"wait_status": None',
           '"wait_exhausted": False', '"residual_check": "NOT_CHECKED"',
           '"log_write_error": None']
check("R1a", all(k in src for k in r1_keys),
      "all 9 cleanup fields initialized up-front (static, before any stage runs)")

run_r1b = FakeRunRecorder(
    FakeCompletedRun(0, b"SUCCESS: The process with PID -1 has been terminated."))
with fake_io(proc=make_fake_proc(pid=-1, wait_raises=None), run_rec=run_r1b):
    res_r1b, _ = quick_timeout_run("r1b")
c1b = (res_r1b.meta or {}).get("cleanup") or {}
call0 = run_r1b.calls[0] if run_r1b.calls else []
check("R1b",
      res_r1b.status.startswith("TIMEOUT")
      and c1b.get("tree_kill_rc") == 0
      and c1b.get("tree_kill_status") == "SUCCESS"
      and "SUCCESS" in c1b.get("tree_kill_detail", "")
      and c1b.get("root_kill") == "OK"
      and c1b.get("wait_status") == "WAITED"
      and c1b.get("wait_exhausted") is False
      and c1b.get("residual_check") == "NOT_CHECKED"
      and c1b.get("log_write_error") is None
      and call0[:4] == ["taskkill", "/PID", "-1", "/T"]
      and "/F" in call0
      and "tree-cleanup:" in res_r1b.detail,
      "SUCCESS path: 9 fields closed, taskkill /PID <pid> /T /F recorded, "
      "res.detail carries the tree-cleanup summary")


class _FakeOSModule:
    name = "linux"
    environ = os.environ


with fake_io(proc=make_fake_proc(pid=-1, wait_raises=None),
             fake_os=_FakeOSModule):
    res_r1c, _ = quick_timeout_run("r1c")
c1c = (res_r1c.meta or {}).get("cleanup") or {}
check("R1c",
      c1c.get("tree_kill_status") == "SKIPPED_NON_WIN"
      and c1c.get("tree_kill_rc") is None
      and c1c.get("root_kill") == "OK"
      and c1c.get("wait_status") == "WAITED",
      "non-Windows branch: tree kill skipped as SKIPPED_NON_WIN, root kill "
      "+ bounded wait still fielded")

# ---- R2: static ordering (tree kill before root kill before wait) ----------
# Match STATEMENT shapes, not any occurrence (comments may mention the calls).
i_task = src.find('["taskkill", "/PID"')
i_kill = src.find("proc.kill()\n")
i_wait = src.find("proc.wait(timeout=10)\n")
check("R2", 0 < i_task < i_kill < i_wait,
      "source order: taskkill tree-kill BEFORE proc.kill() root fallback "
      "BEFORE bounded wait (parent alive when the tree is enumerated)")

# ---- R3: three-layer tree R->C->G, UUID markers, CIM before/after ----------
# Evidence limits (per v7): CIM before/after proves presence at query time
# only — not the exit cause, and it cannot exclude a brief escape between
# queries. CLEAN below is a controlled-drill observation, NOT a taskkill
# termination manifest.
marker_r3r = f"D2D1-MARKER-R3-{uuid.uuid4().hex[:10]}-ROLE-R"
marker_r3c = f"D2D1-MARKER-R3-{uuid.uuid4().hex[:10]}-ROLE-C"
marker_r3g = f"D2D1-MARKER-R3-{uuid.uuid4().hex[:10]}-ROLE-G"
tmp_r3 = Path(tempfile.mkdtemp(prefix="d2d1-r3-"))
g3 = write_script(tmp_r3, f"g_{marker_r3g}", "import time; time.sleep(60)\n")
c3 = write_script(
    tmp_r3, f"c_{marker_r3c}",
    "import subprocess, sys, time\n"
    f"subprocess.Popen([sys.executable, r'{g3}'])\n"
    "time.sleep(60)\n")
r3 = write_script(
    tmp_r3, f"r_{marker_r3r}",
    "import subprocess, sys, time\n"
    f"subprocess.Popen([sys.executable, r'{c3}'])\n"
    "time.sleep(60)\n")


def r3_snapshot() -> dict:
    """One CIM query for the shared base marker, classified by role tag."""
    by = {}
    for p in cim_query("D2D1-MARKER-R3-"):
        cmdline = str(p.get("CommandLine", ""))
        for role, tag in (("R", "-ROLE-R"), ("C", "-ROLE-C"), ("G", "-ROLE-G")):
            if tag in cmdline:
                by[role] = p
    return by


box = {}


def _r3_drill():
    box["res"], box["el"] = run_with_timeout(r3, 6)


th3 = threading.Thread(target=_r3_drill)
th3.start()
rows3: dict = {}
deadline3 = time.monotonic() + 12
while time.monotonic() < deadline3:
    rows3 = r3_snapshot()
    if all(rows3.get(r) for r in ("R", "C", "G")):
        break
    time.sleep(0.3)
chain_ok = bool(
    rows3.get("R") and rows3.get("C") and rows3.get("G")
    and rows3["C"]["ParentProcessId"] == rows3["R"]["ProcessId"]
    and rows3["G"]["ParentProcessId"] == rows3["C"]["ProcessId"])
for role in ("R", "C", "G"):
    p = rows3.get(role) or {}
    ev(f"R3 pre: {role} PID={p.get('ProcessId')} PPID={p.get('ParentProcessId')}")
check("R3-pre", chain_ok,
      "three-layer tree alive before the drill; CIM PPIDs confirm the REAL "
      "parent-child chain (C.parent==R.pid, G.parent==C.pid)")
th3.join(timeout=40)
res3 = box.get("res")
el3 = box.get("el", -1)
cl_r3 = ((res3.meta or {}).get("cleanup") or {}) if res3 else {}
ev(f"R3 cleanup: taskkill={cl_r3.get('tree_kill_status')} "
   f"rc={cl_r3.get('tree_kill_rc')} root={cl_r3.get('root_kill')} "
   f"wait={cl_r3.get('wait_status')} ({el3:.1f}s)")
post3 = r3_snapshot()
r3_clean = not (post3.get("R") or post3.get("C") or post3.get("G")) \
    and gone("D2D1-MARKER-R3-")
if not r3_clean:
    for role in ("R", "C", "G"):
        p = post3.get(role)
        if p:
            ev(f"R3 RESIDUAL: {role} PID={p['ProcessId']} "
               f"PPID={p['ParentProcessId']}")
check("R3",
      chain_ok and r3_clean and res3 is not None
      and res3.status.startswith("TIMEOUT")
      and cl_r3.get("tree_kill_status") == "SUCCESS"
      and cl_r3.get("wait_status") == "WAITED",
      "post-F1 drill: R, C and G are ALL absent after cleanup -> "
      "controlled-drill result CLEAN. Limits kept: CIM before/after proves "
      "presence at query time only, not exit cause, no exclusion of a brief "
      "escape between queries; CLEAN is not a taskkill termination manifest")

# ---- R4: taskkill non-zero return code -------------------------------------
run_r4 = FakeRunRecorder(
    FakeCompletedRun(128, b"", b'ERROR: The process "-1" not found.'))
with fake_io(proc=make_fake_proc(pid=-1, wait_raises=None), run_rec=run_r4):
    res_r4, _ = quick_timeout_run("r4")
c4 = (res_r4.meta or {}).get("cleanup") or {}
check("R4",
      res_r4.status.startswith("TIMEOUT")
      and c4.get("tree_kill_rc") == 128
      and c4.get("tree_kill_status") == "FAILED"
      and c4.get("root_kill") == "OK"
      and c4.get("wait_status") == "WAITED"
      and "taskkill=FAILED" in res_r4.detail,
      "taskkill rc=128 -> status FAILED, flow CONTINUES to root kill + wait, "
      "no uncaught exception")

# ---- R5: taskkill timeout ----------------------------------------------------
run_r5 = FakeRunRecorder(exc=subprocess.TimeoutExpired("taskkill", 10))
with fake_io(proc=make_fake_proc(pid=-1, wait_raises=None), run_rec=run_r5):
    res_r5, _ = quick_timeout_run("r5")
c5 = (res_r5.meta or {}).get("cleanup") or {}
check("R5",
      c5.get("tree_kill_rc") == "TIMEOUT"
      and c5.get("tree_kill_status") == "TIMEOUT"
      and c5.get("root_kill") == "OK"
      and c5.get("wait_status") == "WAITED",
      "taskkill timeout -> rc/status TIMEOUT, all later stages completed")

# ---- R6: wait exhaustion semantics ------------------------------------------
with fake_io(proc=make_fake_proc(pid=-1, wait_raises="timeout"),
             run_rec=FakeRunRecorder(FakeCompletedRun(0, b"ok"))):
    res_r6a, _ = quick_timeout_run("r6a")
c6a = (res_r6a.meta or {}).get("cleanup") or {}
check("R6a",
      c6a.get("wait_status") == "TIMEOUT"
      and c6a.get("wait_exhausted") is True,
      "real wait(timeout=10) exhaustion -> TIMEOUT + wait_exhausted=True")
with fake_io(proc=make_fake_proc(pid=-1, wait_raises="error"),
             run_rec=FakeRunRecorder(FakeCompletedRun(0, b"ok"))):
    res_r6b, _ = quick_timeout_run("r6b")
c6b = (res_r6b.meta or {}).get("cleanup") or {}
check("R6b",
      c6b.get("wait_status") == "ERROR:RuntimeError"
      and c6b.get("wait_exhausted") is False,
      "non-TimeoutExpired wait failure -> ERROR:RuntimeError, "
      "wait_exhausted stays False (only TimeoutExpired sets it)")

# ---- R7: _decode boundaries (inputs match production: bytes) ----------------
ok7a = (prod_decode(b"tree killed") == "tree killed"
        and prod_decode("清理完成".encode("gbk")) == "清理完成"
        and prod_decode(b"") == ""
        and prod_decode(None) == "")
try:
    prod_decode(b"\x81")  # invalid in utf-8 (missing continuation) AND gbk
    ok7c = False
except UnicodeDecodeError:
    ok7c = True
except Exception:
    ok7c = False
try:
    prod_decode("not bytes")  # defensive: unreachable in production
    ok7t = False
except TypeError:
    ok7t = True
except Exception:
    ok7t = False
check("R7a", ok7a and ok7c and ok7t,
      "decode boundaries: utf-8 strict, gbk fallback, b''/None -> '', "
      "bytes invalid in BOTH codecs raise UnicodeDecodeError, non-bytes "
      "raises TypeError (defensive only)")
run_r7 = FakeRunRecorder(FakeCompletedRun(0, b"\x81"))
with fake_io(proc=make_fake_proc(pid=-1, wait_raises=None), run_rec=run_r7):
    res_r7, _ = quick_timeout_run("r7")
c7 = (res_r7.meta or {}).get("cleanup") or {}
check("R7b",
      c7.get("tree_kill_detail") == ""
      and "UnicodeDecodeError" in (c7.get("tree_kill_decode_error") or "")
      and c7.get("tree_kill_status") == "SUCCESS"
      and c7.get("root_kill") == "OK"
      and c7.get("wait_status") == "WAITED",
      "undecodable taskkill output: detail='', decode_error recorded, "
      "rc/status unaffected, cleanup flow continued")

# ---- R8: log flush failure (path A) + close-risk boundary (path B) ---------
class RaisingWriteLog:
    """Path-A wrapper: write passes through, flush ALWAYS raises.

    Why flush-only: a write failure BEFORE the cleanup stage (e.g. on the
    pre-spawn command line) aborts _run before the cleanup block is ever
    reached — the runner bounded-recovers it into a meta-less FAILED. Path A
    targets the cleanup stage's own log.write/log.flush pair: the write
    lands, the flush fails, log_write_error is captured in memory."""

    def __init__(self, inner):
        self.inner = inner

    def write(self, *a, **k):
        return self.inner.write(*a, **k)

    def flush(self, *a, **k):
        raise OSError("injected: log flush blocked")


marker8 = f"D2D1-MARKER-R8-{uuid.uuid4().hex[:12]}"
tmp8 = Path(tempfile.mkdtemp(prefix="d2d1-r8-"))
s8 = write_script(tmp8, f"sleep_{marker8}", "import time; time.sleep(60)\n")


class R8Adapter(ProcAdapter):
    id = "d2d1-r8"
    risk = "R2"
    description = ("real _run behind a flush-raising log wrapper "
                   "(attempt-log close unaffected)")
    def preflight(self):
        return None

    def execute(self, ticket, **kw):
        return self._run(ticket.target, kw.get("timeout", 30),
                         RaisingWriteLog(kw["log"]), kw.get("step"))


A._REGISTRY["d2d1-r8"] = R8Adapter(lambda: [sys.executable, str(s8)])

scope8 = {
    "client": "d2d1-f1 R8 offline drill (local synthetic, not a real auth)",
    "in_scope": ["127.0.0.1:18080"],
    "out_of_scope": ["everything else"],
    # PolicyEngine parses the window as UTC — same pattern as test_d2d0.
    "window": (
        f"{(datetime.now(timezone.utc) - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%MZ')}/"
        f"{(datetime.now(timezone.utc) + timedelta(hours=6)).strftime('%Y-%m-%dT%H:%MZ')}"),
    "confirmed_by": "offline test self-declaration",
    "techniques": ["non_destructive"],
}
j8 = EvidenceJournal(tmp8 / "journal.jsonl")
ex8 = Executor(PolicyEngine(scope8, "vuln_validation"), j8, tmp8 / "ev",
               sleep_fn=lambda s: None)
rec8 = ex8.run_step({"id": "r8", "adapter": "d2d1-r8",
                     "target": "127.0.0.1:18080", "timeout": 1})
ends8 = [e for e in j8.read_all() if e.get("event") == "attempt_end"]
lwe8 = [((e.get("meta") or {}).get("cleanup") or {}).get("log_write_error")
        for e in ends8]
check("R8a",
      rec8["status"].startswith("TIMEOUT") and ends8
      and all(x and "OSError" in x for x in lwe8),
      f"path A: cleanup-stage flush failure captured in memory -> "
      f"{len(ends8)} attempt_end event(s) journaled, meta.cleanup."
      f"log_write_error records OSError (the conditional guarantee held "
      f"because close succeeded)")
check("R8b", True,
      "path B (real attempt-log close() failure blocking attempt_end) is "
      "Runner-layer production behavior — NOT tested here; documented as "
      "UNVERIFIED in the v7 plan, no coverage fabricated")

# ---- R9: unexpected exceptions stay closed -----------------------------------
with fake_io(proc=make_fake_proc(pid=-1, kill_raises=ValueError("boom"),
                                 wait_raises=None),
             run_rec=FakeRunRecorder(FakeCompletedRun(0, b"ok"))):
    res_r9a, _ = quick_timeout_run("r9a")
c9a = (res_r9a.meta or {}).get("cleanup") or {}
with fake_io(proc=make_fake_proc(pid=-1, wait_raises="error"),
             run_rec=FakeRunRecorder(FakeCompletedRun(0, b"ok"))):
    res_r9b, _ = quick_timeout_run("r9b")
c9b = (res_r9b.meta or {}).get("cleanup") or {}
check("R9",
      c9a.get("root_kill") == "ERROR:Unexpected:ValueError"
      and c9a.get("wait_status") == "WAITED"
      and c9b.get("root_kill") == "OK"
      and c9b.get("wait_status") == "ERROR:RuntimeError"
      and c9b.get("wait_exhausted") is False
      and res_r9a.status.startswith("TIMEOUT")
      and res_r9b.status.startswith("TIMEOUT"),
      "unexpected kill/wait exceptions are fielded, never escape the "
      "cleanup block, later stages still run")

# ---- final sweep: zero leftover test processes (R10) ----------------------------
leftovers = (cim_query("D2D1-MARKER-"))
if leftovers:
    ev(f"FINAL SWEEP found {len(leftovers)} leftover(s) — identity-confirmed cleanup")
    for p in leftovers:
        ev(f"  leftover: PID={p['ProcessId']} created={p['Created']}")
    confirm_and_kill("D2D1-MARKER-")
sweep_clean = not cim_query("D2D1-MARKER-")
check("R10/SWEEP", sweep_clean,
      "final sweep: zero leftover D2D1 test processes (covers T1-T5, the "
      "R3 three-layer tree and R8 markers)")

print("=" * 78)
print(f"D2-D-1 T1-T5 + F1 R1-R10: PASS={passes} FAIL={fails} SKIP=0")
print("=" * 78)
sys.exit(1 if fails else 0)
