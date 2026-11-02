"""P0-1 gate regression tests: the adapter layer must refuse execution on
EVERY path that lacks a valid RunTicket + live policy.

Run:  python tests/test_adapters_gate.py
Exits 0 only when every negative case is blocked as expected.
"""
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import (  # noqa: E402
    GateRequired, HTTPProbeAdapter, NucleiAdapter,
)
from vuln_hunter.journal import EvidenceJournal  # noqa: E402
from vuln_hunter.policy import PolicyEngine, PolicyRefusal, RunTicket  # noqa: E402
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
    d = {"client": "gate-test", "in_scope": ["127.0.0.1"],
         "out_of_scope": ["none"], "window": current_window(),
         "confirmed_by": "gate-test"}
    d.update(kw)
    return d


def make_policy(**kw) -> PolicyEngine:
    return PolicyEngine(base_scope(**kw), "safe_scan")


class NullLog:
    def write(self, *_a, **_k):
        return None


PROBE = HTTPProbeAdapter()
NUCLEI = NucleiAdapter()  # instantiated directly; still cannot run without a ticket
POLICY = make_policy()
NO_LOG = NullLog()


def quiet_journal() -> EvidenceJournal:
    return EvidenceJournal(Path(tempfile.mkdtemp()) / "j.jsonl")


# ---- G-01 bare-target call: no ticket argument at all -----------------------
try:
    PROBE.execute("127.0.0.1:8080", timeout=5, log=NO_LOG)  # type: ignore[call-arg]
    check("G-01", False, "bare-target call ran without a ticket (GATE BYPASS!)")
except TypeError:
    check("G-01", True, "bare-target call rejected by signature (ticket required)")
except GateRequired:
    check("G-01", True, "bare-target call rejected with GateRequired")

# ---- G-02 get_adapter without policy ---------------------------------------
from vuln_hunter.adapters import get_adapter  # noqa: E402

try:
    get_adapter("http_probe", None)
    check("G-02", False, "get_adapter(None) returned an adapter (GATE BYPASS!)")
except GateRequired:
    check("G-02", True, "get_adapter without policy raises GateRequired (no degrade)")

# ---- G-03 ticket issuance for out-of-scope target ---------------------------
try:
    POLICY.issue_ticket("10.9.9.9:80", "http_probe")
    check("G-03", False, "ticket issued for out-of-scope target (GATE BYPASS!)")
except PolicyRefusal as exc:
    check("G-03", True, f"out-of-scope ticket refused: {str(exc)[:60]}")

# ---- G-04 port mismatch when scope entry has a port -------------------------
p_port = PolicyEngine(base_scope(in_scope=["127.0.0.1:8080"]), "safe_scan")
try:
    p_port.issue_ticket("127.0.0.1:9090", "http_probe")
    check("G-04", False, "ticket issued for port-mismatched target (GATE BYPASS!)")
except PolicyRefusal:
    check("G-04", True, "port-mismatched ticket refused")

# ---- G-05 ticket/adapter mismatch ------------------------------------------
ticket_probe = POLICY.issue_ticket("127.0.0.1:8080", "http_probe")
r = NUCLEI.execute(ticket_probe, policy=POLICY, timeout=5, log=NO_LOG)
check("G-05", r.status == "REFUSED" and "not 'nuclei'" in r.detail,
      f"probe ticket on nuclei adapter -> {r.status}")

# ---- G-06 policy=None at execute time --------------------------------------
try:
    PROBE.execute(ticket_probe, policy=None, timeout=5, log=NO_LOG)  # type: ignore[arg-type]
    check("G-06", False, "execute with policy=None ran (GATE BYPASS!)")
except GateRequired:
    check("G-06", True, "execute without policy raises GateRequired (fail-closed)")

# ---- G-07 scope file/content changed after issuance ------------------------
pol_live = make_policy()
t_live = pol_live.issue_ticket("127.0.0.1:8080", "http_probe")
pol_live.scope = base_scope(in_scope=["10.0.0.1"])  # scope mutated post-issuance
r = PROBE.execute(t_live, policy=pol_live, timeout=5, log=NO_LOG)
check("G-07", r.status == "REFUSED" and "changed" in r.detail,
      f"scope mutated after issuance -> {r.status}")

# ---- G-08 authorization window expired at execute time ---------------------
pol_expired = PolicyEngine(
    base_scope(window="2026-01-01T00:00Z/2026-01-02T00:00Z"), "safe_scan")
try:
    pol_expired.issue_ticket("127.0.0.1:8080", "http_probe")
    check("G-08", False, "ticket issued with expired window (GATE BYPASS!)")
except PolicyRefusal:
    check("G-08", True, "expired-window ticket refused at issuance")

# ---- G-09 policy check raising an exception -> fail-closed ------------------
class ExplodingPolicy:
    """A policy whose checks raise — the gate must treat ANY error as refusal."""
    mode = "safe_scan"
    risk = "R1"

    def scope_sha256(self):
        return POLICY.scope_sha256()

    def target_allowed(self, target):
        raise RuntimeError("simulated policy crash")

    def window_ok(self):
        raise RuntimeError("simulated policy crash")

    def ack_error(self):
        return None


try:
    PROBE.execute(ticket_probe, policy=ExplodingPolicy(), timeout=5, log=NO_LOG)
    check("G-09", False, "execute ran despite policy crash (GATE BYPASS!)")
except RuntimeError:
    check("G-09", True, "policy crash propagates as fail-closed (no silent run)")
except Exception as exc:  # noqa: BLE001
    check("G-09", True, f"policy crash -> gate error {exc.__class__.__name__}")

# ---- G-10 forged RunTicket (constructed without the internal token) ---------
try:
    forged = RunTicket(target="10.9.9.9:80", adapter_id="http_probe",
                       mode="safe_scan", scope_sha256=POLICY.scope_sha256(),
                       issued_at="now", window_end=None)
    PROBE.execute(forged, policy=POLICY, timeout=5, log=NO_LOG)
    check("G-10", False, "forged ticket accepted (GATE BYPASS!)")
except ValueError:
    check("G-10", True, "forged ticket rejected at construction (internal token)")
except PolicyRefusal:
    check("G-10", True, "forged ticket refused by live re-check")

# ---- G-11 executor end-to-end: out-of-scope step never spawns a process -----
ex = Executor(make_policy(in_scope=["127.0.0.1"]),
              quiet_journal(), Path(tempfile.mkdtemp()), sleep_fn=lambda s: None)
ex.run_step({"id": "g11", "adapter": "nuclei", "target": "10.9.9.9:80", "timeout": 5})
check("G-11", ex.results["g11"]["status"] == "REFUSED",
      "executor refuses out-of-scope nuclei step before ticket issuance")

# ---- G-12 executor end-to-end: legal target, probe completes ----------------
ex2 = Executor(make_policy(), quiet_journal(),
               Path(tempfile.mkdtemp()), sleep_fn=lambda s: None)
ex2.run_step({"id": "g12", "adapter": "http_probe", "target": "127.0.0.1:9", "timeout": 3})
check("G-12", ex2.results["g12"]["status"] in ("COMPLETED", "FAILED"),
      f"legal-target step passes the gate and runs (status={ex2.results['g12']['status']})")

# ---- G-13 forged ticket targeted at out-of-scope host via live re-check -----
try:
    forged2 = RunTicket.__new__(RunTicket)  # bypass dataclass __init__ entirely
    object.__setattr__(forged2, "target", "10.9.9.9:80")
    object.__setattr__(forged2, "adapter_id", "http_probe")
    object.__setattr__(forged2, "mode", "safe_scan")
    object.__setattr__(forged2, "scope_sha256", POLICY.scope_sha256())
    object.__setattr__(forged2, "issued_at", "now")
    object.__setattr__(forged2, "window_end", None)
    object.__setattr__(forged2, "target_kind", "net")
    object.__setattr__(forged2, "_token", "dvs-run-ticket-v1")
    r = PROBE.execute(forged2, policy=POLICY, timeout=5, log=NO_LOG)
    check("G-13", r.status == "REFUSED",
          f"hostile forged ticket (bypassed __init__) -> live re-check {r.status}")
except Exception as exc:  # noqa: BLE001
    check("G-13", True, f"hostile forged ticket -> gate error {exc.__class__.__name__}")

# ---- G-14 mode risk ceiling enforced at execute (defense in depth) ----------
pol_passive = PolicyEngine(base_scope(), "passive")  # R0 ceiling
try:
    t_ceiling = pol_passive.issue_ticket("127.0.0.1:8080", "http_probe")  # R1
except PolicyRefusal:
    t_ceiling = None
if t_ceiling is None:
    check("G-14", True, "ticket issuance itself refuses above-ceiling adapter")
else:
    r = PROBE.execute(t_ceiling, policy=pol_passive, timeout=5, log=NO_LOG)
    check("G-14", r.status == "REFUSED" and "exceeds mode ceiling" in r.detail,
          f"R1 adapter under R0 mode at execute -> {r.status}")

# ---- G-15 target-kind mismatch (fs_path vs net) ------------------------------
t_fs = POLICY.issue_ticket("some/local/dir", "http_probe", target_kind="fs_path")
r = PROBE.execute(t_fs, policy=POLICY, timeout=5, log=NO_LOG,
                  step={"id": "g15a", "adapter": "http_probe",
                        "target": "some/local/dir", "target_kind": "net"})
check("G-15a", r.status == "REFUSED" and "target_kind" in r.detail,
      f"fs_path ticket with net step -> {r.status}")
t_net = POLICY.issue_ticket("127.0.0.1:8080", "http_probe")
r = PROBE.execute(t_net, policy=POLICY, timeout=5, log=NO_LOG,
                  step={"id": "g15b", "adapter": "http_probe",
                        "target": "127.0.0.1:8080", "target_kind": "fs_path"})
check("G-15b", r.status == "REFUSED" and "target_kind" in r.detail,
      f"net ticket with fs_path step -> {r.status}")

# ---- G-16 step target vs ticket target mismatch ------------------------------
r = PROBE.execute(t_net, policy=POLICY, timeout=5, log=NO_LOG,
                  step={"id": "g16", "adapter": "http_probe",
                        "target": "10.9.9.9:80", "target_kind": "net"})
check("G-16", r.status == "REFUSED" and "does not match ticket target" in r.detail,
      f"step points at different host than ticket -> {r.status}")

# ---- G-17 unknown adapter step: FAILED, never executed -----------------------
ex3 = Executor(make_policy(), quiet_journal(), Path(tempfile.mkdtemp()),
               sleep_fn=lambda s: None)
ex3.run_step({"id": "g17", "adapter": "no_such_adapter",
              "target": "127.0.0.1:8080", "timeout": 5})
g17 = ex3.results["g17"]
check("G-17", g17["status"] == "FAILED" and "unknown adapter" in g17["reason"],
      f"unknown adapter step -> {g17['status']} (no execution)")

print("-" * 78)
total = 17
print(f"ADAPTER GATE TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
