"""Engine unit tests — state machine, policy refusals, retry/quarantine/cancel.

These tests inject FAKE adapters into the registry (clearly labeled). They
verify the Executor/PolicyEngine logic. REAL tool execution is covered
separately by the closed-loop run against the local lab (see TEST-RECORD).

Run:  python tests/test_engine.py
"""
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter  # noqa: E402
from vuln_hunter.journal import EvidenceJournal  # noqa: E402
from vuln_hunter.planner import build_plan  # noqa: E402
from vuln_hunter.policy import ACK_KEYS, MODES, PolicyEngine, hostport  # noqa: E402
from vuln_hunter.runner import Executor  # noqa: E402

failures = 0


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    end = datetime.now(timezone.utc) + timedelta(hours=2)
    return f"{start.strftime(fmt)}/{end.strftime(fmt)}"


def base_scope(**kw) -> dict:
    d = {
        "client": "engine-test",
        "in_scope": ["127.0.0.1"],
        "out_of_scope": ["none"],
        "window": current_window(),
        "confirmed_by": "engine-test",
    }
    d.update(kw)
    return d


class OkAdapter(ToolAdapter):
    id, risk = "fake_ok", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "ok", [{"type": "x"}])


class FailAdapter(ToolAdapter):
    id, risk = "fake_fail", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("FAILED", False, "boom")


class TimeoutAdapter(ToolAdapter):
    id, risk = "fake_timeout", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("TIMEOUT", False, "hung")


class FlakyAdapter(ToolAdapter):
    """Fails on attempt 1, succeeds afterwards."""
    id, risk = "fake_flaky", "R1"
    calls = 0

    def _run(self, target, timeout, log, step=None):
        FlakyAdapter.calls += 1
        if FlakyAdapter.calls == 1:
            return AdapterResult("FAILED", False, "transient")
        return AdapterResult("COMPLETED", True, "recovered")


class RateLimitedAdapter(ToolAdapter):
    id, risk = "fake_429", "R1"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("FAILED", False, "HTTP 429", no_retry=True, quarantine=True)


class MissingDepsAdapter(ToolAdapter):
    id, risk = "fake_missing", "R1"

    def preflight(self):
        return "dependency not installed"

    def _run(self, target, timeout, log, step=None):  # pragma: no cover
        raise AssertionError("should not run")


# Register the injected fakes (same dict object the Executor references).
import vuln_hunter.adapters as _adapters_mod  # noqa: E402

for _cls in (OkAdapter, FailAdapter, TimeoutAdapter, FlakyAdapter,
             RateLimitedAdapter, MissingDepsAdapter):
    _adapters_mod.register_adapter(_cls)


def make_executor(scope, mode, steps_log, sleeps=None):
    journal = EvidenceJournal(Path(tempfile.mkdtemp()) / "j.jsonl")
    ex = Executor(
        PolicyEngine(scope, mode), journal, Path(tempfile.mkdtemp()),
        sleep_fn=lambda s: (sleeps or []).append(s),
    )
    return ex


with tempfile.TemporaryDirectory() as td:
    # ---- TE-01 happy path ------------------------------------------------
    ex = make_executor(base_scope(), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "127.0.0.1:8080", "timeout": 5})
    r = ex.results["s1"]
    check("TE-01", r["status"] == "COMPLETED" and ex.summary_status() == "COMPLETED", "happy path COMPLETED")

    # ---- TE-02 target out of scope ---------------------------------------
    ex = make_executor(base_scope(in_scope=["10.9.9.9"]), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "127.0.0.1:8080", "timeout": 5})
    check("TE-02", ex.results["s1"]["status"] == "REFUSED" and "not covered by in_scope" in ex.results["s1"]["reason"], "out-of-scope target REFUSED")

    # ---- TE-03 adapter risk above ceiling --------------------------------
    ex = make_executor(base_scope(), "passive", None)
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "127.0.0.1", "timeout": 5})  # R1 > R0
    check("TE-03", ex.results["s1"]["status"] == "REFUSED" and "exceeds mode ceiling" in ex.results["s1"]["reason"], "R1 adapter refused under passive (R0)")

    # ---- TE-04 expired window -> ABORTED ---------------------------------
    ex = make_executor(base_scope(window="2026-01-01T00:00Z/2026-01-02T00:00Z"), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "127.0.0.1", "timeout": 5})
    check("TE-04", ex.results["s1"]["status"] == "ABORTED", "expired window ABORTED")

    # ---- TE-05 failed dependency -> SKIPPED ------------------------------
    ex = make_executor(base_scope(), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_fail", "target": "127.0.0.1", "timeout": 5})
    ex.run_step({"id": "s2", "adapter": "fake_ok", "target": "127.0.0.1", "timeout": 5, "deps": ["s1"]})
    check("TE-05", ex.results["s2"]["status"] == "SKIPPED" and ex.summary_status() == "FAILED", "dep FAILED -> SKIPPED, summary FAILED")

    # ---- TE-06 retry: fail then succeed ----------------------------------
    FlakyAdapter.calls = 0
    sleeps = []
    journal = EvidenceJournal(Path(tempfile.mkdtemp()) / "j.jsonl")
    ex = Executor(PolicyEngine(base_scope(), "safe_scan"), journal, Path(tempfile.mkdtemp()), sleep_fn=sleeps.append)
    ex.run_step({"id": "s1", "adapter": "fake_flaky", "target": "127.0.0.1", "timeout": 5})
    check("TE-06", ex.results["s1"]["status"] == "COMPLETED" and ex.results["s1"]["attempts"] == 2 and sleeps == [5], "retry once with 5s backoff -> COMPLETED")

    # ---- TE-07 always fail -> FAILED after 2 attempts --------------------
    sleeps = []
    journal = EvidenceJournal(Path(tempfile.mkdtemp()) / "j.jsonl")
    ex = Executor(PolicyEngine(base_scope(), "safe_scan"), journal, Path(tempfile.mkdtemp()), sleep_fn=sleeps.append)
    ex.run_step({"id": "s1", "adapter": "fake_fail", "target": "127.0.0.1", "timeout": 5})
    check("TE-07", ex.results["s1"]["status"] == "FAILED" and ex.results["s1"]["attempts"] == 2 and sleeps == [5], "always-fail FAILED after exactly 2 attempts")

    # ---- TE-08 timeout -> 10s backoff, 2 attempts ------------------------
    sleeps = []
    journal = EvidenceJournal(Path(tempfile.mkdtemp()) / "j.jsonl")
    ex = Executor(PolicyEngine(base_scope(), "safe_scan"), journal, Path(tempfile.mkdtemp()), sleep_fn=sleeps.append)
    ex.run_step({"id": "s1", "adapter": "fake_timeout", "target": "127.0.0.1", "timeout": 5})
    check("TE-08", ex.results["s1"]["status"] == "TIMEOUT" and ex.results["s1"]["attempts"] == 2 and sleeps == [10], "TIMEOUT retried once after 10s, still TIMEOUT")

    # ---- TE-09 429 -> no retry + quarantine + dep skipped ----------------
    ex = make_executor(base_scope(), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_429", "target": "127.0.0.1", "timeout": 5})
    ex.run_step({"id": "s2", "adapter": "fake_ok", "target": "127.0.0.1", "timeout": 5, "deps": ["s1"]})
    check("TE-09", ex.results["s1"]["attempts"] == 1 and ex.results["s1"]["quarantined"] and ex.results["s2"]["status"] == "SKIPPED", "429: single attempt, quarantine, downstream SKIPPED")

    # ---- TE-10 preflight missing -> SKIPPED ------------------------------
    ex = make_executor(base_scope(), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_missing", "target": "127.0.0.1", "timeout": 5})
    check("TE-10", ex.results["s1"]["status"] == "SKIPPED" and "preflight" in ex.results["s1"]["reason"], "preflight failure -> SKIPPED (no execution)")

    # ---- TE-11 cancel file ----------------------------------------------
    ex = make_executor(base_scope(), "safe_scan", None)
    (ex.evidence_dir / "CANCEL").write_text("stop", encoding="utf-8")
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "127.0.0.1", "timeout": 5})
    check("TE-11", ex.results["s1"]["status"] == "CANCELLED", "CANCEL file -> CANCELLED, adapter never runs")

    # ---- TE-12 hostport parsing / prefix-bypass resistance ---------------
    check("TE-12a", hostport("127.0.0.1") == ("127.0.0.1", None), "hostport bare host")
    check("TE-12b", hostport("127.0.0.1:8080") == ("127.0.0.1", 8080), "hostport host:port")
    check("TE-12c", hostport("http://LOCALHost:80/") == ("localhost", 80), "hostport case-insensitive, default port")
    check("TE-12d", hostport("") is None and hostport("http://") is None, "hostport rejects empty")

    # ---- TE-13 target matching semantics ---------------------------------
    p = PolicyEngine(base_scope(in_scope=["127.0.0.1"]), "safe_scan")
    check("TE-13a", p.target_allowed("127.0.0.1:9999") is None, "portless in_scope entry matches any port")
    check("TE-13b", p.target_allowed("127.0.0.199") is not None, "prefix-lookalike host NOT matched")
    check("TE-13c", p.target_allowed("127.0.0.1.evil.com") is not None, "suffix-attached host NOT matched")
    p2 = PolicyEngine(base_scope(in_scope=["127.0.0.1:8080"]), "safe_scan")
    check("TE-13d", p2.target_allowed("127.0.0.1:9090") is not None, "port mismatch refused when entry has port")
    p3 = PolicyEngine(base_scope(out_of_scope=["10.0.0.5"]), "safe_scan")
    check("TE-13e", p3.target_allowed("10.0.0.5:80") is not None, "out_of_scope entry blocks matching target")

    # ---- TE-14 acknowledgement enforcement --------------------------------
    ack = {k: "filled" for k in ACK_KEYS}
    pol_ok = PolicyEngine(base_scope(risk_acknowledgement=ack), "attack_simulation")
    pol_bad = PolicyEngine(base_scope(), "attack_simulation")
    pol_partial = PolicyEngine(base_scope(risk_acknowledgement={"impact_boundary": "x"}), "attack_simulation")
    check("TE-14a", pol_ok.ack_error() is None, "complete risk_acknowledgement accepted for R3")
    check("TE-14b", pol_bad.ack_error() is not None, "missing risk_acknowledgement refused for R3")
    check("TE-14c", pol_partial.ack_error() is not None and "rollback_plan" in pol_partial.ack_error(), "partial ack refused, names missing keys")
    check("TE-14d", PolicyEngine(base_scope(), "safe_scan").ack_error() is None, "ack not required below R3")

    # ---- TE-16 fs_path target skips net scope check only ------------------
    ex = make_executor(base_scope(), "safe_scan", None)
    ex.run_step({"id": "s1", "adapter": "fake_ok", "target": "some/local/dir", "timeout": 5, "target_kind": "fs_path"})
    check("TE-16a", ex.results["s1"]["status"] == "COMPLETED", "fs_path target not blocked by net scope")
    ex.run_step({"id": "s2", "adapter": "fake_ok", "target": "some/local/dir", "timeout": 5})
    check("TE-16b", ex.results["s2"]["status"] == "REFUSED", "same target as net IS refused (no blanket exemption)")

    # ---- TE-15 planner shapes ---------------------------------------------
    plan_a = build_plan("safe_scan", "127.0.0.1:8080")
    plan_b = build_plan("vuln_validation", "127.0.0.1:8080", source_dir="src")
    # EXT-1.1: the planner appends the gitleaks step only when the binary
    # resolves (a missing optional tool must not turn green runs red), so
    # the expectation is computed, not hard-coded — machine-independent.
    from vuln_hunter.adapters_ext.gitleaks import gitleaks_binary
    expect_b = ["http_probe", "nuclei", "bandit"]
    if gitleaks_binary() is not None:
        expect_b.append("gitleaks")
    check("TE-15a", [s["adapter"] for s in plan_a] == ["http_probe"], "safe_scan: probe only")
    check("TE-15b", [s["adapter"] for s in plan_b] == expect_b,
          "vuln_validation + source_dir: probe, nuclei, bandit (+gitleaks when installed)")
    check("TE-15c", plan_b[1]["deps"] == ["s1-probe"], "nuclei depends on probe")
    check("TE-15d", MODES["high_risk"] == "R4", "mode table intact")

total_checks = 11 + 4 + 5 + 4 + 4 + 2  # TE-01..11, TE-12a-d, TE-13a-e, TE-14a-d, TE-15a-d, TE-16a-b
print("-" * 78)
print(f"ENGINE UNIT TESTS: {total_checks - failures}/{total_checks} checks passed")
sys.exit(1 if failures else 0)
