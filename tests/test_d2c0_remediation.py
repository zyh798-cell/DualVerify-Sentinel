"""D2-C0 remediation tests: engine flags (-dr/-ni) + synthetic isolation.

Verifies:
- build_command always carries -duc AND now -dr (R1) and -ni (R2);
- no parameter re-enables redirects or OAST callbacks;
- synthetic findings are structurally classified end-to-end:
  finding -> journal step_end -> report statistics (R3);
- run-wide synthetic_run marking honours pre-existing per-finding markers;
- default (non-synthetic) runs do NOT add markers.

Run:  python tests/test_d2c0_remediation.py
"""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.adapters import AdapterResult, ToolAdapter, register_adapter  # noqa: E402
from vuln_hunter.journal import EvidenceJournal, verify  # noqa: E402
from vuln_hunter.policy import PolicyEngine  # noqa: E402
from vuln_hunter.report import is_synthetic_finding, render_report  # noqa: E402
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
    return (f"{(now - timedelta(minutes=5)).strftime(fmt)}/"
            f"{(now + timedelta(hours=2)).strftime(fmt)}")


def base_scope(**kw) -> dict:
    d = {"client": "d2c0-test", "in_scope": ["127.0.0.1:18080"],
         "out_of_scope": ["everything else"], "window": current_window(),
         "confirmed_by": "d2c0-test"}
    d.update(kw)
    return d


# ---------------------------------------------------------------------------
print("=" * 78)
print("D2-C0 REMEDIATION TESTS")
print("=" * 78)

# ---------------------------------------------------------------------------
# R1/R2 — engine flags
# ---------------------------------------------------------------------------
from vuln_hunter.adapters import NucleiAdapter  # noqa: E402

nuc = NucleiAdapter()

# R-01: command with a declared template subset
cmd = nuc.build_command("127.0.0.1:18080",
                        {"nuclei_ids": ["d2b-synthetic-lab-echo"]})
check("R-01a", cmd[cmd.index("-u") + 1] == "http://127.0.0.1:18080",
      "target originates from the controlled argument")
for flag in ("-duc", "-disable-update-check", "-dr", "-ni"):
    check(f"R-01[{flag}]", flag in cmd, f"{flag} present in engine command")
check("R-01[id]", cmd[cmd.index("-id") + 1] == "d2b-synthetic-lab-echo",
      "single template id restriction intact")
check("R-01b", cmd.count("-dr") == 1 and cmd.count("-ni") == 1,
      "-dr/-ni appear exactly once (no duplication)")
for banned in ("-follow-redirects", "-iserver", "-interactsh-server",
               "-ut", "-update-templates", "-lfa", "-scan-all-ips"):
    check(f"R-02[{banned}]", banned not in cmd,
          f"behaviour-widening parameter absent: {banned}")

# R-03: command without a step dict (None) — flags unconditional
cmd0 = nuc.build_command("127.0.0.1:18080", None)
for flag in ("-duc", "-dr", "-ni"):
    check(f"R-03[{flag}]", flag in cmd0, f"{flag} present even without step")
check("R-03[id]", "-id" not in cmd0,
      "no -id when no template subset declared")

# R-04: tags path does not disturb the safety flags
cmdt = nuc.build_command("127.0.0.1:18080",
                         {"nuclei_ids": ["t1"], "nuclei_tags": ["tech"]})
for flag in ("-duc", "-dr", "-ni"):
    check(f"R-04[{flag}]", flag in cmdt, f"{flag} survives the -tags path")

# ---------------------------------------------------------------------------
# R3 — synthetic classification
# ---------------------------------------------------------------------------
REAL = {"type": "bandit_finding", "test_id": "B101", "severity": "low",
        "filename": "x.py", "line": 1, "issue": "real issue"}
SYN = {"type": "nuclei_finding", "template": "d2b-synthetic-lab-echo",
       "severity": "high", "name": "SYNTHETIC-LAB-FINDING",
       "host": "http://127.0.0.1:18080", "matched_at": "http://127.0.0.1:18080/",
       "synthetic": True}

check("R-05a", is_synthetic_finding(SYN), "explicit marker -> synthetic")
check("R-05b", not is_synthetic_finding(REAL), "no marker -> real")
check("R-05c", not is_synthetic_finding({"synthetic": "yes"}),
      "non-boolean marker value does NOT classify (strict is True)")

report = render_report(
    mode="vuln_validation", risk="R2", scope_path="scope.json",
    scope=base_scope(), gate_ok=True, gate_message="ok", plan=[],
    results={}, summary="COMPLETED",
    findings=[REAL, SYN], journal_path="j.jsonl", decision_trace=None,
    audit=None)
check("R-06a", "真实发现 **1** 条" in report
      and "合成/实验室标记发现 **1** 条" in report,
      "report statistics separate real vs synthetic counts")
check("R-06b", "**[SYNTHETIC]**" in report and report.count("**[SYNTHETIC]**") == 1,
      "per-finding SYNTHETIC tag rendered exactly for marked findings")
check("R-06c", "不计入真实漏洞数量" in report,
      "exclusion statement explicit in report")

# R-07 — run-wide synthetic_run marking end-to-end: finding -> journal -> rec
class LabNuclei(ToolAdapter):
    id, risk = "d2c0_nuclei", "R2"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "lab scan",
                             findings=[{"type": "nuclei_finding",
                                        "template": "lab-tpl",
                                        "severity": "high",
                                        "name": "lab finding",
                                        "synthetic": True}])


class RealNuclei(ToolAdapter):
    id, risk = "d2c0_real", "R2"

    def _run(self, target, timeout, log, step=None):
        return AdapterResult("COMPLETED", True, "real scan",
                             findings=[{"type": "nuclei_finding",
                                        "template": "real-tpl",
                                        "severity": "medium",
                                        "name": "real finding"}])


register_adapter(LabNuclei)
register_adapter(RealNuclei)

for run_id, synthetic, adapter in (("synthetic-run", True, "d2c0_nuclei"),
                                   ("default-run", False, "d2c0_real")):
    tmp = Path(tempfile.mkdtemp(prefix=f"d2c0-{run_id}-"))
    journal = EvidenceJournal(tmp / "j.jsonl")
    policy = PolicyEngine(base_scope(), "vuln_validation")
    ex = Executor(policy, journal, tmp / "ev", sleep_fn=lambda s: None,
                  synthetic_run=synthetic)
    rec = ex.run_step({"id": "s1", "adapter": adapter,
                       "target": "127.0.0.1:18080", "timeout": 10})
    f = rec["findings"][0]
    if synthetic:
        check(f"R-07[{run_id}]", f.get("synthetic") is True,
              "run-wide marking sets synthetic=True on findings")
    else:
        check(f"R-07[{run_id}]", "synthetic" not in f,
              "default run adds NO synthetic field (zero behaviour change)")
tmp = Path(tempfile.mkdtemp(prefix="d2c0-journal-"))
journal = EvidenceJournal(tmp / "j.jsonl")
policy = PolicyEngine(base_scope(), "vuln_validation")
ex = Executor(policy, journal, tmp / "ev", sleep_fn=lambda s: None,
              synthetic_run=True)
ex.run_step({"id": "s1", "adapter": "d2c0_nuclei",
             "target": "127.0.0.1:18080", "timeout": 10})
recs = [json.loads(l)["rec"] for l in
        (tmp / "j.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
step_end = next(r for r in recs if r.get("event") == "step_end")
check("R-08a", step_end["findings"][0].get("synthetic") is True,
      "synthetic marker preserved verbatim in journal step_end")
ok, _bad, det = verify(tmp / "j.jsonl")
check("R-08b", ok, f"journal chain intact ({det})")

# R-09 — CLI flag exists (help only, no run)
help_out = subprocess.run(
    [sys.executable, "-m", "vuln_hunter", "run", "--help"],
    capture_output=True, text=True, cwd=str(ROOT), timeout=60).stdout
check("R-09", "--synthetic" in help_out,
      "CLI exposes the run-level synthetic declaration")

print("-" * 78)
print(f"D2-C0 TESTS: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
