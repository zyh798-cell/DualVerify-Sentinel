"""CLI gate-check subcommand tests (S1).

Verifies `python -m vuln_hunter gate-check` behaves exactly like the
standalone `python -m vuln_hunter.gate_check` gate: exit 0 accept,
1 refuse, consistent output. (The `dvs` entry point shares the same
main(), so these cover both invocation forms' logic.)

Run:  python tests/test_cli_gate.py
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

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


def run_cli(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-m", "vuln_hunter", *args],
        capture_output=True, text=True, cwd=str(ROOT), env=env,
    )


with tempfile.TemporaryDirectory() as td:
    # ---- CG-01 valid scope -> exit 0 -------------------------------------
    good = Path(td) / "good.json"
    good.write_text(json.dumps({
        "client": "cli-test", "in_scope": ["127.0.0.1"],
        "out_of_scope": ["everything else"],
        "window": current_window(), "confirmed_by": "cli-test",
        "techniques": ["non_destructive"],
    }), encoding="utf-8")
    r = run_cli("gate-check", str(good))
    check("CG-01", r.returncode == 0 and "scope OK" in r.stdout,
          f"valid scope -> exit {r.returncode}")

    # ---- CG-02 expired window -> exit 1 ----------------------------------
    expired = Path(td) / "expired.json"
    expired.write_text(json.dumps({
        "client": "cli-test", "in_scope": ["127.0.0.1"],
        "out_of_scope": ["everything else"],
        "window": "2026-01-01T00:00Z/2026-01-02T00:00Z",
        "confirmed_by": "cli-test",
    }), encoding="utf-8")
    r = run_cli("gate-check", str(expired))
    check("CG-02", r.returncode == 1 and "expired" in (r.stderr + r.stdout),
          f"expired window -> exit {r.returncode}")

    # ---- CG-03 destructive techniques -> exit 1 --------------------------
    bad = Path(td) / "destructive.json"
    bad.write_text(json.dumps({
        "client": "cli-test", "in_scope": ["127.0.0.1"],
        "out_of_scope": ["everything else"],
        "window": current_window(), "confirmed_by": "cli-test",
        "techniques": ["dos"],
    }), encoding="utf-8")
    r = run_cli("gate-check", str(bad))
    check("CG-03", r.returncode == 1 and "destructive" in (r.stderr + r.stdout),
          f"destructive techniques -> exit {r.returncode}")

    # ---- CG-04 missing file -> exit 1 ------------------------------------
    r = run_cli("gate-check", str(Path(td) / "nope.json"))
    check("CG-04", r.returncode == 1, f"missing scope file -> exit {r.returncode}")

    # ---- CG-05 missing argument -> exit 2 --------------------------------
    r = run_cli("gate-check")
    check("CG-05", r.returncode == 2, f"missing scope argument -> exit {r.returncode}")

    # ---- CG-06 parity with python -m vuln_hunter.gate_check --------------
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    r_mod = subprocess.run(
        [sys.executable, "-m", "vuln_hunter.gate_check", str(good)],
        capture_output=True, text=True, cwd=str(td), env=env,
    )
    r_cli = run_cli("gate-check", str(good))
    check("CG-06", r_mod.returncode == r_cli.returncode == 0,
          "subcommand and standalone module agree (both exit 0)")

print("-" * 78)
total = 6
print(f"CLI GATE-CHECK TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
