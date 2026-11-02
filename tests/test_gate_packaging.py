"""P0-3 gate packaging tests: vuln_hunter.gate_check must be locatable and
runnable in ALL supported install modes, and gate failures must be fail-closed.

Run:  python tests/test_gate_packaging.py
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

failures = 0


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def run_gate_module(scope_text: str | None, tmp: Path, cwd: Path | None = None):
    p = tmp / "scope.json"
    if scope_text is not None:
        p.write_text(scope_text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "vuln_hunter.gate_check", str(p)],
        capture_output=True, text=True, timeout=60,
        cwd=str(cwd) if cwd else None,
        env={"PYTHONPATH": str(ROOT), "PATH": __import__("os").environ["PATH"],
             "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
    )


# ---- GP-01 module importable via find_spec ---------------------------------
spec = importlib.util.find_spec("vuln_hunter.gate_check")
check("GP-01", spec is not None, "vuln_hunter.gate_check resolvable in this environment")

# ---- GP-02 subprocess: valid scope -> exit 0 -------------------------------
import json  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

fmt = "%Y-%m-%dT%H:%MZ"
now = datetime.now(timezone.utc)
win = f"{(now - timedelta(minutes=5)).strftime(fmt)}/{(now + timedelta(hours=2)).strftime(fmt)}"
good = json.dumps({"client": "gp", "in_scope": ["127.0.0.1"], "out_of_scope": ["none"],
                   "window": win, "confirmed_by": "gp"})
with __import__("tempfile").TemporaryDirectory() as td:
    r = run_gate_module(good, Path(td))
    check("GP-02", r.returncode == 0 and "scope OK" in r.stdout,
          f"gate_check subprocess accepts valid scope (exit={r.returncode})")

    # ---- GP-03 subprocess: invalid scope -> exit 1 (fail-closed) -----------
    bad = good.replace('"dos"', '"x"').replace('"none"', '"none"')
    bad = json.dumps({"client": "gp", "in_scope": ["127.0.0.1"], "out_of_scope": ["none"],
                      "window": win, "confirmed_by": "gp", "techniques": ["dos"]})
    r = run_gate_module(bad, Path(td))
    check("GP-03", r.returncode == 1 and "destructive" in r.stderr,
          f"gate_check subprocess refuses destructive scope (exit={r.returncode})")

    # ---- GP-04 subprocess: unreadable scope -> exit 1 (fail-closed) --------
    r = run_gate_module(None, Path(td))  # no file written
    check("GP-04", r.returncode == 1, "missing scope file -> exit 1 (no fallback)")

    # ---- GP-05 module missing usage error path -----------------------------
    r = subprocess.run([sys.executable, "-m", "vuln_hunter.gate_check"],
                       capture_output=True, text=True, timeout=60,
                       env={"PYTHONPATH": str(ROOT), "PATH": __import__("os").environ["PATH"],
                            "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")})
    check("GP-05", r.returncode == 2, "gate_check without args -> usage exit 2")

print("-" * 78)
total = 5
print(f"GATE PACKAGING TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
