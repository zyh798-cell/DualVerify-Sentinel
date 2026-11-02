"""Gate access layer.

The scope gate (vuln_hunter.gate_check) is the single source of truth:
policy reuses its window_error(), and the CLI validates the scope file by
running the SAME module as a REAL subprocess (`python -m vuln_hunter.gate_check`),
so the tested artifact is the same check a human would run.

Fail-closed: if the module is missing, the subprocess fails, times out or its
output cannot be interpreted as success, run_gate returns a non-zero result
and the CLI refuses the run. There is no code path that skips authorization
when the gate is unavailable.
"""
import importlib.util
import subprocess
import sys

from . import gate_check as _impl


def load_gate():
    """Import the in-package gate module (kept for API compatibility)."""
    return _impl


def window_error(window) -> str | None:
    """Delegate to the gate implementation — no duplicated parsing logic."""
    return _impl.window_error(window)


def gate_available() -> bool:
    """Fail-closed pre-check: the gate module must be importable."""
    try:
        return importlib.util.find_spec("vuln_hunter.gate_check") is not None
    except (ImportError, ValueError):
        return False


def run_gate(scope_path, timeout: int = 30) -> subprocess.CompletedProcess:
    """Validate a scope file through the real gate subprocess.

    Propagates subprocess.TimeoutExpired — callers treat any gate failure
    (including timeout) as a refusal, never as a skip.
    """
    return subprocess.run(
        [sys.executable, "-m", "vuln_hunter.gate_check", str(scope_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
