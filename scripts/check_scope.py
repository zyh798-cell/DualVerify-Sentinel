"""Thin wrapper for human/manual use. The actual gate logic lives in
vuln_hunter.gate_check (single source of truth — no duplicated logic here).

Manual run:  python scripts/check_scope.py <scope.json>
Equivalent:  python -m vuln_hunter.gate_check <scope.json>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_hunter.gate_check import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
