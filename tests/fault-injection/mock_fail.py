"""Fault-injection mock: always exits non-zero (simulates a broken tool)."""
import sys

print("mock failure", file=sys.stderr)
sys.exit(1)
