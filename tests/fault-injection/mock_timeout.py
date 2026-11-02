"""Fault-injection mock: sleeps longer than any sane timeout, then exits 0.

Used to verify the SKILL.md timeout/backoff policy: a call killed by a
timeout must count as a failure and follow the one-retry rule.

Usage: python mock_timeout.py [--sleep SECONDS]   (default 30)
"""
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument("--sleep", type=float, default=30.0)
args = parser.parse_args()
time.sleep(args.sleep)
print("done")
