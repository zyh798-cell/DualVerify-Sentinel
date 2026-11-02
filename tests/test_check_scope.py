"""Unit tests for check_scope.py — destructive-technique gate hardening.

Run:  python tests/test_check_scope.py
Exits 0 only when every case matches its expected outcome.
Scope files are created inside an auto-cleaning TemporaryDirectory.
"""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_scope.py"


def current_window() -> str:
    fmt = "%Y-%m-%dT%H:%MZ"
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    end = datetime.now(timezone.utc) + timedelta(hours=2)
    return f"{start.strftime(fmt)}/{end.strftime(fmt)}"


def base_scope(techniques: object = "OMIT", window: str | None = None) -> dict:
    d = {
        "client": "unit-test",
        "in_scope": ["127.0.0.1"],
        "out_of_scope": ["none"],
        "window": window if window is not None else current_window(),
        "confirmed_by": "unit-test",
    }
    if techniques != "OMIT":
        d["techniques"] = techniques
    return d


def run_script(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    )


CASES = [
    # (id, raw-json | ("file", text), expected-exit, note)
    ("TC-01", base_scope(techniques=["non_destructive"]), 0, "legal baseline"),
    ("TC-02", base_scope(), 0, "techniques omitted -> default"),
    ("TC-03", base_scope(techniques=[]), 0, "empty list -> default"),
    ("TC-04", base_scope(techniques=None), 0, "null -> default"),
    ("TC-05", base_scope(techniques=["dos"]), 1, "destructive: dos"),
    ("TC-06", base_scope(techniques=["destructive"]), 1, "destructive: destructive"),
    ("TC-07", base_scope(techniques=["mutation"]), 1, "destructive: mutation"),
    ("TC-08", base_scope(techniques=["social_engineering"]), 1, "destructive: social_engineering"),
    ("TC-09", base_scope(techniques=["DOS"]), 1, "case variant: DOS"),
    ("TC-10", base_scope(techniques=["Dos"]), 1, "case variant: Dos"),
    ("TC-11", base_scope(techniques=["DESTRUCTIVE"]), 1, "case variant: DESTRUCTIVE"),
    ("TC-12", base_scope(techniques=["Social_Engineering"]), 1, "case variant: Social_Engineering"),
    ("TC-13", base_scope(techniques=[" dos "]), 1, "whitespace padding"),
    ("TC-14", base_scope(techniques=["non_destructive", "DOS"]), 1, "mixed legal+illegal"),
    ("TC-15", base_scope(techniques=["dos", "dos"]), 1, "in-list duplicates"),
    ("TC-16", base_scope(techniques=["non_destructive", "dos"]), 1, "legal first, illegal last"),
    ("TC-17", base_scope(techniques=["dos", 123]), 1, "mixed-type list"),
    ("TC-18", base_scope(techniques="dos"), 1, "string instead of list"),
    ("TC-19", base_scope(techniques=123), 1, "int instead of list"),
    ("TC-20", base_scope(techniques=[{}]), 1, "unhashable element"),
    ("TC-21", base_scope(techniques=["nuclear_strike"]), 1, "unknown technique name"),
    ("TC-22", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"2026-01-01T00:00Z/2026-01-02T00:00Z","confirmed_by":"t","techniques":["dos"]}', 1, "expired window (regression F5)"),
    ("TC-23", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"broken","confirmed_by":"t"}', 1, "unparseable window (regression F5)"),
    ("TC-24", '{"client":"t",', 1, "malformed JSON"),
    ("TC-27", '{"client":"t","in_scope":"127.0.0.1","out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t"}', 1, "in_scope as string (not list)"),
    ("TC-28", '{"client":"t","in_scope":["x"],"out_of_scope":"n","window":"' + current_window() + '","confirmed_by":"t"}', 1, "out_of_scope as string (not list)"),
    ("TC-29", '{"client":"t","in_scope":["x",5],"out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t"}', 1, "in_scope mixed-type list"),
    ("TC-30", '﻿{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t"}', 1, "UTF-8 BOM prefix"),
    ("TC-31", '{"client":"t","in_scope":' + "[" * 3000 + "]" * 3000 + ',"out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t"}', 1, "deeply nested JSON"),
    ("TC-32", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"2026-10-28T00:00Z/2026-10-27T00:00Z","confirmed_by":"t"}', 1, "window end before start"),
    ("TC-33", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t","techniques":""}', 1, "techniques empty string"),
    ("TC-34", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"9999-12-31T23:59Z/9999-12-31T23:59Z","confirmed_by":"t"}', 1, "window far future"),
]

RAW_CASES = [
    ("TC-25", '{"client":"t","in_scope":["x"],"out_of_scope":["n"],"window":"' + current_window() + '","confirmed_by":"t","techniques":["dos"],"techniques":["non_destructive"]}', 1, "duplicate JSON keys"),
]

failures = 0
print(f"check_scope.py unit tests — script: {SCRIPT}")
print(f"window used: {current_window()}")
print("-" * 78)

with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)

    for cid, payload, expect, note in CASES:
        p = tmp / f"{cid}.json"
        if isinstance(payload, str):
            text = payload  # raw JSON text, written verbatim
        else:
            text = json.dumps(payload)
        p.write_text(text, encoding="utf-8")
        r = run_script(p)
        ok = r.returncode == expect
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {cid} exit={r.returncode} expect={expect} — {note}")
        if not ok:
            print(f"       stdout: {r.stdout.strip()[:200]}")
            print(f"       stderr: {r.stderr.strip()[:200]}")

    for cid, text, expect, note in RAW_CASES:
        p = tmp / f"{cid}.json"
        p.write_text(text, encoding="utf-8")
        r = run_script(p)
        ok = r.returncode == expect
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {cid} exit={r.returncode} expect={expect} — {note}")
        if not ok:
            print(f"       stderr: {r.stderr.strip()[:200]}")

    # TC-26: nonexistent scope file
    r = run_script(tmp / "does-not-exist.json")
    ok = r.returncode == 1
    failures += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] TC-26 exit={r.returncode} expect=1 — nonexistent scope file")

print("-" * 78)
total = len(CASES) + len(RAW_CASES) + 1
print(f"TOTAL: {total - failures}/{total} passed, {failures} failed")
sys.exit(1 if failures else 0)
