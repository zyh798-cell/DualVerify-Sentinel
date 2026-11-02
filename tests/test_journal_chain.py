"""Journal hash-chain integrity tests (S1).

Covers: chain validity, record tampering, deletion, reordering, tail
truncation (external-anchor detection), legacy records, fail-closed append on
corrupt tail, and write-failure propagation.

Run:  python tests/test_journal_chain.py
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.journal import (  # noqa: E402
    EvidenceJournal, JournalIntegrityError, GENESIS_PREV, head, verify,
)

failures = 0


def check(case_id: str, cond: bool, note: str = ""):
    global failures
    if not cond:
        failures += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {case_id} — {note}")


def tmpfile(name="j.jsonl") -> Path:
    return Path(tempfile.mkdtemp()) / name


def make_journal(n=4) -> tuple[EvidenceJournal, Path]:
    p = tmpfile()
    j = EvidenceJournal(p)
    for i in range(n):
        j.append("step_end", step=f"s{i}", status="COMPLETED", attempt=i + 1)
    return j, p


with tempfile.TemporaryDirectory() as td:

    # ---- JC-01 fresh chain verifies --------------------------------------
    j, p = make_journal()
    ok, bad, detail = verify(p)
    check("JC-01", ok and bad is None and "4 record" in detail, f"fresh chain verifies: {detail}")

    # ---- JC-02 read_all returns inner records ----------------------------
    recs = j.read_all()
    check("JC-02", len(recs) == 4 and recs[0]["event"] == "step_end"
          and recs[0]["step"] == "s0" and "ts" in recs[0],
          "read_all unwraps to inner records with ts/event/fields")

    # ---- JC-03 head anchor advances --------------------------------------
    h1 = head(p)
    j.append("extra")
    h2 = head(p)
    check("JC-03", h1 and h2 and h1 != h2, "head changes after each append")

    # ---- JC-04 field tampering detected ----------------------------------
    j2, p2 = make_journal()
    lines = p2.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["rec"]["status"] = "FAILED"  # forge a worse result
    lines[2] = json.dumps(rec, ensure_ascii=False)
    p2.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad, detail = verify(p2)
    check("JC-04", not ok and bad == 2 and "hash mismatch" in detail,
          f"modified record detected at seq {bad}: {detail}")

    # ---- JC-05 ts tampering detected -------------------------------------
    j3, p3 = make_journal()
    lines = p3.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["rec"]["ts"] = "2000-01-01T00:00:00+00:00"
    lines[1] = json.dumps(rec, ensure_ascii=False)
    p3.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad, _ = verify(p3)
    check("JC-05", not ok and bad == 1, "timestamp rewrite detected")

    # ---- JC-06 deletion detected -----------------------------------------
    j4, p4 = make_journal()
    lines = p4.read_text(encoding="utf-8").splitlines()
    del lines[1]
    p4.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad, detail = verify(p4)
    check("JC-06", not ok and bad == 1 and "seq missing/out of order" in detail,
          f"deleted middle record detected: {detail}")

    # ---- JC-07 reordering detected ---------------------------------------
    j5, p5 = make_journal()
    lines = p5.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p5.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad, _ = verify(p5)
    check("JC-07", not ok and bad == 1, "reordered records detected")

    # ---- JC-08 tail truncation: in-chain verify passes on the prefix,
    #      but the externally stored anchor no longer matches ---------------
    j6, p6 = make_journal()
    anchor = head(p6)  # operator stores this externally
    lines = p6.read_text(encoding="utf-8").splitlines()
    p6.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")  # drop tail
    ok_trunc, _, detail_trunc = verify(p6)
    check("JC-08", ok_trunc and head(p6) != anchor,
          "truncated tail: prefix chain valid, head anchor mismatch exposes truncation "
          f"({detail_trunc})")

    # ---- JC-09 legacy (unhashed) records reported UNVERIFIED -------------
    p7 = tmpfile()
    plain = [{"ts": "t", "event": "old", "seq": 0, "prev": GENESIS_PREV}]
    p7.write_text("\n".join(json.dumps(r) for r in plain) + "\n", encoding="utf-8")
    ok, bad, detail = verify(p7)
    check("JC-09", not ok and bad == 0 and "UNVERIFIED" in detail,
          f"legacy record never silently accepted: {detail}")

    # ---- JC-10 append refuses on corrupt tail (fail-closed) ---------------
    j8, p8 = make_journal()
    with open(p8, "a", encoding="utf-8") as fh:
        fh.write("{CORRUPT NOT JSON\n")
    try:
        EvidenceJournal(p8)
        j8.append("sneaky")
        check("JC-10", False, "append continued on corrupt journal (NOT fail-closed!)")
    except JournalIntegrityError as exc:
        check("JC-10", True, f"append on corrupt tail raises JournalIntegrityError: "
                             f"{str(exc)[:60]}")

    # ---- JC-11 write failure propagates (never swallowed) ----------------
    dir_as_file = Path(tempfile.mkdtemp())          # path IS a directory
    j9 = EvidenceJournal(dir_as_file / "sub")        # parent ok, target valid
    (dir_as_file / "sub").mkdir()                    # make append target a dir
    try:
        j9.append("boom")
        check("JC-11", False, "write failure silently swallowed!")
    except OSError:
        check("JC-11", True, "unwritable journal -> OSError propagates to caller")

    # ---- JC-12 resume continues the chain correctly ----------------------
    j10, p10 = make_journal(3)
    j10b = EvidenceJournal(p10)  # reopen existing valid journal
    j10b.append("resumed")
    ok, _, detail = verify(p10)
    recs = j10b.read_all()
    check("JC-12", ok and len(recs) == 4 and recs[-1]["event"] == "resumed",
          f"reopened journal continues chain: {detail}")

print("-" * 78)
total = 12
print(f"JOURNAL CHAIN TESTS: {total - failures}/{total} checks passed")
sys.exit(1 if failures else 0)
