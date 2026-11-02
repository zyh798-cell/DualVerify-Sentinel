"""Evidence journal: append-only, hash-chained JSONL (one line per event).

Integrity model (S1):
- Every record carries `seq` (0-based), `prev` (chain hash of the previous
  record; "0"*64 for the genesis record) and `h` (sha256 over the canonical
  JSON of {"seq", "prev", "rec"}).
- `verify(path)` recomputes the whole chain and reports the first bad seq.
- `head(path)` returns the chain anchor (last record's `h`) so an operator can
  store it externally; with an external anchor, tail truncation IS detectable
  (a truncated file has a different head). Without an external anchor,
  truncation of the tail is NOT detectable — this is documented honestly.

Fail-closed behaviour:
- Appending to a journal whose last line is corrupt/tampered raises
  JournalIntegrityError instead of continuing the chain from bad state.
- Write errors (OSError) propagate to the caller: a step that cannot be
  journaled fails loudly — journal failures are never swallowed.

Legacy records (no seq/prev/h, e.g. written before S1) make verify() report
`UNVERIFIED` for that seq; they do not break the chain after them because
their stored `h` is absent — verify treats a legacy record as a break point
and reports it (fail-closed reporting, never silent success).

Single-process only: no file locking. Concurrent writers corrupt the chain.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS_PREV = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JournalIntegrityError(Exception):
    """The on-disk journal failed integrity validation (corrupt/tampered)."""


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")


def _record_hash(seq: int, prev: str, rec: dict) -> str:
    return hashlib.sha256(
        _canonical({"seq": seq, "prev": prev, "rec": rec})
    ).hexdigest()


def _parse(path: Path) -> list[dict]:
    """Read all records. Raises JournalIntegrityError on unreadable JSON."""
    if not path.exists():
        return []
    out = []
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError as exc:
            raise JournalIntegrityError(
                f"{path}: line {lineno} is not valid JSON: {exc}"
            ) from exc
    return out


def verify(path) -> tuple[bool, int | None, str]:
    """Verify the hash chain of a journal file.

    Returns (ok, first_bad_seq, detail). ok=True means every record's chain
    hash recomputes correctly. Legacy records (missing seq/prev/h) are
    reported as UNVERIFIED at their position — never silently accepted.
    """
    path = Path(path)
    recs = _parse(path)
    prev = GENESIS_PREV
    for i, rec in enumerate(recs):
        seq = rec.get("seq")
        if not isinstance(seq, int) or seq != i:
            return False, i, f"seq missing/out of order at line {i + 1}"
        if rec.get("prev") != prev:
            return False, i, f"prev-hash mismatch at seq {i} (chain broken)"
        if "h" not in rec or "rec" not in rec:
            return False, i, f"legacy/unhashed record at seq {i} (UNVERIFIED)"
        expect = _record_hash(seq, prev, rec["rec"])
        if rec["h"] != expect:
            return False, i, f"hash mismatch at seq {i} (record tampered)"
        prev = rec["h"]
    return True, None, f"chain OK ({len(recs)} record(s))"


def head(path) -> str | None:
    """Chain anchor: the `h` of the last record, or None for an empty journal.

    Store this value externally (e.g. in the run report) to make tail
    truncation detectable later."""
    recs = _parse(Path(path))
    return recs[-1].get("h") if recs else None


def audit_status(path) -> dict:
    """One-call audit snapshot: chain verification, head anchor and count.

    Returns {"ok": bool, "detail": str, "head": str|None, "count": int}.
    Raises JournalIntegrityError only for unreadable JSON (verify() itself
    reports structural/tamper problems via ok=False without raising)."""
    path = Path(path)
    recs = _parse(path)  # may raise JournalIntegrityError (corrupt JSON)
    ok, bad, detail = verify(path)
    return {
        "ok": ok,
        "detail": detail,
        "head": recs[-1].get("h") if recs else None,
        "count": len(recs),
    }


class EvidenceJournal:
    def __init__(self, jsonl_path):
        self.path = Path(jsonl_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = -1
        self._prev = GENESIS_PREV
        if self.path.exists():
            recs = _parse(self.path)
            if recs:
                ok, bad, detail = verify(self.path)
                if not ok:
                    raise JournalIntegrityError(
                        f"refusing to append to journal that fails integrity: {detail}"
                    )
                self._seq = recs[-1]["seq"]
                self._prev = recs[-1]["h"]

    def append(self, event: str, **fields) -> dict:
        """Append one event as a chained record. Write errors propagate to
        the caller (fail-closed: an unwritable journal aborts the run)."""
        seq = self._seq + 1
        inner = {"ts": utcnow(), "event": event, **fields}
        line = {
            "seq": seq,
            "prev": self._prev,
            "rec": inner,
            "h": _record_hash(seq, self._prev, inner),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        self._seq = seq
        self._prev = line["h"]
        return inner

    def read_all(self) -> list[dict]:
        """Return the inner records (ts/event/fields) in file order.
        Raises JournalIntegrityError on corrupt JSON (fail-closed)."""
        return [line["rec"] if "rec" in line else line for line in _parse(self.path)]

    def head(self) -> str | None:
        return head(self.path)

    def verify(self) -> tuple[bool, int | None, str]:
        return verify(self.path)

    def audit_status(self) -> dict:
        return audit_status(self.path)
