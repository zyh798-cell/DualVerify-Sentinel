"""Validate a machine-readable scope file before any active test.

This is the SINGLE source of truth for scope validation. It runs both as an
importable module (vuln_hunter.gate.window_error) and as a standalone command:

    python -m vuln_hunter.gate_check <scope.json>

Exits 0 when the scope is complete and confirmed, non-zero otherwise.
"""
import json
import sys
from datetime import datetime, timezone

REQUIRED = [
    "client",
    "in_scope",
    "out_of_scope",
    "window",
    "confirmed_by",
]

ALLOWED_TECHNIQUES_DEFAULT = {"non_destructive"}
DESTRUCTIVE = {"dos", "destructive", "mutation", "social_engineering"}


def window_error(window) -> str | None:
    """Return an error string if the authorization window is unparseable or not currently open."""
    if not isinstance(window, str) or "/" not in window:
        return "window must be a 'start/end' ISO-8601 string, e.g. 2026-11-01T09:00Z/2026-11-01T18:00Z"
    try:
        start_s, end_s = window.split("/", 1)
        start = datetime.fromisoformat(start_s.strip().replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_s.strip().replace("Z", "+00:00"))
    except ValueError:
        return f"unparseable window (expected 'start/end' ISO-8601): {window!r}"
    now = datetime.now(timezone.utc)
    if now < start:
        return f"authorization window not yet open: {window}"
    if now > end:
        return f"authorization window expired: {window}"
    return None


def _no_duplicate_keys(pairs):
    """object_pairs_hook that fails closed on duplicate JSON keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in scope file: {key}")
        result[key] = value
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: python -m vuln_hunter.gate_check <scope.json>", file=sys.stderr)
        return 2

    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh, object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError) as exc:
        print(f"scope file unreadable: {exc}", file=sys.stderr)
        return 1

    errors = []
    for field in REQUIRED:
        if not data.get(field):
            errors.append(f"missing or empty field: {field}")

    for field in ("in_scope", "out_of_scope"):
        val = data.get(field)
        if val and not (isinstance(val, list) and all(isinstance(x, str) for x in val)):
            errors.append(f"{field} must be a list of strings")

    if data.get("window"):
        window_problem = window_error(data["window"])
        if window_problem:
            errors.append(window_problem)

    raw = data.get("techniques")
    techniques = set()
    if raw is None or raw == []:
        # documented default: absent/empty list falls back to non-destructive only
        techniques = set(ALLOWED_TECHNIQUES_DEFAULT)
    elif isinstance(raw, list) and all(isinstance(t, str) for t in raw):
        techniques = {t.strip().lower() for t in raw}
        unknown = techniques - (ALLOWED_TECHNIQUES_DEFAULT | DESTRUCTIVE)
        if unknown:
            errors.append(
                f"unknown techniques (allowed: non_destructive): {sorted(unknown)}"
            )
    else:
        errors.append('techniques must be a list of strings, e.g. ["non_destructive"]')

    bad = sorted(techniques & DESTRUCTIVE)
    if bad:
        errors.append(
            f"destructive techniques present but not allowed by this skill: {bad}"
        )

    if errors:
        print("scope not acceptable:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"scope OK: {len(data['in_scope'])} in-scope asset(s), confirmed by {data['confirmed_by']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
