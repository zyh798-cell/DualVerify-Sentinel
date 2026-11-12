"""Unified Finding data structure (EXT-0).

This module is PURE ADDITION. It does not touch the execution chain:
existing Nuclei / Bandit / HTTP-probe adapters keep emitting their current
dict shapes unchanged, and nothing in the engine consumes Finding yet.
New tool adapters (gitleaks, semgrep, ...) can convert their raw records
into a Finding here, and future dedup / correlation / report layers get a
single canonical shape.

Schema (v1)
-----------
Required (non-empty str, validated & normalized at creation):
  tool          emitting tool id, e.g. "nuclei", "bandit", "http-probe"
  finding_type  raw-record type tag, e.g. "nuclei_finding", "http_service"
  title         human-readable headline (capped, deterministic truncation)
  severity      one of info|low|medium|high|critical (case-insensitive in,
                stored lowercase)
  target        what was scanned (URL, host, file, ...)
  location      precise match point (file:line, matched-at URL, ...)
  rule_id       tool rule / template / test id
  description   what the finding means (capped)

Optional:
  evidence            redacted, length-capped evidence string or None.
                      NEVER stored raw: secret-shaped content is replaced
                      by [REDACTED:<kind>] markers before storage.
  evidence_redacted   True when at least one redaction/truncation fired.
  references          tuple of non-empty reference strings, default ()

Computed (never accepted from callers — a supplied finding_id is an error):
  finding_id    "fnd_" + first 16 hex chars of
                sha256(canonical JSON of [tool, finding_type, target,
                location, rule_id]). Stable across runs/processes;
                two records with identical locator quintuples ARE the same
                finding for dedup purposes by design.

Normalizers convert the REAL raw dict shapes emitted by today's adapters
(see vuln_hunter/adapters.py):
  http_service   {type,url,status,server[,title]}
  nuclei_finding {type,template,severity,name,host,matched_at}
  bandit_finding {type,test_id,severity,filename,line,issue}
Unknown or malformed records raise FindingError — fail-closed, nothing
invalid ever silently enters the unified structure.

register_normalizer() is the documented extension point for future tools;
no future tool is wired here in EXT-0.

Security notes (honest limits):
- Evidence redaction is regex-based defense in depth, not a guarantee.
  It targets the common secret shapes (cloud keys, bearer/Basic/Digest
  auth credentials, JWT, key=value assignments, private key blocks).
  Callers must still avoid feeding full raw responses into evidence.
- Known unmodeled gaps (recorded, never claimed safe): credentials
  shorter than a pattern's minimum, pure-letter standalone Basic values,
  custom auth protocols, and bare opaque secrets without key context.
- All test fixtures in tests/test_findings_schema.py are fictional.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

SCHEMA_VERSION = 1

ALLOWED_SEVERITY = ("info", "low", "medium", "high", "critical")

# Deterministic length caps. Truncation appends a visible marker — it is a
# length bound, not a security mechanism.
_CAP_TITLE = 300
_CAP_TEXT = 2000
_CAP_LOCATION = 1000
_CAP_REFERENCE = 500
_CAP_EVIDENCE = 512
_TRUNCATION_MARKER = "…[truncated]"

_MISSING = object()


class FindingError(ValueError):
    """A record failed schema validation. Fail-closed: callers must not
    fall back to storing unvalidated data."""


def _cap(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    keep = limit - len(_TRUNCATION_MARKER)
    return value[:keep] + _TRUNCATION_MARKER


def _require_str(name: str, value, cap: int) -> str:
    if not isinstance(value, str):
        raise FindingError(f"{name} must be str, got {type(value).__name__}")
    if not value.strip():
        raise FindingError(f"{name} must be a non-empty string")
    return _cap(value, cap)


# --------------------------------------------------------------------------
# Evidence redaction — pattern-based, defense in depth. NOT a guarantee.
# Order matters (EXT-0.6 G1 regression): the Bearer scheme pattern MUST run
# BEFORE the generic key=value assignment pattern. Otherwise the assignment
# regex consumes the 'Bearer' keyword itself as the assignment value, and
# the token that follows survives redaction.
# EXT-0.7 hardening:
#   * The assignment pattern additionally recognizes "<scheme> <credential>"
#     values (bearer/basic/digest/token, ANY credential length) so that
#     header-context credentials cannot escape via the keyword — the scheme
#     and its credential are replaced together.
#   * Standalone Bearer accepts short credentials (>= 4 chars; shorter is
#     treated as prose, e.g. "bearer of bad news").
#   * Standalone Basic requires a base64-shaped credential (>= 8 chars of
#     [A-Za-z0-9+/=] containing a digit or +/=) so ordinary English prose
#     ("Basic authentication") is never damaged; non-conforming values are
#     left untouched (documented limitation, NOT silently "safe").
# --------------------------------------------------------------------------
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|api[_-]?secret|secret|token|password|passwd|pwd"
    r"|authorization|auth|credential[s]?|access[_-]?key)\b"
    r"(\s*[:=]\s*)(\"|')?"
    r"(?:(bearer|basic|digest|token)\s+([^\s\"',;&]{1,})|([^\s\"',;&\[\]]{6,}))"
)

_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{4,}")
_BASIC_RE = re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/=]{8,})")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GH_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9_-]{36}\b")
_SK_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"
)


def _assign_repl(m) -> str:
    """Assignment replacement. When the value is "<scheme> <credential>"
    the whole scheme+credential pair is replaced (any credential length);
    otherwise the plain value is replaced (min length 6, unchanged)."""
    if m.group(4):
        scheme = m.group(4).lower()
        return f"{m.group(1)}{m.group(2)}{m.group(3) or ''}[REDACTED:{scheme}-credentials]"
    return f"{m.group(1)}{m.group(2)}{m.group(3) or ''}[REDACTED:secret]"


def redact_evidence(text: str) -> tuple[str, int]:
    """Redact secret-shaped content and cap length.

    Returns (safe_text, redaction_count). Deterministic: identical input
    always yields identical output. Test fixtures are fictional; real
    secrets must never be pasted into evidence by adapter authors.

    Known limits (recorded, not "safe"): standalone credentials shorter
    than the per-pattern minimums, pure-letter standalone Basic values,
    and shapes no pattern models (custom auth protocols) are NOT redacted
    — this is defense in depth, never a guarantee.
    """
    count = 0
    out = text

    def _sub(pattern, repl):
        nonlocal out, count
        out, n = pattern.subn(repl, out)
        count += n

    _sub(_PRIVATE_KEY_RE, "[REDACTED:private-key-block]")
    # G1 fix: Bearer scheme BEFORE generic assignment (see comment above).
    _sub(_BEARER_RE, lambda m: f"{m.group(0).split()[0]} [REDACTED:bearer]")
    _sub(_SECRET_ASSIGN_RE, _assign_repl)
    # Standalone Basic: count only ACTUAL redactions — returning the match
    # unchanged (prose) must not inflate the count or set the flag.
    redacted_basic = 0

    def _basic_local(m):
        nonlocal redacted_basic
        cred = m.group(1)
        if any(c.isdigit() or c in "+/=" for c in cred):
            redacted_basic += 1
            return "[REDACTED:basic-credentials]"
        return m.group(0)

    out, _ = _BASIC_RE.subn(_basic_local, out)
    count += redacted_basic
    _sub(_AWS_KEY_RE, "[REDACTED:aws-access-key]")
    _sub(_GH_TOKEN_RE, "[REDACTED:github-token]")
    _sub(_SK_RE, "[REDACTED:api-key]")
    _sub(_JWT_RE, "[REDACTED:jwt]")

    before = len(out)
    out = _cap(out, _CAP_EVIDENCE)
    if len(out) != before:
        count += 1
    return out, count


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------
def _norm_severity_strict(value) -> str:
    if not isinstance(value, str):
        raise FindingError(f"severity must be str, got {type(value).__name__}")
    sev = value.strip().lower()
    if sev not in ALLOWED_SEVERITY:
        raise FindingError(
            f"severity must be one of {ALLOWED_SEVERITY}, got {value!r}"
        )
    return sev


def _norm_severity_lenient(value) -> str:
    """For normalizers: missing/None/'unknown' degrade to 'info'; anything
    else illegal is rejected."""
    if value is None:
        return "info"
    if not isinstance(value, str):
        raise FindingError(f"severity must be str or None, got {type(value).__name__}")
    sev = value.strip().lower()
    if sev in ALLOWED_SEVERITY:
        return sev
    if sev in ("unknown", "none", "none ", ""):
        return "info"
    raise FindingError(f"illegal severity {value!r} in raw record")


def _norm_references(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise FindingError("references must be a list/tuple of strings")
    refs = []
    for i, r in enumerate(value):
        if not isinstance(r, str) or not r.strip():
            raise FindingError(f"references[{i}] must be a non-empty string")
        refs.append(_cap(r, _CAP_REFERENCE))
    return tuple(refs)


def _compute_finding_id(tool: str, finding_type: str, target: str,
                        location: str, rule_id: str) -> str:
    payload = json.dumps(
        [tool, finding_type, target, location, rule_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"fnd_{digest[:16]}"


@dataclass(frozen=True)
class Finding:
    """Immutable, validated, unified finding record. See module docstring
    for the field contract. Create via the keyword constructor; finding_id
    is always computed here, never supplied.

    The 8 required fields carry a None default only so that OMITTING one
    raises FindingError (uniform fail-closed exception type) instead of a
    raw TypeError from the dataclass constructor — None never passes
    validation.
    """

    tool: str | None = None
    finding_type: str | None = None
    title: str | None = None
    severity: str | None = None
    target: str | None = None
    location: str | None = None
    rule_id: str | None = None
    description: str | None = None
    evidence: str | None = None
    evidence_redacted: bool = False
    references: tuple[str, ...] = ()
    finding_id: str = ""
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if self.finding_id:
            raise FindingError(
                "finding_id is computed internally; supplying it is not allowed"
            )
        tool = _require_str("tool", self.tool, 100)
        ftype = _require_str("finding_type", self.finding_type, 100)
        title = _cap(self._checked_str("title", self.title), _CAP_TITLE)
        severity = _norm_severity_strict(self.severity)
        target = _cap(self._checked_str("target", self.target), _CAP_TEXT)
        location = _cap(self._checked_str("location", self.location), _CAP_LOCATION)
        rule_id = _require_str("rule_id", self.rule_id, 200)
        description = _cap(self._checked_str("description", self.description), _CAP_TEXT)

        if self.evidence is None:
            evidence, redacted = None, False
        elif isinstance(self.evidence, str):
            evidence, n = redact_evidence(self.evidence)
            redacted = n > 0
        else:
            raise FindingError(
                f"evidence must be str or None, got {type(self.evidence).__name__}"
            )

        refs = _norm_references(self.references)

        if not isinstance(self.evidence_redacted, bool):
            raise FindingError("evidence_redacted must be bool")
        if not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool):
            raise FindingError("schema_version must be int")

        fid = _compute_finding_id(tool, ftype, target, location, rule_id)
        for attr, val in (
            ("tool", tool), ("finding_type", ftype), ("title", title),
            ("severity", severity), ("target", target), ("location", location),
            ("rule_id", rule_id), ("description", description),
            ("evidence", evidence), ("evidence_redacted", redacted),
            ("references", refs), ("finding_id", fid),
        ):
            object.__setattr__(self, attr, val)

    @staticmethod
    def _checked_str(name: str, value) -> str:
        if not isinstance(value, str):
            raise FindingError(f"{name} must be str, got {type(value).__name__}")
        if not value.strip():
            raise FindingError(f"{name} must be a non-empty string")
        return value

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "tool": self.tool,
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "location": self.location,
            "rule_id": self.rule_id,
            "description": self.description,
            "evidence": self.evidence,
            "evidence_redacted": self.evidence_redacted,
            "references": list(self.references),
        }

    @classmethod
    def from_dict(cls, d) -> "Finding":
        """Rebuild from to_dict() output and VERIFY the finding_id against a
        fresh recomputation (integrity check — a tampered id is rejected)."""
        if not isinstance(d, dict):
            raise FindingError(f"from_dict expects dict, got {type(d).__name__}")
        required = (
            "tool", "finding_type", "title", "severity", "target",
            "location", "rule_id", "description",
        )
        missing = [k for k in required if k not in d]
        if missing:
            raise FindingError(f"missing required key(s): {', '.join(missing)}")
        f = cls(
            tool=d["tool"],
            finding_type=d["finding_type"],
            title=d["title"],
            severity=d["severity"],
            target=d["target"],
            location=d["location"],
            rule_id=d["rule_id"],
            description=d["description"],
            evidence=d.get("evidence"),
            references=d.get("references") or (),
        )
        supplied = d.get("finding_id")
        if supplied != f.finding_id:
            raise FindingError(
                f"finding_id mismatch: supplied {supplied!r}, recomputed {f.finding_id!r}"
            )
        return f


# --------------------------------------------------------------------------
# Normalizers — exact conversions from the REAL raw dict shapes in
# vuln_hunter/adapters.py. Nothing in the engine calls these in EXT-0;
# they exist so future adapters/layers have one obvious entry point.
# --------------------------------------------------------------------------
def normalize_http_service(raw: dict) -> Finding:
    """HTTPProbeAdapter finding shape:
    {"type": "http_service", "url": str, "status": int, "server": str
     [, "title": str]}  (adapters.py L260-265)"""
    status = raw.get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        raise FindingError(f"http_service: status must be int, got {status!r}")
    url = raw.get("url")
    if not isinstance(url, str) or not url.strip():
        raise FindingError("http_service: url must be a non-empty string")
    server = raw.get("server") or ""
    if not isinstance(server, str):
        raise FindingError("http_service: server must be str or missing")
    page_title = raw.get("title") or ""
    if not isinstance(page_title, str):
        raise FindingError("http_service: title must be str or missing")
    desc = f"HTTP service responded {status}"
    if server:
        desc += f" (Server: {server})"
    return Finding(
        tool="http-probe",
        finding_type="http_service",
        title=page_title.strip() or f"HTTP {status}",
        severity="info",  # shape carries no severity; deterministic default
        target=url,
        location=url,
        rule_id="http-probe",  # synthetic, documented
        description=desc,
    )


def normalize_nuclei_finding(raw: dict) -> Finding:
    """NucleiAdapter finding shape:
    {"type": "nuclei_finding", "template": str|None, "severity": str|None,
     "name": str|None, "host": str|None, "matched_at": str|None}
    (adapters.py L494-503). host/matched_at must resolve; template-less
    records get rule_id "unknown"; missing severity degrades to info."""
    host = raw.get("host")
    matched_at = raw.get("matched_at")
    if not isinstance(host, str) or not host.strip():
        raise FindingError("nuclei_finding: host missing or not a string")
    location = matched_at if isinstance(matched_at, str) and matched_at.strip() else host
    template = raw.get("template")
    rule_id = template.strip() if isinstance(template, str) and template.strip() else "unknown"
    name = raw.get("name")
    name = name.strip() if isinstance(name, str) else ""
    title = name or (f"nuclei template {rule_id}")
    return Finding(
        tool="nuclei",
        finding_type="nuclei_finding",
        title=title,
        severity=_norm_severity_lenient(raw.get("severity")),
        target=host,
        location=location,
        rule_id=rule_id,
        description=f"nuclei template match: {name} (template {rule_id})",
    )


def normalize_bandit_finding(raw: dict) -> Finding:
    """BanditAdapter finding shape:
    {"type": "bandit_finding", "test_id": str, "severity": str,
     "filename": str, "line": int, "issue": str} (adapters.py L542-551)."""
    test_id = raw.get("test_id")
    if not isinstance(test_id, str) or not test_id.strip():
        raise FindingError("bandit_finding: test_id missing or not a string")
    filename = raw.get("filename")
    if not isinstance(filename, str) or not filename.strip():
        raise FindingError("bandit_finding: filename missing or not a string")
    line = raw.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
        raise FindingError(f"bandit_finding: line must be int or None, got {line!r}")
    issue = raw.get("issue") or ""
    if not isinstance(issue, str):
        raise FindingError("bandit_finding: issue must be str or missing")
    location = f"{filename}:{line}" if line is not None else filename
    fallback = f"bandit rule {test_id}"
    return Finding(
        tool="bandit",
        finding_type="bandit_finding",
        title=issue.strip() or fallback,
        severity=_norm_severity_lenient(raw.get("severity")),
        target=filename,
        location=location,
        rule_id=test_id,
        description=issue.strip() or fallback,
    )


NORMALIZERS: dict[str, callable] = {
    "http_service": normalize_http_service,
    "nuclei_finding": normalize_nuclei_finding,
    "bandit_finding": normalize_bandit_finding,
}


def register_normalizer(type_name: str, fn) -> None:
    """Documented extension point for FUTURE tool adapters (EXT-1+).
    Registers fn(raw_dict) -> Finding under raw["type"] == type_name.
    Duplicate registration is rejected to prevent accidental shadowing.
    Registration alone grants no execution rights — it is pure data
    conversion, mirroring the register_adapter() philosophy."""
    if not isinstance(type_name, str) or not type_name.strip():
        raise FindingError("register_normalizer: type_name must be a non-empty string")
    if not callable(fn):
        raise FindingError("register_normalizer: fn must be callable")
    if type_name in NORMALIZERS:
        raise FindingError(f"register_normalizer: {type_name!r} is already registered")
    NORMALIZERS[type_name] = fn


def normalize(raw) -> Finding:
    """Convert any registered raw finding record into a Finding.
    Fail-closed: non-dict input, missing/unknown type tag, or a normalizer
    rejection all raise FindingError."""
    if not isinstance(raw, dict):
        raise FindingError(
            f"normalize expects dict, got {type(raw).__name__}"
        )
    type_name = raw.get("type")
    if not isinstance(type_name, str) or not type_name.strip():
        raise FindingError("normalize: raw record has no 'type' tag")
    fn = NORMALIZERS.get(type_name)
    if fn is None:
        raise FindingError(
            f"normalize: unknown finding type {type_name!r}; "
            f"known types: {sorted(NORMALIZERS)}"
        )
    return fn(raw)


__all__ = [
    "SCHEMA_VERSION",
    "ALLOWED_SEVERITY",
    "Finding",
    "FindingError",
    "redact_evidence",
    "normalize",
    "normalize_http_service",
    "normalize_nuclei_finding",
    "normalize_bandit_finding",
    "register_normalizer",
]
