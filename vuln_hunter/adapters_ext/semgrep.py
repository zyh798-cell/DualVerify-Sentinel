"""Semgrep adapter (EXT-2) — multi-language static analysis, metadata-only findings.

SECURITY CONTRACT (highest priority; a scan report can contain source code):
- The semgrep JSON report is treated as hostile. Only a FIXED WHITELIST of
  metadata fields is ever read per result: `check_id`, `path`,
  `start.line`/`end.line`, `extra.severity`, `extra.message`,
  and a sub-whitelist of `extra.metadata` keys (see `_METADATA_WHITELIST`).
- `extra.lines` (the MATCHED SOURCE CODE) and every other field are NEVER
  read, logged, or stored. Regex redaction in findings.py is a secondary net,
  NOT the security boundary — the boundary is whitelist extraction.
- Raw tool output never reaches logs, findings, detail strings, exception
  messages, or adapter meta — only the command line (paths/flags only),
  exit code, and record counts.
- Local directory scans only. The target must be an existing directory and
  must NOT be a filesystem/drive root or the user home directory
  (adapter-level guard; the PolicyEngine remains the authorization
  authority). No rule download: the rules source must be a LOCAL file or
  directory supplied by the operator. Registry/auto config is NOT used —
  a missing rules source is a configuration error, never an implicit
  network fetch.
- Failure paths (bad exit code, invalid JSON, timeout, tool errors,
  malformed record) return safe status strings with no raw output.

NO NETWORK / NO AUTO-INSTALL:
- `--metrics off` (no telemetry). `SEMGREP_ENABLE_VERSION_CHECK=false` is set
  in the subprocess environment as a version-robust belt-and-braces against a
  version-check ping; an unknown env var is ignored harmlessly.
- `--disable-version-check` is deliberately NOT passed as a CLI flag, and
  neither is `--quiet`: EXT-1 established the discipline of using only
  long-stable flags so a tool release cannot silently break every run. A
  version that drops a used flag fails closed (non-zero exit -> FAILED),
  never silently.
- The binary is NOT auto-installed; preflight() reports when it is missing.

EXIT-CODE SEMANTICS (CR-01 remediation; verified-flag discipline kept):
  Only rc == 0 is accepted as a COMPLETED scan. The command deliberately
  does NOT pass `--error` (no optional-flag dependency, see below), so NO
  non-zero exit code has a proven "findings found" meaning: rc=1 and every
  other non-zero exit are reported FAILED (fail-closed) and NO findings are
  harvested. Findings are taken EXCLUSIVELY from a valid, complete `results[]`
  JSON object — the exit code is NEVER used to infer findings. A blank
  stdout is NEVER treated as a clean result — it fails closed.
  CR-02: a NON-EMPTY `errors` array, a MISSING `errors`/`paths` field, or an
  UNEXPLAINED `paths.skipped` entry means the scan was INCOMPLETE: the step
  fails closed and NO findings are harvested from an incomplete scan (the
  engine's existing discipline — cf. adapters.NucleiAdapter, which also
  refuses to present partial results of a non-zero exit as success).

FUTURE WIRING NOTE (EXT-2): planner.build_plan emits the "s5-semgrep" step
when a source tree is given AND the binary resolves AND a LOCAL rules source
is configured; the step passes target_kind="fs_path" (same as bandit and
gitleaks). The inherited execute() gate (RunTicket + live policy + mode
ceiling) applies unchanged.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from ..adapters import AdapterResult, ToolAdapter, tool_env
from ..findings import Finding, FindingError

SEMGREP_FALLBACKS = [
    Path.home() / "Tools" / "semgrep" / "semgrep.exe",
    Path.home() / "Tools" / "semgrep" / "semgrep",
]

# Metadata keys read from a semgrep result's `extra.metadata`. Deliberately
# EXCLUDES `lines` (matched source code), `fingerprint`, and every other
# field — whitelist, never blacklist.
_METADATA_WHITELIST = ("cwe", "confidence", "category", "subcategory",
                       "likelihood", "impact", "owasp")

# semgrep's `extra.severity` (a TOOL-REPORTED fact) -> unified Finding
# severity. STRICT allowlist: an unknown or missing severity invalidates the
# record (fail-closed) instead of silently downgrading it to "info".
#
# The official vocabulary has NINE values (semgrep JSON schema
# `match_severity`): ERROR, WARNING, EXPERIMENT, INVENTORY, CRITICAL, HIGH,
# MEDIUM, LOW, INFO. Mapping basis — official rule-syntax docs (quoted
# verbatim in the Phase A gap analysis §8.1):
#   "Severity can be LOW, MEDIUM, HIGH, or CRITICAL. ... The older levels
#    ERROR, WARNING, and INFO match HIGH, MEDIUM, and LOW."
# and the schema description:
#   "Error -> High, Warning -> Medium. Critical/Low are the only really new
#    category here without equivalent before. Experiment and Inventory above
#    should be removed. Info can be kept."
#
# EXT-2 batch-1 decisions (D1/D2, user-approved 2026-11-11):
#   ERROR / WARNING                -> high / medium   (official legacy mapping)
#   CRITICAL / HIGH / MEDIUM / LOW -> critical / high / medium / low
#   INFO                           -> info   (D1: keep existing semantics)
#   EXPERIMENT / INVENTORY         -> info   (D2: legacy categories mapped to
#                                 info, but the ORIGINAL category token is
#                                 preserved in the finding name for audit and
#                                 never presented as an ordinary vulnerability)
# Unknown / missing / non-string values still raise FindingError (fail-closed).
_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "experiment": "info",
    "inventory": "info",
}

# EXT-2 (T-severity): semgrep's severity vocabulary. The unified Finding
# schema requires info|low|medium|high|critical, so the mapping above is the
# SYSTEM's documented translation — it is NOT a value semgrep reported and
# must never be presented as one. Reports/labels call it a mapping, not a
# tool fact.
SEMGREP_SEVERITY_MAP = dict(_SEVERITY_MAP)


# ---------------------------------------------------------------------------
# CR-03 remediation: untrusted-output VALUE sanitisation.
# Whitelisting FIELD NAMES is not enough: their VALUES can carry terminal
# control characters, line breaks (which would forge new lines in the
# plain-text attempt log and in the frozen Markdown renderer) and Markdown
# metacharacters. Sanitisation is deliberately INERT-TEXT PRESERVING:
# characters are escaped / replaced, never deleted, so readable evidence
# survives; no record is dropped merely because it looks odd (records are
# skipped only by the existing Finding schema validation).
# ---------------------------------------------------------------------------
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_MARKDOWN_SPECIALS = ("\\", "|", "`", "*", "_", "[", "]", "<", ">", "#")
_SANITIZATION_NOTE = ("untrusted values: control chars/newlines neutralised, "
                      "Markdown metacharacters escaped; text preserved")


def _sanitize(value: str) -> str:
    """Return a single-line, printable, report-safe form of an untrusted
    tool-output string. Evidence text is preserved (escaped, not discarded)."""
    out = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    out = _CONTROL_RE.sub(" ", out)
    out = " ".join(out.split())
    for ch in _MARKDOWN_SPECIALS:
        out = out.replace(ch, "\\" + ch)
    return out


def _log_line(value: str) -> str:
    """Same control/line-break neutralisation for operator-supplied values
    echoed into the command line of the plain-text attempt log; no Markdown
    escaping here so paths stay readable."""
    out = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return " ".join(_CONTROL_RE.sub(" ", out).split())


# ---------------------------------------------------------------------------
# CR-02 remediation: scan-completeness classification (COMPATIBILITY SHIM).
# The frozen core status enum (runner.STATUS_PRIORITY) has NO `PARTIAL`
# bucket, and runner._summary_bucket() maps ANY unrecognized status to
# FAILED. We therefore DO NOT introduce a new AdapterResult.status value and
# DO NOT touch any frozen file. The three completeness levels live in
# meta["completeness"] + a detail prefix (rendered into the step table by the
# frozen report.py) + journal attempt meta:
#   COMPLETE    -> status COMPLETED, findings harvested
#   PARTIAL     -> status COMPLETED, findings harvested, but explicitly
#                  labelled "not a complete scan" in detail/meta
#   INCOMPLETE  -> status FAILED, NO findings harvested (fail-closed)
# ---------------------------------------------------------------------------
_SKIP_REASON_KEYS = ("reason", "type", "message", "code")


def _skip_explained(item) -> bool:
    """A skipped path is EXPLAINED only when semgrep supplies a non-empty
    reason-like field. A bare path string / odd shape is unexplained and must
    never be reported as a complete scan."""
    if not isinstance(item, dict):
        return False
    return any(
        isinstance(item.get(k), str) and item[k].strip()
        for k in _SKIP_REASON_KEYS
    )


def _completeness(data: dict) -> tuple[str, list[str], int]:
    """Classify report completeness. Called ONLY after structural validation
    (results/errors/paths/paths.skipped types). Reasons are value-free fixed
    strings + counts: no raw tool text ever enters detail/meta/journal."""
    reasons: list[str] = []
    level = "COMPLETE"

    if "errors" not in data:
        reasons.append("report lacks 'errors' field; completeness unverified")
        level = "INCOMPLETE"
    elif data["errors"]:
        reasons.append(f"{len(data['errors'])} scan error(s) reported")
        level = "INCOMPLETE"

    paths = data.get("paths")
    if not isinstance(paths, dict):
        reasons.append("report lacks a 'paths' object; coverage unverified")
        level = "INCOMPLETE"
        skipped: list = []
    elif "skipped" not in paths:
        reasons.append("report lacks 'paths.skipped'; skipped files cannot be ruled out")
        level = "INCOMPLETE"
        skipped = []
    else:
        skipped = paths["skipped"]
        unexplained = sum(1 for it in skipped if not _skip_explained(it))
        if skipped:
            if unexplained:
                reasons.append(
                    f"{len(skipped)} skipped path(s), {unexplained} without a stated reason")
                level = "INCOMPLETE"
            else:
                reasons.append(
                    f"{len(skipped)} skipped path(s), all with a stated reason")
                if level != "INCOMPLETE":
                    level = "PARTIAL"
    return level, reasons, len(skipped)


def _meta(completeness: str, reasons: list[str], *, records_seen: int = 0,
          records_used: int = 0, records_skipped: int = 0,
          errors_seen: int = 0, paths_skipped: int = 0,
          skip_counts: dict | None = None) -> dict:
    """Uniform, value-free audit meta for every terminal result.

    `skip_counts` (when given) is a structured, fixed-category count of
    harvested-record skips: {"unsupported_severity": int, "malformed_record":
    int}. It contains NO tool values — only fixed category names and counts.
    """
    meta = {
        "env_policy": "direct",
        "completeness": completeness,
        "completeness_reasons": list(reasons),
        "records_seen": records_seen,
        "records_used": records_used,
        "records_skipped": records_skipped,
        "errors_seen": errors_seen,
        "paths_skipped": paths_skipped,
        "sanitization": _SANITIZATION_NOTE,
    }
    if skip_counts:
        meta["skip_counts"] = dict(skip_counts)
    return meta


def semgrep_binary() -> str | None:
    """Resolve the semgrep executable without instantiating the adapter.

    Single source of truth for "is the tool available?" — used by the planner
    to decide whether to emit the s5-semgrep step, and by the adapter's
    binary()/preflight(). Resolution only; NEVER spawns anything.
    """
    exe = shutil.which("semgrep")
    if exe:
        return exe
    for p in SEMGREP_FALLBACKS:
        if p.exists():
            return str(p)
    return None


class SemgrepAdapter(ToolAdapter):
    id = "semgrep"
    risk = "R1"
    description = "semgrep multi-language static analysis (metadata-only findings)."

    def binary(self) -> str | None:
        return semgrep_binary()

    def preflight(self) -> str | None:
        if self.binary() is None:
            where = (SEMGREP_FALLBACKS[0].parent if SEMGREP_FALLBACKS
                     else Path.home() / "Tools" / "semgrep")
            return (f"semgrep binary not found on PATH or in {where} "
                    "(requires semgrep with the `scan` subcommand)")
        return None

    def build_command(self, target: str, step: dict | None = None) -> list[str]:
        """EXT-2 command contract (verified-flag discipline):
          scan            multi-language scan subcommand (long-stable)
          <target>        the scanned directory
          --config <p>    LOCAL rules file/dir — never the registry/auto
          --json          machine-readable report on stdout
          --metrics off   no telemetry (no outbound call)
        `--quiet`, `--disable-version-check` and other convenience flags are
        deliberately unused: a tool release that drops a flag would otherwise
        break every run. The version-check ping is suppressed through the
        subprocess ENVIRONMENT instead (see `_spawn`), which is ignored
        harmlessly when a version does not know it.
        """
        step = step or {}
        rules = str(step.get("semgrep_rules") or "")
        return [self.binary() or "semgrep", "scan", target,
                "--config", rules,
                "--json",
                "--metrics", "off"]

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        refuse = _refuse_reason(target)
        if refuse:
            return AdapterResult("FAILED", False, refuse)

        step = step or {}
        rules = step.get("semgrep_rules")
        if not (isinstance(rules, str) and rules.strip()):
            # A missing rules source is an OPERATOR CONFIGURATION ERROR. The
            # adapter never falls back to semgrep's registry/auto config:
            # that would download rules over the network without an audited
            # scope decision. Fail closed instead.
            return AdapterResult(
                "FAILED", False,
                "no semgrep rules configured: a LOCAL rules file or directory "
                "must be supplied (registry/auto config is not used — no "
                "network, no implicit rule download)")
        if not Path(rules).exists():
            return AdapterResult(
                "FAILED", False,
                f"semgrep rules not found: {rules} (a LOCAL rules file or "
                f"directory must exist)")

        exe = self.binary()
        if exe is None:
            return AdapterResult("FAILED", False, self.preflight())

        cmd = self.build_command(target, step)
        # CR-03: operator-supplied target/rules may contain line breaks;
        # keep the echoed command line a single inert line in the log.
        log.write("$ " + " ".join(_log_line(str(part)) for part in cmd) + "\n")
        log.write(f"[budget] timeout={timeout}s env=proxy-sanitized(direct) "
                  f"metrics=off version-check=env-disabled\n")

        try:
            proc = _spawn(cmd, timeout)
        except subprocess.TimeoutExpired:
            log.write("semgrep timeout (no partial output retained)\n")
            return AdapterResult("TIMEOUT", False, f"semgrep exceeded {timeout}s")
        except Exception as exc:  # noqa: BLE001 - honest failure reporting
            return AdapterResult(
                "FAILED", False,
                f"semgrep spawn failed: {exc.__class__.__name__}")

        rc = proc.returncode
        # EXT-2 stdout/stderr lifecycle: `stdout` is the ONLY place raw tool
        # output ever exists. It stays a local str, is parsed immediately
        # below, and is NEVER written to the log, detail, meta, journal,
        # exception text or report. `_spawn` captures stderr, but this adapter
        # deliberately never reads proc.stderr. Every failure path below uses
        # fixed strings + exit code + counts only.
        stdout = proc.stdout or ""

        # CR-01: only rc == 0 is a PROVEN completed scan. The command does
        # NOT pass `--error`, so no non-zero exit code has a documented
        # "findings found" meaning. Findings are taken exclusively from a
        # valid, complete `results[]` object — NEVER inferred from rc.
        if rc != 0:
            reason = f"non-zero exit {rc} (no --error flag: unproven)"
            log.write(f"semgrep exit {rc} -> FAILED ({reason})\n")
            return AdapterResult(
                "FAILED", False,
                f"semgrep exit {rc} (non-zero exit is not treated as a "
                f"completed scan; no findings harvested)",
                meta=_meta("INCOMPLETE", [reason]))

        if not stdout.strip():
            # A successful scan emits a JSON object thanks to --json. A BLANK
            # stdout therefore means the tool did not produce a usable report;
            # it must NEVER be reported as a clean result (nor harvested for
            # findings). Fail closed.
            log.write("semgrep exit 0, empty report -> fail-closed\n")
            return AdapterResult(
                "FAILED", False,
                "semgrep exit 0, empty report (fail-closed: no clean result assumed)",
                meta=_meta("INCOMPLETE", ["blank report: no JSON object"]))

        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            log.write("semgrep output not valid JSON (raw output discarded)\n")
            return AdapterResult(
                "FAILED", False, "semgrep output not valid JSON",
                meta=_meta("INCOMPLETE", ["stdout is not valid JSON"]))
        if not isinstance(data, dict):
            return AdapterResult(
                "FAILED", False, "semgrep report is not a JSON object",
                meta=_meta("INCOMPLETE", ["report is not a JSON object"]))

        # Structural validation (unchanged fail-closed contract).
        if "results" not in data:
            return AdapterResult(
                "FAILED", False, "semgrep report has no 'results' array",
                meta=_meta("INCOMPLETE", ["report has no 'results' array"]))
        raw_results = data["results"]
        if not isinstance(raw_results, list):
            return AdapterResult(
                "FAILED", False, "semgrep report 'results' is not a list",
                meta=_meta("INCOMPLETE", ["'results' is not a list"]))
        raw_errors = data.get("errors", [])
        if not isinstance(raw_errors, list):
            return AdapterResult(
                "FAILED", False, "semgrep report 'errors' is not a list",
                meta=_meta("INCOMPLETE", ["'errors' is not a list"]))
        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            return AdapterResult(
                "FAILED", False, "semgrep report 'paths' is not an object",
                meta=_meta("INCOMPLETE", ["'paths' is not an object"]))
        skipped_paths = paths.get("skipped", [])
        if not isinstance(skipped_paths, list):
            return AdapterResult(
                "FAILED", False, "semgrep report 'paths.skipped' is not a list",
                meta=_meta("INCOMPLETE", ["'paths.skipped' is not a list"]))

        # CR-02: completeness classification. NO new status value is emitted
        # (see the compatibility shim above); INCOMPLETE fails closed and
        # harvests NOTHING, PARTIAL is explicitly labelled as not complete.
        level, reasons, skipped_count = _completeness(data)
        if level == "INCOMPLETE":
            log.write("[completeness=INCOMPLETE] results incomplete "
                      "(fail-closed, no findings harvested)\n")
            return AdapterResult(
                "FAILED", False,
                "[completeness=INCOMPLETE] " + "; ".join(reasons)
                + "; results incomplete (fail-closed: not reported as a "
                  "complete scan, no findings harvested)",
                meta=_meta("INCOMPLETE", reasons,
                           records_seen=len(raw_results),
                           errors_seen=len(raw_errors),
                           paths_skipped=skipped_count))

        findings = []
        skipped = 0
        # D6: structured, fixed-category skip counts (no tool values).
        skip_counts = {"unsupported_severity": 0, "malformed_record": 0}
        mapping_phrase = " / ".join(
            f"{k.upper()}→{v}" for k, v in _SEVERITY_MAP.items())
        for i, rec in enumerate(raw_results):
            try:
                f = _to_finding(rec, target)
            except FindingError as exc:
                # Message is value-free by construction (field names only).
                msg = str(exc)
                if "unsupported or missing severity" in msg:
                    skip_counts["unsupported_severity"] += 1
                else:
                    skip_counts["malformed_record"] += 1
                skipped += 1
                log.write(f"record {i} skipped: {msg}\n")
                continue
            d = f.to_dict()
            # EXT-2 renderer-compatibility alias. The frozen report.py finding
            # line reads legacy keys (name/template/issue/type); unified-schema
            # findings carry title/finding_type, so without this alias every
            # unified finding renders as "**high** None".
            #
            # The SAME alias also states where the severity came from: semgrep
            # DOES report a severity, so the value is the documented MAPPING
            # (see _SEVERITY_MAP), not a value the unified schema invented and
            # not a raw tool token. report.py renders `name` verbatim, so a
            # reader can always tell a mapped tool fact from a system default.
            # ADDITIVE OUTPUT ONLY: the 13 Finding schema fields are untouched,
            # and no extra key is introduced beyond this existing alias.
            # CR-03: f.title is built from a SANITISED check_id, so no
            # untrusted value can forge a report line here.
            # W1-05 (batch 1): the mapping phrase is generated from the live
            # _SEVERITY_MAP instead of a hardcoded 3-value string, so extending
            # the vocabulary cannot leave the label stale.
            # Follow-up: teach report.py the unified schema and drop the shim.
            name = (
                f"{f.title} "
                f"[severity={f.severity} 由 Semgrep 报告的 severity 字段经 "
                f"{mapping_phrase} 映射得到"
            )
            # D2: preserve the ORIGINAL category token for legacy values so
            # they stay auditable and are never presented as ordinary
            # vulnerabilities. The token is a fixed-vocabulary value reached
            # only via the whitelist branch below (experiment/inventory).
            raw_sev = _raw_severity(rec)
            if raw_sev in ("experiment", "inventory"):
                name += (f"；原始类别 {raw_sev.upper()} 为官方遗留值"
                         f"（schema 标注 should be removed），系统映射为 info "
                         f"并保留类别标识")
            name += "；非 DualVerify-Sentinel 自行判定]"
            d["name"] = name
            findings.append(d)
            log.write(f"  {f.rule_id} {f.location}\n")

        # D3: a scan that skipped records is NOT a complete scan. Downgrade
        # COMPLETE -> PARTIAL (the existing compatibility-shim level) so the
        # frozen report step table shows [completeness=PARTIAL]. INCOMPLETE
        # already returned above; an existing PARTIAL (explained paths.skipped)
        # is preserved as-is.
        total_skipped = sum(skip_counts.values())
        if total_skipped and level == "COMPLETE":
            level = "PARTIAL"
            reasons.append(
                f"{total_skipped} record(s) skipped "
                f"(unsupported severity/shape)")

        detail = f"[completeness={level}] semgrep exit {rc}, {len(findings)} finding(s)"
        if total_skipped:
            cats = ", ".join(f"{v} {k.replace('_', ' ')}"
                             for k, v in skip_counts.items() if v)
            detail += f", {total_skipped} record(s) skipped ({cats})"
        if reasons:
            detail += "; " + "; ".join(reasons)
        log.write(f"semgrep exit {rc}, {len(findings)} finding(s) "
                  f"from {len(raw_results)} record(s), {total_skipped} skipped "
                  f"(unsupported_severity={skip_counts['unsupported_severity']}, "
                  f"malformed_record={skip_counts['malformed_record']})\n")
        return AdapterResult(
            "COMPLETED", True, detail, findings,
            meta=_meta(level, reasons,
                       records_seen=len(raw_results),
                       records_used=len(findings),
                       records_skipped=total_skipped,
                       errors_seen=0,
                       paths_skipped=skipped_count,
                       skip_counts=skip_counts))


def _spawn(cmd, timeout: int):
    """Single subprocess seam — tests replace this with a fake. Same
    proxy-sanitized environment as built-in adapters, plus the semgrep
    version-check suppression (an unknown env var is ignored harmlessly by
    any semgrep version, which is why this is done here and not via a CLI
    flag)."""
    env = tool_env()
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "false"
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env)


def _refuse_reason(target: str) -> str | None:
    """Adapter-level scope guard (defense in depth; the policy engine
    remains authoritative). Refuses non-directories, filesystem/drive
    roots and the user home directory."""
    p = Path(target)
    if not p.is_dir():
        return f"source dir not found: {target}"
    try:
        rp = p.resolve()
    except OSError:
        return f"cannot resolve source dir: {target}"
    if rp == Path(rp.anchor):
        return "refusing to scan a filesystem/drive root (adapter-level scope guard)"
    try:
        home = Path.home().resolve()
    except OSError:
        home = None
    if home is not None and rp == home:
        return "refusing to scan the user home directory (adapter-level scope guard)"
    return None


def _str_field(rec: dict, name: str) -> str:
    """CR-03: every whitelisted string value is sanitised before it can
    reach a Finding, the plain-text attempt log or the Markdown report."""
    val = rec.get(name)
    if val is None:
        return ""
    if not isinstance(val, str):
        raise FindingError(f"semgrep record: {name} must be a string")
    return _sanitize(val.strip())


def _line(node):
    """start/end line number, or None when absent/malformed (never invented)."""
    if not isinstance(node, dict):
        return None
    val = node.get("line")
    if val is None:
        return None
    if not isinstance(val, int) or isinstance(val, bool):
        return None
    return val


def _location(rec: dict, path: str) -> str:
    """path / path:line / path:start-end — mirrors the gitleaks location rule."""
    sline = _line(rec.get("start"))
    eline = _line(rec.get("end"))
    if sline is None:
        return path
    if eline is not None and eline != sline:
        return f"{path}:{sline}-{eline}"
    return f"{path}:{sline}"


def _metadata(meta: dict) -> tuple[list[str], list[str]]:
    """Whitelist-extract (tags, references) from extra.metadata. Values are
    read only for the whitelisted keys and only when they are strings or
    lists of strings; anything else is ignored (not an error — metadata is
    rule-authored and free-form). Never raises on odd shapes.
    CR-03: every accepted value is sanitised (inert, evidence preserved)."""
    tags: list[str] = []
    for key in _METADATA_WHITELIST:
        if key not in meta:
            continue
        val = meta[key]
        if isinstance(val, str) and val.strip():
            clean = _sanitize(val.strip())
            if clean:
                tags.append(f"{key}={clean}")
        elif isinstance(val, list):
            parts = [_sanitize(x.strip()) for x in val
                     if isinstance(x, str) and x.strip()]
            parts = [p for p in parts if p]
            if parts:
                tags.append(f"{key}={'|'.join(parts)}")
    refs: list[str] = []
    raw_refs = meta.get("references")
    if isinstance(raw_refs, list):
        refs = [c for c in (_sanitize(r.strip()) for r in raw_refs
                            if isinstance(r, str) and r.strip()) if c]
    elif isinstance(raw_refs, str) and raw_refs.strip():
        clean = _sanitize(raw_refs.strip())
        if clean:
            refs = [clean]
    return tags, refs


def _raw_severity(rec: dict) -> str:
    """Return the raw semgrep severity token (lower-cased) for audit labelling
    only. Used to preserve the ORIGINAL category of legacy values
    (EXPERIMENT/INVENTORY) in the finding name (D2). Never logged, never
    stored in meta; a fixed-vocabulary token, not free tool text."""
    if not isinstance(rec, dict):
        return ""
    extra = rec.get("extra")
    if not isinstance(extra, dict):
        return ""
    val = extra.get("severity")
    if not isinstance(val, str):
        return ""
    return val.strip().lower()


def _to_finding(rec: dict, target: str) -> Finding:
    """Whitelist-extract one semgrep result into a unified Finding.
    Error messages never echo record values (fail-closed, leak-free).
    `extra.lines` (matched source code) is deliberately never read."""
    if not isinstance(rec, dict):
        raise FindingError("semgrep record is not a JSON object")
    check_id = _str_field(rec, "check_id")
    if not check_id:
        raise FindingError("semgrep record: check_id missing or not a string")
    path = _str_field(rec, "path")
    if not path:
        raise FindingError("semgrep record: path missing or not a string")
    location = _location(rec, path)
    extra = rec.get("extra")
    if not isinstance(extra, dict):
        raise FindingError("semgrep record: extra must be an object")
    sev_raw = _str_field(extra, "severity").lower()
    sev = _SEVERITY_MAP.get(sev_raw)
    if sev is None:
        raise FindingError("semgrep record: unsupported or missing severity")
    message = _str_field(extra, "message")
    meta = extra.get("metadata")
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise FindingError("semgrep record: extra.metadata must be an object")
    tags, refs = _metadata(meta)
    description = f"semgrep rule {check_id} matched at {location}"
    if message:
        description += f" — {message}"
    return Finding(
        tool="semgrep",
        finding_type="semgrep_finding",
        title=f"semgrep: {check_id}",
        # Documented nine-value mapping (SEMGREP_SEVERITY_MAP): semgrep
        # reports a severity; this is the system's translation of it, never
        # an invented value.
        severity=sev,
        target=target,
        location=location,
        rule_id=check_id,
        description=description,
        evidence=f"rule metadata: {', '.join(tags)}" if tags else None,
        references=tuple(refs),
    )


def register_semgrep() -> None:
    """Explicit, IDEMPOTENT registration of the semgrep adapter (EXT-2).

    This function is the ONLY supported registration path. It is called by
    the CLI start-up path (vuln_hunter.__main__.main); no module import has
    registration side effects. If a SemgrepAdapter instance is already
    registered this is a no-op — repeated calls create no duplicate entry
    and never replace the existing instance (including ones prepared by a
    test that needs an explicit registration environment).

    Registration alone grants NO execution rights: the inherited (final)
    ToolAdapter.execute() still requires a RunTicket issued by a live
    PolicyEngine, plus Scope/window/risk-ceiling checks.
    """
    from .. import adapters as _adapters
    # Access the live module attribute (not a copied import) so a registry
    # rebound by a test is still respected. Read-only: adapters.py is frozen.
    existing = _adapters._REGISTRY.get(SemgrepAdapter.id)
    if isinstance(existing, SemgrepAdapter):
        return
    _adapters.register_adapter(SemgrepAdapter)


__all__ = ["SemgrepAdapter", "register_semgrep", "SEMGREP_FALLBACKS",
           "SEMGREP_SEVERITY_MAP", "semgrep_binary",
           "_METADATA_WHITELIST", "_SEVERITY_MAP"]
