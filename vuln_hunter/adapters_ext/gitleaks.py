"""Gitleaks adapter (EXT-1) — local secret scanning, metadata-only findings.

SECURITY CONTRACT (highest priority; gitleaks reports contain REAL secrets):
- The gitleaks JSON report is treated as hostile. Only a FIXED WHITELIST of
  metadata fields is ever read: RuleID, File, StartLine, EndLine,
  Description, Tags, Link. The secret-bearing fields (Secret, Match, and
  everything else) are NEVER read, logged, or stored.
- Raw tool output never reaches logs, findings, detail strings, exception
  messages, or adapter meta — only the command line (paths/flags only),
  exit code, record counts, and per-finding rule/file/line metadata.
- The unified Finding (vuln_hunter.findings.Finding) is built from
  whitelisted metadata; `evidence` carries rule TAGS (rule metadata), never
  scanned-file content. Regex redaction in findings.py is a secondary net,
  NOT the security boundary — the boundary is whitelist extraction.
- Local directory scans only. The target must be an existing directory and
  must NOT be a filesystem/drive root or the user home directory
  (adapter-level guard; the PolicyEngine remains the authorization
  authority). No network access: subprocesses use the same
  proxy-sanitized environment as built-in adapters.
- Failure paths (bad exit code, invalid JSON, timeout, malformed record)
  return safe status strings with no raw output.

TOOL REQUIREMENTS: gitleaks >= 8.18 (`dir` subcommand). The binary is NOT
auto-installed; preflight() reports when it is missing.

REPORT LOCATION (verified on gitleaks 8.30.1, EXT-1.3 / EXT-1.3-F1):
  `--report-format json` alone does NOT write the report to stdout — gitleaks
  defaults the report to a file. `--report-path -` is REQUIRED to put the JSON
  array on stdout for the whitelist parser. `--redact` is enabled as DEFENCE
  IN DEPTH (also verified on 8.30.1): it replaces raw Secret/Match values in
  the captured stdout. It is NOT the security boundary — whitelist extraction
  in _to_finding() remains the boundary, and no raw stdout/stderr is ever
  logged, stored or echoed.

EXIT-CODE SEMANTICS (version-robust, no optional flags required):
  0 = scan completed, no leaks; 1 = scan completed, leaks found;
  anything else = failure. Findings come from the JSON report, so a
  non-zero-but-successful exit is never misread as an error. A blank stdout
  is NEVER treated as a clean result — it fails closed (EXT-1.3-F1).

FUTURE WIRING NOTE (updated EXT-1.1): the planner step "s4-gitleaks" now runs
this adapter and passes target_kind="fs_path" (same as bandit); the inherited
execute() gate (RunTicket + live policy + mode ceiling) applies unchanged.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..adapters import AdapterResult, ToolAdapter, tool_env
from ..findings import Finding, FindingError

GITLEAKS_FALLBACKS = [
    Path.home() / "Tools" / "gitleaks" / "gitleaks.exe",
    Path.home() / "Tools" / "gitleaks" / "gitleaks",
]

# Fields read from a gitleaks report record. Deliberately EXCLUDES Secret,
# Match and every other field — whitelist, never blacklist.
_WHITELIST_FIELDS = ("RuleID", "File", "StartLine", "EndLine",
                     "Description", "Tags", "Link")

# EXT-1.1 (T5) severity decision, made explicit: the gitleaks JSON report
# carries NO severity field. This constant is the SYSTEM's fixed policy
# default for gitleaks findings — it is NOT a value reported by the tool and
# must never be presented as one (reports/labels call it a system default).
GITLEAKS_DEFAULT_SEVERITY = "high"


def gitleaks_binary() -> str | None:
    """Resolve the gitleaks executable without instantiating the adapter.

    Single source of truth for "is the tool available?" — used by the planner
    to decide whether to emit the s4-gitleaks step, and by the adapter's
    binary()/preflight(). Resolution only; NEVER spawns anything.
    """
    exe = shutil.which("gitleaks")
    if exe:
        return exe
    for p in GITLEAKS_FALLBACKS:
        if p.exists():
            return str(p)
    return None


class GitleaksAdapter(ToolAdapter):
    id = "gitleaks"
    risk = "R1"
    description = "gitleaks local secret scan (metadata-only findings)."

    def binary(self) -> str | None:
        return gitleaks_binary()

    def preflight(self) -> str | None:
        if self.binary() is None:
            where = (GITLEAKS_FALLBACKS[0].parent if GITLEAKS_FALLBACKS
                     else Path.home() / "Tools" / "gitleaks")
            return (f"gitleaks binary not found on PATH or in {where} "
                    "(requires gitleaks >= 8.18)")
        return None

    def build_command(self, target: str, step: dict | None = None) -> list[str]:
        # EXT-1.3-F1: on gitleaks 8.30.1 the JSON report is NOT written to
        # stdout without --report-path - (both rc=0 and rc=1 produced an empty
        # stdout in EXT-1.3). Verified real CLI flags, minimal set:
        #   dir              local directory/file scan (long-stable)
        #   --report-format  json (long-stable)
        #   --report-path -  force the report onto stdout
        #   --redact         defence in depth: raw Secret/Match values never
        #                    appear in captured stdout. NOT the security
        #                    boundary — _to_finding() whitelist remains it.
        # --no-banner / --exit-code are still deliberately unused.
        return [self.binary() or "gitleaks", "dir", target,
                "--report-format", "json", "--report-path", "-", "--redact"]

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        refuse = _refuse_reason(target)
        if refuse:
            return AdapterResult("FAILED", False, refuse)

        exe = self.binary()
        if exe is None:
            return AdapterResult("FAILED", False, self.preflight())

        cmd = self.build_command(target, step)
        log.write("$ " + " ".join(cmd) + "\n")
        log.write(f"[budget] timeout={timeout}s env=proxy-sanitized(direct)\n")

        try:
            proc = _spawn(cmd, timeout)
        except subprocess.TimeoutExpired:
            log.write("gitleaks timeout (no partial output retained)\n")
            return AdapterResult("TIMEOUT", False, f"gitleaks exceeded {timeout}s")
        except Exception as exc:  # noqa: BLE001 - honest failure reporting
            return AdapterResult(
                "FAILED", False,
                f"gitleaks spawn failed: {exc.__class__.__name__}")

        rc = proc.returncode
        # EXT-1.3-F1 stdout/stderr lifecycle: `stdout` is the ONLY place raw
        # tool output ever exists. It stays a local str, is parsed immediately
        # below, and is NEVER written to the log, detail, meta, journal,
        # exception text or report. `_spawn` captures stderr, but this adapter
        # deliberately never reads proc.stderr. Every failure path below uses
        # fixed strings + exit code + counts only.
        stdout = proc.stdout or ""
        if rc not in (0, 1):
            log.write(f"gitleaks exit {rc} (scan did not complete)\n")
            return AdapterResult("FAILED", False, f"gitleaks exit {rc} (scan did not complete)")

        if not stdout.strip():
            # A successful no-leak scan emits the JSON array "[]" thanks to
            # --report-path -. A BLANK stdout therefore means the tool did not
            # produce a usable report; it must NEVER be reported as a clean
            # result (nor harvested for findings). Fail closed for both 0 and 1.
            log.write(f"gitleaks exit {rc}, empty report -> fail-closed\n")
            return AdapterResult(
                "FAILED", False,
                f"gitleaks exit {rc}, empty report (fail-closed: no clean result assumed)")

        try:
            records = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            log.write("gitleaks output not valid JSON (raw output discarded)\n")
            return AdapterResult("FAILED", False, "gitleaks output not valid JSON")
        if not isinstance(records, list):
            return AdapterResult("FAILED", False, "gitleaks report is not a JSON array")

        findings = []
        skipped = 0
        for i, rec in enumerate(records):
            try:
                f = _to_finding(rec, target)
            except FindingError as exc:
                # Message is value-free by construction (field names only).
                skipped += 1
                log.write(f"record {i} skipped: {exc}\n")
                continue
            d = f.to_dict()
            # EXT-1.1/1.2 renderer-compatibility alias. The frozen report.py
            # finding line reads legacy keys (name/template/issue/type);
            # unified-schema findings carry title/finding_type, so without
            # this alias every unified finding renders as "**high** None".
            #
            # EXT-1.2 (T3): the SAME alias also carries an explicit marker
            # that `high` is a DualVerify-Sentinel SYSTEM DEFAULT policy
            # value, NOT a severity reported by gitleaks (its JSON report
            # has no severity field). report.py renders `name` verbatim, so
            # a reader can always tell tool-native metadata from a system
            # policy value. ADDITIVE OUTPUT ONLY: the 13 Finding schema
            # fields (including severity="high") are untouched, and no
            # extra key is introduced beyond this existing alias.
            # Follow-up: teach report.py the unified schema and drop the shim.
            d["name"] = (
                f"{f.title} "
                f"[severity={GITLEAKS_DEFAULT_SEVERITY} 为系统默认策略，"
                f"非 Gitleaks 原生判定；Gitleaks 报告不含 severity 字段]"
            )
            findings.append(d)
            log.write(f"  {f.rule_id} {f.location}\n")

        log.write(f"gitleaks exit {rc}, {len(findings)} finding(s) "
                  f"from {len(records)} record(s), {skipped} skipped\n")
        return AdapterResult(
            "COMPLETED", True,
            f"gitleaks exit {rc}, {len(findings)} finding(s)",
            findings,
            meta={"env_policy": "direct", "records_seen": len(records),
                  "records_skipped": skipped})


def _spawn(cmd, timeout: int):
    """Single subprocess seam — tests replace this with a fake. Same
    proxy-sanitized environment as built-in adapters."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=tool_env())


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
    val = rec.get(name)
    if val is None:
        return ""
    if not isinstance(val, str):
        raise FindingError(f"gitleaks record: {name} must be a string")
    return val.strip()


def _int_field(rec: dict, name: str):
    val = rec.get(name)
    if val is None:
        return None
    if not isinstance(val, int) or isinstance(val, bool):
        raise FindingError(f"gitleaks record: {name} must be an int")
    return val


def _to_finding(rec: dict, target: str) -> Finding:
    """Whitelist-extract one gitleaks report record into a unified Finding.
    Error messages never echo record values (fail-closed, leak-free)."""
    if not isinstance(rec, dict):
        raise FindingError("gitleaks record is not a JSON object")
    rule_id = _str_field(rec, "RuleID") or "unknown"
    file = _str_field(rec, "File")
    if not file:
        raise FindingError("gitleaks record: File missing or not a string")
    start = _int_field(rec, "StartLine")
    end = _int_field(rec, "EndLine")
    if start is None:
        location = file
    elif end is not None and end != start:
        location = f"{file}:{start}-{end}"
    else:
        location = f"{file}:{start}"
    desc = _str_field(rec, "Description")
    tags_val = rec.get("Tags")
    if tags_val is None:
        tags = []
    elif isinstance(tags_val, list):
        tags = [str(t).strip() for t in tags_val if isinstance(t, str) and t.strip()]
    else:
        raise FindingError("gitleaks record: Tags must be a list")
    link = _str_field(rec, "Link")
    description = f"gitleaks rule {rule_id} matched at {location}"
    if desc:
        description += f" ({desc})"
    return Finding(
        tool="gitleaks",
        finding_type="gitleaks_finding",
        title=f"gitleaks: {rule_id}",
        # Fixed documented system default (GITLEAKS_DEFAULT_SEVERITY):
        # gitleaks carries no severity field; this is policy, not tool fact.
        severity=GITLEAKS_DEFAULT_SEVERITY,
        target=target,
        location=location,
        rule_id=rule_id,
        description=description,
        evidence=f"rule tags: {', '.join(tags)}" if tags else None,
        references=(link,) if link else (),
    )


def register_gitleaks() -> None:
    """Explicit, IDEMPOTENT registration of the gitleaks adapter (EXT-1.2).

    This function is the ONLY supported registration path. It is called by
    the CLI start-up path (vuln_hunter.__main__.main); no module import has
    registration side effects. If a GitleaksAdapter instance is already
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
    existing = _adapters._REGISTRY.get(GitleaksAdapter.id)
    if isinstance(existing, GitleaksAdapter):
        return
    _adapters.register_adapter(GitleaksAdapter)


__all__ = ["GitleaksAdapter", "register_gitleaks", "GITLEAKS_FALLBACKS",
           "GITLEAKS_DEFAULT_SEVERITY", "gitleaks_binary",
           "_WHITELIST_FIELDS"]
