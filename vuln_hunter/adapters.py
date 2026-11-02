"""Tool adapters. Every adapter states its risk level; the Executor refuses to
run any adapter whose risk exceeds the mode ceiling.

Statuses returned are honest: COMPLETED only when the tool actually ran to a
conclusion. TIMEOUT_* subclasses record WHERE the budget ran out
(TIMEOUT_INITIALIZING = killed before any scan traffic was observed,
TIMEOUT_SCANNING = killed while requests were in flight,
TIMEOUT_UNCLASSIFIED = killed with insufficient output to classify).
None of these are ever mapped to success.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .policy import RunTicket

NUCLEI_FALLBACKS = [
    Path.home() / "Tools" / "nuclei" / "nuclei.exe",
    Path.home() / "Tools" / "nuclei" / "nuclei",
]

USER_AGENT = "dualverify-sentinel/0.1 (authorized-scan; contact recorded in scope file)"


class GateRequired(RuntimeError):
    """Raised when execution is attempted without an authorization policy or
    a RunTicket. Fail-closed: callers must NOT fall back to any unguarded path."""


def tool_env() -> dict:
    """Proxy-sanitized environment for tool subprocesses.

    All engine targets must be in-scope and typically local/authorized; an
    ambient proxy (HTTP_PROXY etc.) can answer on their behalf (e.g. 502 for
    closed ports — verified in engine-run3) and pollute results. We strip
    proxy variables and force direct connections. If a future scope needs a
    proxy, that must be an explicit, audited scope field — not ambient env.
    """
    env = dict(os.environ)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy"):
        env.pop(k, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def _decode(data) -> str:
    """Decode subprocess output bytes. utf-8 strict first, gbk fallback.

    Input contract (D2-D-1-F1): `bytes | bytearray | None`. The only
    production caller feeds `subprocess.run(capture_output=True)` output
    (never text=True), so values are bytes; None/str are defensive-only.
    Returns "" for None or empty input. Raises UnicodeDecodeError on bytes
    invalid in BOTH utf-8 and gbk (caller records tree_kill_decode_error).
    Raises TypeError for non-bytes input (defensive; unreachable in
    production) — callers must catch it; this helper never widens the
    production contract.
    """
    if data is None:
        return ""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"expected bytes, got {type(data).__name__}")
    data = bytes(data)
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("gbk")  # may also raise -> caller handles


@dataclass
class AdapterResult:
    status: str  # COMPLETED | FAILED | TIMEOUT_* (see module docstring)
    ok: bool
    detail: str = ""
    findings: list = field(default_factory=list)
    no_retry: bool = False
    quarantine: bool = False
    meta: dict = field(default_factory=dict)


def classify_timeout(phases: list[dict]) -> str:
    """Classify a timeout from the phase timeline. Never invents a phase.

    TIMEOUT_INITIALIZING : killed before templates finished compiling
    TIMEOUT_SCANNING     : killed while scan traffic was in flight
    TIMEOUT_UNCLASSIFIED : insufficient output to tell
    """
    seen = {p.get("phase") for p in phases}
    if "templates_loaded" in seen and (seen & {"scan_progress", "scan_completed", "result_json"}):
        return "TIMEOUT_SCANNING"
    if "templates_loaded" not in seen:
        return "TIMEOUT_INITIALIZING"
    return "TIMEOUT_UNCLASSIFIED"


_PHASE_RE = {
    "templates_loaded": re.compile(r"Templates loaded for current scan:\s*(\d+)"),
    "targets_loaded": re.compile(r"Targets loaded for current scan:\s*(\d+)"),
    "scan_progress": re.compile(r"^\[\d+:\d+:\d+\].*?Requests:\s*(\d+)"),
    "scan_completed": re.compile(r"Scan completed in\s*([\d.]+)ms"),
}


def phase_from_line(line: str) -> tuple[str, str] | None:
    """Map one nuclei output line to (phase, detail). Returns None for noise."""
    s = line.strip()
    if s.startswith("{"):
        return ("result_json", "")
    m = _PHASE_RE["scan_completed"].search(s)
    if m:
        return ("scan_completed", f"{m.group(1)}ms")
    m = _PHASE_RE["templates_loaded"].search(s)
    if m:
        return ("templates_loaded", f"n={m.group(1)}")
    m = _PHASE_RE["targets_loaded"].search(s)
    if m:
        return ("targets_loaded", f"n={m.group(1)}")
    m = _PHASE_RE["scan_progress"].search(s)
    if m:
        return ("scan_progress", f"requests={m.group(1)}")
    if "No results found" in s:
        return ("no_results", "")
    return None


class ToolAdapter:
    id = "base"
    risk = "R0"
    description = ""

    def preflight(self) -> str | None:
        """Return an error string if dependencies are missing, else None."""
        return None

    # ---- unified fail-closed execution gate (FINAL: do not override) -------
    def execute(self, ticket, *, policy, timeout: int, log, step: dict | None = None) -> AdapterResult:
        """The ONLY public execution entry. Accepts a RunTicket issued by
        PolicyEngine.issue_ticket and re-verifies it against the LIVE policy:
        adapter identity, target scope, authorization window and scope content
        hash. Any mismatch -> REFUSED/ABORTED without running the tool.

        Subclasses implement _run(); they never see a request that has not
        passed this gate. Bare-target calls raise GateRequired (TypeError for
        missing ticket argument).
        """
        if policy is None:
            raise GateRequired(
                f"adapter {self.id!r} requires a live PolicyEngine instance; "
                "execution without an authorization policy is not supported"
            )
        if not isinstance(ticket, RunTicket):
            raise GateRequired(
                "bare targets are not accepted: issue a RunTicket via "
                "PolicyEngine.issue_ticket(target, adapter_id) first"
            )
        if ticket.adapter_id != self.id:
            return AdapterResult(
                "REFUSED", False,
                f"ticket is for adapter {ticket.adapter_id!r}, not {self.id!r}",
            )
        if policy.scope_sha256() != ticket.scope_sha256:
            return AdapterResult(
                "REFUSED", False,
                "scope content changed after ticket issuance; re-issue ticket",
            )
        # Ticket/policy mode consistency: a ticket issued under one mode can
        # never be spent under another. The live policy's checks below remain
        # authoritative — this is an additional gate, not a replacement.
        if ticket.mode != policy.mode:
            return AdapterResult(
                "REFUSED", False,
                f"ticket mode {ticket.mode!r} does not match policy mode "
                f"{policy.mode!r}",
            )
        # Target-kind consistency FIRST: a ticket may only be used for the
        # kind of target it was issued for (net vs fs_path). Unknown kinds
        # fail closed. step absent -> treated as "net" (stricter).
        step_kind = (step or {}).get("target_kind", "net")
        if ticket.target_kind != step_kind or ticket.target_kind not in ("net", "fs_path"):
            return AdapterResult(
                "REFUSED", False,
                f"ticket target_kind {ticket.target_kind!r} does not match "
                f"step target_kind {step_kind!r}",
            )
        # step/target consistency: the step handed to _run must be about the
        # same target the ticket was issued for (defense in depth; _run only
        # ever receives ticket.target, never step["target"]).
        if step is not None and "target" in step and str(step["target"]) != ticket.target:
            return AdapterResult(
                "REFUSED", False,
                f"step target {step['target']!r} does not match ticket target "
                f"{ticket.target!r}",
            )
        # Mode risk ceiling (defense in depth: also enforced at run_step).
        aerr = policy.adapter_allowed(self.risk)
        if aerr:
            return AdapterResult("REFUSED", False, aerr)
        # Net targets are re-checked against the LIVE scope. fs_path targets
        # skip ONLY the net-scope check (same documented exemption as
        # issue_ticket); window/mode checks below still apply.
        if ticket.target_kind != "fs_path":
            terr = policy.target_allowed(ticket.target)
            if terr:
                return AdapterResult("REFUSED", False, terr)
        werr = policy.window_ok()
        if werr:
            return AdapterResult("ABORTED", False, f"authorization window: {werr}")
        return self._run(ticket.target, timeout, log, step)

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        raise NotImplementedError


class HTTPProbeAdapter(ToolAdapter):
    id = "http_probe"
    risk = "R1"
    description = "Single GET request via urllib; records status/server/title."

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        url = target if "://" in target else "http://" + target
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        # Bypass ambient proxies (http_proxy etc.): a probe must connect to the
        # target itself, otherwise a proxy's 502 can be misread as a service.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        log.write(f"GET {url} (timeout={timeout}s, proxy=direct)\n")
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
                status, server = resp.status, resp.headers.get("Server", "")
        except urllib.error.HTTPError as exc:
            # 4xx/5xx responses still prove the service answered.
            if exc.code == 429:
                log.write("HTTP 429 rate limited\n")
                return AdapterResult(
                    "FAILED",
                    False,
                    f"HTTP 429 (rate limited) at {url}",
                    no_retry=True,
                    quarantine=True,
                )
            status, server, body = exc.code, exc.headers.get("Server", ""), ""
        except Exception as exc:  # noqa: BLE001 - honest failure reporting
            log.write(f"probe error: {exc.__class__.__name__}: {exc}\n")
            return AdapterResult(
                "FAILED", False, f"probe failed: {exc.__class__.__name__}: {exc}"
            )
        log.write(f"HTTP {status} server={server!r} body_bytes={len(body)}\n")
        finding = {
            "type": "http_service",
            "url": url,
            "status": status,
            "server": server,
        }
        title = ""
        low = body.lower()
        if "<title>" in low:
            s = low.index("<title>") + 7
            e = low.find("</title>", s)
            if e > s:
                title = body[s:e].strip()[:200]
        if title:
            finding["title"] = title
        return AdapterResult("COMPLETED", True, f"HTTP {status}", [finding],
                             meta={"env_policy": "direct"})


class NucleiAdapter(ToolAdapter):
    id = "nuclei"
    risk = "R2"
    description = "nuclei template scan (medium/high/critical), rate-limited."

    def binary(self):
        exe = shutil.which("nuclei")
        if exe:
            return exe
        for p in NUCLEI_FALLBACKS:
            if p.exists():
                return str(p)
        return None

    def preflight(self) -> str | None:
        if self.binary() is None:
            return "nuclei binary not found (PATH or ~/Tools/nuclei/)"
        return None

    def build_command(self, target: str, step: dict | None = None) -> list[str]:
        url = target if "://" in target else "http://" + target
        cmd = [
            self.binary(),
            "-u",
            url,
            "-jsonl",
            "-nc",
            "-duc",
            "-disable-update-check",
            # D2-C0 (R1): explicitly disable redirect following at the engine
            # layer — previously we relied on Nuclei's default no-follow plus
            # the template's own max-redirects field. Belt and braces.
            "-dr",
            # D2-C0 (R2): explicitly disable interactsh/OAST so a scan can
            # never attempt external callback registration, regardless of
            # what templates are loaded.
            "-ni",
            "-rl",
            "20",
            "-c",
            "10",
            "-severity",
            "medium,high,critical",
            "-stats",
            "-si",
            "30",  # stats lines let us classify timeouts honestly
        ]
        step = step or {}
        ids = [i for i in (step.get("nuclei_ids") or []) if str(i).strip()]
        tags = [t for t in (step.get("nuclei_tags") or []) if str(t).strip()]
        if ids:
            cmd += ["-id", ",".join(str(i) for i in ids)]
        if tags:
            cmd += ["-tags", ",".join(str(t) for t in tags)]
        return cmd

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        cmd = self.build_command(target, step)
        log.write("$ " + " ".join(cmd) + "\n")
        log.write(f"[budget] timeout={timeout}s env=proxy-sanitized(direct)\n")
        meta: dict = {"env_policy": "direct", "phases": [], "templates_loaded": None}
        t0 = time.monotonic()

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", env=tool_env(),
            )
        except FileNotFoundError as exc:
            return AdapterResult("FAILED", False, f"nuclei spawn failed: {exc}")

        out_buf: list[str] = []
        err_buf: list[str] = []

        def _reader(stream, sink, track_phases: bool):
            for line in stream:
                sink.append(line)
                if track_phases:
                    ph = phase_from_line(line)
                    if ph:
                        meta["phases"].append(
                            {"offset_ms": int((time.monotonic() - t0) * 1000),
                             "phase": ph[0], "detail": ph[1]}
                        )

        t_out = threading.Thread(target=_reader, args=(proc.stdout, out_buf, True), daemon=True)
        # nuclei emits [INF]/stats progress lines on STDERR — phases must be
        # tracked there too (verified: evidence/mvp4-e1 first run had empty
        # phases when only stdout was parsed).
        t_err = threading.Thread(target=_reader, args=(proc.stderr, err_buf, True), daemon=True)
        t_out.start()
        t_err.start()

        timed_out = False
        deadline = t0 + max(1, timeout)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if proc.poll() is not None and not t_out.is_alive():
                break
            time.sleep(0.2)

        if timed_out:
            # D2-D-1-F1: fielded Windows process-tree cleanup. taskkill /T /F
            # runs FIRST while the parent is alive so the whole tree is
            # enumerated; proc.kill() is the root fallback; wait is bounded
            # and every outcome is recorded. Each stage is independently
            # exception-closed — a stage failure never blocks the next one,
            # and the cleanup itself never escapes this block.
            cleanup: dict = {
                "tree_kill_rc": None, "tree_kill_status": None,
                "tree_kill_detail": "", "tree_kill_decode_error": None,
                "root_kill": None, "wait_status": None,
                "wait_exhausted": False, "residual_check": "NOT_CHECKED",
                "log_write_error": None,
            }
            if os.name == "nt":
                try:
                    r = subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        capture_output=True, timeout=10,
                    )  # stdout/stderr are bytes (no text=True)
                    cleanup["tree_kill_rc"] = r.returncode
                    cleanup["tree_kill_status"] = (
                        "SUCCESS" if r.returncode == 0 else "FAILED")
                except subprocess.TimeoutExpired:
                    cleanup["tree_kill_rc"] = "TIMEOUT"
                    cleanup["tree_kill_status"] = "TIMEOUT"
                except Exception as exc:  # noqa: BLE001 - fielded, not masked
                    cleanup["tree_kill_rc"] = f"ERROR:{exc.__class__.__name__}"
                    cleanup["tree_kill_status"] = "ERROR"
                else:
                    try:
                        cleanup["tree_kill_detail"] = _decode(
                            r.stdout or r.stderr)[:200]
                    except Exception as exc:  # noqa: BLE001
                        cleanup["tree_kill_detail"] = ""
                        cleanup["tree_kill_decode_error"] = (
                            f"{exc.__class__.__name__}: {exc}"[:120])
            else:
                cleanup["tree_kill_status"] = "SKIPPED_NON_WIN"
            try:
                proc.kill()
                cleanup["root_kill"] = "OK"  # kill() did not raise; exit is
                # confirmed separately by wait_status below, not here.
            except ProcessLookupError:
                cleanup["root_kill"] = "ALREADY_EXITED"
            except OSError as exc:
                cleanup["root_kill"] = f"ERROR:OSError:{exc}"[:120]
            except Exception as exc:  # noqa: BLE001
                cleanup["root_kill"] = (
                    f"ERROR:Unexpected:{exc.__class__.__name__}")
            try:
                proc.wait(timeout=10)
                cleanup["wait_status"] = "WAITED"
            except subprocess.TimeoutExpired:
                cleanup["wait_status"] = "TIMEOUT"
                cleanup["wait_exhausted"] = True  # ONLY this path sets it
            except Exception as exc:  # noqa: BLE001
                cleanup["wait_status"] = f"ERROR:{exc.__class__.__name__}"
            meta["cleanup"] = cleanup
            # log_write_error is an in-memory audit field updated only after
            # write/flush fail; it is NOT guaranteed to appear in the same
            # attempt log line that hit the fault, and it reaches the Journal
            # only if the Runner exits its `with open(...)` (close) cleanly
            # and journal.append("attempt_end") then succeeds.
            try:
                log.write(f"[tree-cleanup] "
                          f"{json.dumps(cleanup, ensure_ascii=False)}\n")
                log.flush()
            except Exception as exc:  # noqa: BLE001
                cleanup["log_write_error"] = (
                    f"{exc.__class__.__name__}: {exc}"[:120])
        else:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        stdout = "".join(out_buf)
        stderr = "".join(err_buf)
        log.write(stdout[-30000:])
        if stderr:
            log.write("\n[stderr]\n" + stderr[-5000:] + "\n")

        if timed_out:
            tclass = classify_timeout(meta["phases"])
            meta["timeout_class"] = tclass
            cl = meta.get("cleanup") or {}
            detail = (f"nuclei exceeded {timeout}s -> {tclass} "
                      f"(phases seen: {[p['phase'] for p in meta['phases']] or ['none']})"
                      f"; tree-cleanup: taskkill={cl.get('tree_kill_status')} "
                      f"root={cl.get('root_kill')} wait={cl.get('wait_status')} "
                      f"residual={cl.get('residual_check')}")
            log.write(f"\n[timeout] {detail}\n")
            return AdapterResult(tclass, False, detail, meta=meta)

        # normal completion: parse findings from JSONL
        for p in meta["phases"]:
            if p["phase"] == "templates_loaded":
                meta["templates_loaded"] = int(p["detail"].removeprefix("n="))
        meta["output_valid"] = proc.returncode == 0
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info") or {}
            findings.append(
                {
                    "type": "nuclei_finding",
                    "template": rec.get("template-id") or rec.get("templateID"),
                    "severity": info.get("severity"),
                    "name": info.get("name"),
                    "host": rec.get("host"),
                    "matched_at": rec.get("matched-at"),
                }
            )
        if proc.returncode != 0:
            # A non-zero exit means incomplete results even if some findings
            # were emitted — never reported as success.
            detail = f"nuclei exit {proc.returncode} (incomplete; findings_seen={len(findings)}): {stderr.strip()[:200]}"
            return AdapterResult("FAILED", False, detail, findings, meta=meta)
        return AdapterResult(
            "COMPLETED",
            True,
            f"nuclei exit 0, {len(findings)} finding(s), "
            f"templates_loaded={meta['templates_loaded']}",
            findings,
            meta=meta,
        )


class BanditAdapter(ToolAdapter):
    id = "bandit"
    risk = "R1"
    description = "bandit static analysis (target = source directory)."

    def _run(self, target: str, timeout: int, log, step: dict | None = None) -> AdapterResult:
        src = Path(target)
        if not src.is_dir():
            return AdapterResult("FAILED", False, f"source dir not found: {src}")
        cmd = [sys.executable, "-m", "bandit", "-r", str(src), "-f", "json", "-q"]
        log.write("$ " + " ".join(cmd) + "\n")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=tool_env()
            )
        except subprocess.TimeoutExpired:
            return AdapterResult("TIMEOUT", False, f"bandit exceeded {timeout}s")
        log.write(proc.stdout[-30000:])
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return AdapterResult("FAILED", False, "bandit output not valid JSON")
        results = data.get("results") or []
        findings = [
            {
                "type": "bandit_finding",
                "test_id": r.get("test_id"),
                "severity": r.get("issue_severity"),
                "filename": r.get("filename"),
                "line": r.get("line_number"),
                "issue": (r.get("issue_text") or "")[:200],
            }
            for r in results
        ]
        return AdapterResult(
            "COMPLETED",
            True,
            f"bandit exit {proc.returncode}, {len(findings)} finding(s)",
            findings,
        )


# Private registry. Access goes through get_adapter(), which REQUIRES a live
# policy instance — registration/lookup alone never grants execution rights.
_REGISTRY: dict[str, ToolAdapter] = {
    a.id: a() for a in (HTTPProbeAdapter, NucleiAdapter, BanditAdapter)
}

# Public read-only risk table (data only, no instances, no execution path).
ADAPTER_RISK: dict[str, str] = {a.id: a.risk for a in (HTTPProbeAdapter, NucleiAdapter, BanditAdapter)}


def adapter_risk(name: str) -> str:
    """Risk level for planning lookups (decision engine / loop): public data
    table first, then the live registry (covers test/plugin-registered
    adapters), else "R4" (most conservative) for unknown adapters.

    Planning-only: execution-time ceiling checks happen at the run/execute
    gate, not here."""
    if name in ADAPTER_RISK:
        return ADAPTER_RISK[name]
    inst = _REGISTRY.get(name)
    return inst.risk if inst is not None else "R4"


def register_adapter(cls) -> None:
    """Documented extension point for tests/plugins. Registration does NOT
    grant execution rights: execute() still requires a RunTicket + policy."""
    _REGISTRY[cls.id] = cls()


def get_adapter(name: str, policy):
    """Return the adapter instance for `name`. policy is REQUIRED — calling
    without one raises GateRequired instead of degrading to an unguarded path."""
    if policy is None:
        raise GateRequired(
            f"get_adapter({name!r}) requires a live PolicyEngine instance"
        )
    adapter = _REGISTRY.get(name)
    if adapter is None:
        raise KeyError(f"unknown adapter: {name!r} (known: {sorted(_REGISTRY)})")
    return adapter
