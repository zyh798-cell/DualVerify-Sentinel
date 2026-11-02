"""Policy engine: mode -> risk ceiling, target matching, acknowledgement.

Design notes:
- Host/port matching is done on parsed hostname equality, never string prefix,
  so "127.0.0.1" cannot be bypassed with "127.0.0.199" or "127.0.0.1.evil.com".
- A scope entry without a port matches ANY port on that host (documented
  semantics); an entry with a port matches exactly.
- R3+ modes require a fully populated risk_acknowledgement object, otherwise
  every adapter is refused.
- Execution authorization is capability-based: the ONLY way to run an adapter
  is with a RunTicket issued by PolicyEngine.issue_ticket after target/window
  checks. Adapters re-verify the ticket against a live policy at execution
  time (see adapters.ToolAdapter.execute). NOTE (honest boundary): frozen
  dataclasses and private constructors are API-hardening, NOT a sandbox;
  hostile same-process code can bypass anything (declared in SECURITY.md).
"""
import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import gate
from .journal import utcnow as _utcnow

MODES = {
    "passive": "R0",
    "safe_scan": "R1",
    "vuln_validation": "R2",
    "attack_simulation": "R3",
    "high_risk": "R4",
}

RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}

ACK_KEYS = ("impact_boundary", "rollback_plan", "emergency_contact", "authorized_for")

_TICKET_TOKEN = "dvs-run-ticket-v1"  # internal construction guard (API hardening)


class PolicyRefusal(Exception):
    """Raised when issuing a run ticket fails an authorization check."""


@dataclass(frozen=True)
class RunTicket:
    """Capability to run ONE adapter against ONE target. Issued only by
    PolicyEngine.issue_ticket after target/window/adapter-risk checks.

    Honest boundary: the private constructor token is API hardening against
    accidental misuse, not defense against hostile same-process code.
    """
    target: str
    adapter_id: str
    mode: str
    scope_sha256: str
    issued_at: str
    window_end: str | None
    target_kind: str = "net"
    _token: str = field(default="", repr=False, compare=False)

    def __post_init__(self):
        if self._token != _TICKET_TOKEN:
            raise ValueError(
                "RunTicket must be created via PolicyEngine.issue_ticket"
            )


def hostport(entry) -> tuple[str, int | None] | None:
    """Parse a target/scope entry into (hostname_lower, port|None)."""
    s = str(entry).strip()
    if not s:
        return None
    if "//" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
        host = p.hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return (host.lower(), p.port)
    except ValueError:
        return None


def entry_matches(entry, host: str, port: int | None) -> bool:
    hp = hostport(entry)
    if hp is None:
        return False
    ehost, eport = hp
    return ehost == host and (eport is None or eport == port)


class PolicyEngine:
    def __init__(self, scope: dict, mode: str):
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode!r} (known: {sorted(MODES)})")
        self.scope = scope
        self.mode = mode
        self.risk = MODES[mode]

    # ---- mode-level acknowledgement -------------------------------------
    def ack_error(self) -> str | None:
        if RISK_ORDER[self.risk] < 3:
            return None
        ack = self.scope.get("risk_acknowledgement")
        if not isinstance(ack, dict):
            return (
                f"mode '{self.mode}' ({self.risk}) requires a risk_acknowledgement "
                f"object with non-empty keys: {', '.join(ACK_KEYS)}"
            )
        missing = [
            k
            for k in ACK_KEYS
            if not (isinstance(ack.get(k), str) and ack.get(k).strip())
        ]
        if missing:
            return f"risk_acknowledgement missing or empty: {', '.join(missing)}"
        return None

    # ---- adapter-level ceiling -------------------------------------------
    def adapter_allowed(self, adapter_risk: str) -> str | None:
        if RISK_ORDER[adapter_risk] > RISK_ORDER[self.risk]:
            return (
                f"adapter risk {adapter_risk} exceeds mode ceiling "
                f"{self.risk} (mode '{self.mode}')"
            )
        return None

    # ---- target scope -----------------------------------------------------
    def target_allowed(self, target) -> str | None:
        hp = hostport(target)
        if hp is None:
            return f"unparseable target: {target!r}"
        host, port = hp
        for entry in self.scope.get("out_of_scope") or []:
            if entry_matches(entry, host, port):
                return f"target {host}:{port} matches out_of_scope entry {entry!r}"
        for entry in self.scope.get("in_scope") or []:
            if entry_matches(entry, host, port):
                return None
        return (
            f"target {host}:{port} is not covered by in_scope "
            f"(scope entries: {self.scope.get('in_scope')})"
        )

    # ---- authorization window (re-checked before EVERY step) --------------
    def window_ok(self) -> str | None:
        return gate.window_error(self.scope.get("window"))

    # ---- capability ticket -------------------------------------------------
    def scope_sha256(self) -> str:
        """Hash of the current scope content; tickets are bound to this. If the
        scope content changes after issuance, live tickets stop validating."""
        payload = json.dumps(self.scope, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def issue_ticket(self, target: str, adapter_id: str,
                     target_kind: str = "net") -> "RunTicket":
        """Issue a RunTicket after target-authorization and window checks.

        target_kind="fs_path" targets are local read-only paths and skip ONLY
        the net-scope check (same documented exemption as the executor);
        window and mode checks still apply.
        Raises PolicyRefusal on any check failure — never returns a ticket
        for an unauthorized target.
        """
        if not adapter_id or not str(adapter_id).strip():
            raise PolicyRefusal("issue_ticket: adapter_id is required")
        if target_kind != "fs_path":
            terr = self.target_allowed(target)
            if terr:
                raise PolicyRefusal(terr)
        werr = self.window_ok()
        if werr:
            raise PolicyRefusal(werr)
        aerr = self.ack_error()
        if aerr:
            raise PolicyRefusal(aerr)
        # window end for the ticket record (best-effort parse; window_ok
        # already passed, so the window string is well-formed)
        window_end = None
        window = self.scope.get("window")
        if isinstance(window, str) and "/" in window:
            window_end = window.split("/", 1)[1].strip()
        return RunTicket(
            target=str(target),
            adapter_id=str(adapter_id),
            mode=self.mode,
            scope_sha256=self.scope_sha256(),
            issued_at=_utcnow(),
            window_end=window_end,
            target_kind=target_kind,
            _token=_TICKET_TOKEN,
        )
