"""External tool adapters (EXT-1+); Gen-1 CLI/Planner wiring: EXT-1.1/1.2.

Gen-1 integration: the Gitleaks adapter is wired into the Gen-1 CLI
(``python -m vuln_hunter`` / ``dvs``) and into ``planner.build_plan``,
which emits the local ``s4-gitleaks`` step only when a source tree is
supplied and the gitleaks binary resolves. The Semgrep adapter (EXT-2) is
wired the same way: ``planner.build_plan`` emits ``s5-semgrep`` only when a
source tree is supplied, the binary resolves, AND a LOCAL rules source is
configured (registry/auto config is never used — no network).

Registration is controlled EXPLICITLY by the CLI start-up path:
``vuln_hunter.__main__.main()`` calls :func:`register_gitleaks` and
:func:`register_semgrep`. Importing this package, its adapter modules, or
the planner has NO registration side effects. Both functions are
idempotent: they never create a duplicate entry and never replace an
already-registered adapter instance. Tests that need an adapter registered
call the function explicitly.

Registration itself grants NO execution permissions. An actual scan still
passes the unchanged authorization chain: Scope validation, a fresh
RunTicket issued by a live PolicyEngine, the authorization window, the
mode's risk ceiling (R1 for gitleaks and semgrep),
``target_kind="fs_path"`` handling, and the inherited final
``ToolAdapter.execute()`` gate. DualVerify-Sentinel is an
authorization-gated local security check engine; it does not act as
an autonomous penetration-testing agent.
"""
from .gitleaks import GitleaksAdapter, register_gitleaks
from .semgrep import SemgrepAdapter, register_semgrep

__all__ = ["GitleaksAdapter", "register_gitleaks",
           "SemgrepAdapter", "register_semgrep"]
