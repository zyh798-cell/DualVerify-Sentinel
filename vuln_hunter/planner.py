"""Plan builder. Kept minimal: what runs depends only on mode + inputs."""
from .adapters_ext.gitleaks import gitleaks_binary
from .adapters_ext.semgrep import semgrep_binary
from .policy import MODES


def build_plan(
    mode: str,
    target: str,
    source_dir: str | None = None,
    timeout_probe: int = 15,
    timeout_dynamic: int = 120,
    nuclei_timeout: int | None = None,
    nuclei_ids: list | None = None,
    nuclei_tags: list | None = None,
    semgrep_rules: str | None = None,
) -> list[dict]:
    """nuclei_timeout is an INDEPENDENT budget: measured fixed startup cost on
    this machine is ~3-3.5min (evidence/mvp4-p1-diag/), so it defaults to 240s
    for the nuclei step only; bandit/probe keep timeout_dynamic."""
    steps = [
        {
            "id": "s1-probe",
            "adapter": "http_probe",
            "target": target,
            "timeout": timeout_probe,
        }
    ]
    if MODES.get(mode) in ("R2", "R3", "R4"):
        steps.append(
            {
                "id": "s2-nuclei",
                "adapter": "nuclei",
                "target": target,
                "timeout": nuclei_timeout if nuclei_timeout else max(timeout_dynamic, 240),
                "deps": ["s1-probe"],
                "nuclei_ids": list(nuclei_ids or []),
                "nuclei_tags": list(nuclei_tags or []),
            }
        )
    if source_dir:
        steps.append(
            {
                "id": "s3-bandit",
                "adapter": "bandit",
                "target": str(source_dir),
                "timeout": timeout_dynamic,
                "target_kind": "fs_path",  # local read-only path: no net scope check
            }
        )
        # EXT-1.1: gitleaks secret scan. Emitted ONLY when the source tree is
        # given AND the gitleaks binary resolves. The binary condition is
        # deliberate: gitleaks is an OPTIONAL external tool, and an always-
        # present step without the binary would be SKIPPED by preflight and
        # drag an existing green run summary off COMPLETED. When the tool is
        # absent the step is simply not planned — the report still shows
        # exactly what ran. No deps: bandit and gitleaks are independent
        # local scanners (a bandit failure must not cascade-skip gitleaks).
        # Same fs_path authorization path as bandit (see runner/policy).
        if gitleaks_binary() is not None:
            steps.append(
                {
                    "id": "s4-gitleaks",
                    "adapter": "gitleaks",
                    "target": str(source_dir),
                    "timeout": timeout_dynamic,
                    "target_kind": "fs_path",  # local read-only path: no net scope check
                }
            )
        # EXT-2: semgrep multi-language static analysis. Emitted ONLY when the
        # source tree is given, the semgrep binary resolves AND a LOCAL rules
        # source is configured. The rules condition is deliberate and mirrors
        # the binary condition: semgrep without a local rules source would have
        # to fetch rules from the registry, which is a network action this
        # engine never takes implicitly. A missing rules source means the step
        # is simply not planned — the report still shows exactly what ran, and
        # an operator who asked for semgrep gets an explicit adapter-level
        # FAILED (not a silent skip) when the step is hand-written without one.
        # No deps: bandit/gitleaks/semgrep are independent local scanners
        # (a bandit failure must not cascade-skip semgrep).
        # Same fs_path authorization path as bandit (see runner/policy).
        if semgrep_binary() is not None and semgrep_rules:
            steps.append(
                {
                    "id": "s5-semgrep",
                    "adapter": "semgrep",
                    "target": str(source_dir),
                    "timeout": timeout_dynamic,
                    "target_kind": "fs_path",  # local read-only path: no net scope check
                    "semgrep_rules": str(semgrep_rules),
                }
            )
    return steps
