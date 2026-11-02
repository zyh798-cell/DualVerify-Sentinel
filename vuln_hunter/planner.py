"""Plan builder. Kept minimal: what runs depends only on mode + inputs."""
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
    return steps
