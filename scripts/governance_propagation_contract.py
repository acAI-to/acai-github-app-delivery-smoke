"""One canonical body contract for isolated governance propagation PRs."""
from __future__ import annotations

import hashlib
import re


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def body_digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def canonical_pr_body(*, source_repository: str, source_pr: int, target_repository: str, manifest_sha256: str, head_sha: str, base_sha: str) -> str:
    """Render the only target PR body accepted by collector and verifier."""
    fields = (source_repository, target_repository)
    if (
        any(not isinstance(value, str) or not re.fullmatch(r"[^/\s]+/[^/\s]+", value) for value in fields)
        or not isinstance(source_pr, int) or source_pr <= 0
        or not all(isinstance(value, str) and pattern.fullmatch(value) for value, pattern in ((manifest_sha256, DIGEST), (head_sha, SHA), (base_sha, SHA)))
    ):
        raise ValueError("canonical propagation body inputs are malformed")
    return (
        "ACAI isolated governance propagation\n\n"
        f"ACAI-Propagation-Source: {source_repository}#{source_pr}\n"
        f"ACAI-Propagation-Target: {target_repository}\n"
        f"ACAI-Manifest-SHA256: {manifest_sha256}\n"
        f"ACAI-Target-Head: {head_sha}\n"
        f"ACAI-Target-Base: {base_sha}\n"
        "skip-checks: true\n"
    )


def validate_pr_body(body: str, **identity: object) -> list[str]:
    try:
        expected = canonical_pr_body(**identity)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ["canonical propagation body identity is malformed"]
    return [] if isinstance(body, str) and body == expected else ["target PR body is not the canonical propagation body"]
