#!/usr/bin/env python3
"""Locally attest one exact-head checksum-verified governance propagation.

This is intentionally an operator-side bridge for private repositories where
the per-repository GitHub Actions token cannot read the trusted harness source.
It uses the existing authenticated GitHub CLI identity only for API reads and
for posting one commit status; no credential is stored in a repository or
workflow secret.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any

import governance_propagation_collect as collector
import governance_propagation_verify as verifier


CONTEXT = "governance/propagation-attested"


def post_status(repository: str, sha: str, source_repository: str, source_pr: int) -> None:
    target_url = f"https://github.com/{source_repository}/pull/{source_pr}"
    process = subprocess.run(
        [
            "gh", "api", "--method", "POST", f"repos/{repository}/statuses/{sha}",
            "-f", "state=success", "-f", f"context={CONTEXT}",
            "-f", "description=Exact-head checksum-attested propagation verified locally",
            "-f", f"target_url={target_url}",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or "unable to publish propagation attestation")


def attest(source_repository: str, source_pr: int, target_repository: str, target_pr: int) -> dict[str, Any]:
    data = collector.collect(source_repository, source_pr, target_repository, target_pr)
    reasons = verifier.verify(data)
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    head = str(target.get("head") or "")
    if reasons:
        raise RuntimeError("; ".join(reasons))
    if len(head) != 40:
        raise RuntimeError("target PR head is unavailable")
    post_status(target_repository, head, source_repository, source_pr)
    return {"context": CONTEXT, "source_pr": source_pr, "target_head": head, "tier1_eligible": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-pr", required=True, type=int)
    parser.add_argument("--target-repository", required=True)
    parser.add_argument("--target-pr", required=True, type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(attest(args.source_repository, args.source_pr, args.target_repository, args.target_pr), sort_keys=True))
    except (RuntimeError, TypeError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "tier1_eligible": False}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
