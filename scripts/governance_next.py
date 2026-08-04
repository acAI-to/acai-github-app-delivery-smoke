#!/usr/bin/env python3
"""Read-only next-step evaluation for governed repository changes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import tier_policy
import validation_profile


PHASES = (
    "issue-plan", "independent-plan-review", "approval", "draft-pr",
    "implementation", "gate-a", "gate-b", "ready-for-review",
)


def evaluate(root: Path, paths: list[str], metadata: dict[str, Any], phase: str) -> dict[str, Any]:
    """Select the next allowed phase without changing repository or GitHub state."""
    tier = tier_policy.load_policy(root)
    validation = validation_profile.load_policy(root)
    tier_reasons = tier_policy.validate_declared_tier(tier, metadata.get("declared_tier"), paths, metadata)
    selected_profile = validation_profile.select_profile(validation, paths, metadata)
    declared_tier = tier_policy.declared_tier(metadata.get("declared_tier"))
    blockers = tier_reasons
    if phase == "ready-for-review" and metadata.get("github_status") == "unknown":
        blockers.append("unknown GitHub status cannot satisfy ready-for-review enforcement evidence")
    if blockers:
        return {
            "status": "blocked", "phase": phase, "next_phase": "issue-plan",
            "allowed_actions": ["revise issue plan metadata"], "blockers": list(dict.fromkeys(blockers)),
            "required_tier": tier_policy.minimum_tier(tier, paths, metadata), "validation": selected_profile,
        }
    transitions = {
        "issue-plan": "independent-plan-review" if declared_tier == 2 else ("approval" if declared_tier == 1 else "draft-pr"),
        "independent-plan-review": "approval",
        "approval": "draft-pr",
        "draft-pr": "implementation",
        "implementation": "gate-a",
        "gate-a": "gate-b" if declared_tier == 2 else "ready-for-review",
        "gate-b": "ready-for-review",
        "ready-for-review": "ready-for-review",
    }
    next_phase = transitions[phase]
    actions = {
        "independent-plan-review": "request independent adversarial plan review",
        "approval": "request the tier-specific approval artifact",
        "draft-pr": "create issue-linked branch and draft PR",
        "implementation": "begin implementation",
        "gate-a": "run Gate A validation",
        "gate-b": "request exact-head independent Gate B",
        "ready-for-review": "mark the PR ready for operator review",
    }
    return {
        "status": "ready", "phase": phase, "next_phase": next_phase,
        "allowed_actions": [actions[next_phase]], "blockers": [],
        "required_tier": tier_policy.minimum_tier(tier, paths, metadata), "validation": selected_profile,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--path", dest="paths", action="append", required=True)
    parser.add_argument("--metadata-json", default="{}")
    parser.add_argument("--phase", choices=PHASES, default="issue-plan")
    args = parser.parse_args()
    metadata = json.loads(args.metadata_json)
    if not isinstance(metadata, dict):
        raise ValueError("metadata JSON must be an object")
    print(json.dumps(evaluate(args.root, args.paths, metadata, args.phase), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
