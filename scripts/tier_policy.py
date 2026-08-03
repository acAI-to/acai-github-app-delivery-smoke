#!/usr/bin/env python3
"""Tracked risk-tier policy and deterministic minimum-tier calculation."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any

TIER_NAMES = {0: "mechanical", 1: "routine", 2: "significant"}
DEFAULT_POLICY = Path("governance/tier-policy.json")


def load_policy(root: Path) -> dict[str, Any]:
    path = root / DEFAULT_POLICY
    if not path.is_file():
        raise ValueError(f"missing tracked tier policy: {DEFAULT_POLICY}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("tier policy version must be 1")
    if data.get("default_tier") not in (0, 1, 2):
        raise ValueError("tier policy default_tier must be 0, 1, or 2")
    return data


def declared_tier(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value in (0, 1, 2):
        return value
    match = re.fullmatch(r"governance/tier-([012])", str(value or "").strip())
    return int(match.group(1)) if match else None


def _risk_tags(metadata: dict[str, Any]) -> set[str]:
    raw = metadata.get("risk_tags", [])
    if isinstance(raw, str):
        values = raw.split(",")
    elif isinstance(raw, list):
        values = raw
    else:
        values = []
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _change_class(metadata: dict[str, Any]) -> str:
    return str(metadata.get("change_class", "")).strip().lower()


def action_metadata_errors(policy: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    """Return fail-closed errors for parser-stable action/effect metadata.

    The caller retains duplicate/conflict counts from both the issue and PR.  A
    policy decision must never infer a live effect from paths or free-form prose.
    """
    contract = policy.get("action_metadata") if isinstance(policy.get("action_metadata"), dict) else {}
    phases = set(contract.get("action_phases") or [])
    effects = set(contract.get("merge_effects") or [])
    enforced = bool(metadata.get("enforce_action_metadata")) or any(
        key in metadata for key in ("action_phase", "merge_effect", "action_metadata_errors")
    )
    if not enforced:
        return []
    errors = [str(value) for value in metadata.get("action_metadata_errors", []) if str(value)]
    phase = str(metadata.get("action_phase") or "").strip().lower()
    effect = str(metadata.get("merge_effect") or "").strip().lower()
    if phase not in phases:
        errors.append("Action phase must appear exactly once on both issue and PR and be reviewable-artifact or live-mutation")
    if effect not in effects:
        errors.append("Merge effect must appear exactly once on both issue and PR and be none or live-mutation")
    return list(dict.fromkeys(errors))


def _has_live_or_trusted_effect(policy: dict[str, Any], metadata: dict[str, Any]) -> bool:
    contract = policy.get("action_metadata") if isinstance(policy.get("action_metadata"), dict) else {}
    trusted = {str(value).strip().lower() for value in contract.get("trusted_control_change_classes", [])}
    return (
        str(metadata.get("action_phase") or "").strip().lower() == "live-mutation"
        or str(metadata.get("merge_effect") or "").strip().lower() == "live-mutation"
        or _change_class(metadata) in trusted
    )


def _tier_two_risk_tags(policy: dict[str, Any]) -> set[str]:
    tags: set[str] = set()
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict) or int(rule.get("tier", 2)) != 2:
            continue
        predicates = rule.get("predicates") or {}
        values = predicates.get("risk_tags", []) if isinstance(predicates, dict) else []
        if isinstance(values, str):
            values = [values]
        tags.update(str(value).strip().lower() for value in values if str(value).strip())
    return tags


def _is_pure_bugfix(policy: dict[str, Any], metadata: dict[str, Any]) -> bool:
    return _change_class(metadata) == "bugfix" and not _risk_tags(metadata).intersection(_tier_two_risk_tags(policy))


def _predicate_matches(predicates: dict[str, Any], metadata: dict[str, Any]) -> bool:
    if not predicates:
        return True
    tags = _risk_tags(metadata)
    if "risk_tags" in predicates:
        expected = predicates["risk_tags"]
        if isinstance(expected, str):
            expected = [expected]
        if not tags.intersection({str(value).strip().lower() for value in expected}):
            return False
    if "issue_metadata" in predicates:
        # Legacy policies now consume explicit tags only. Free-form issue/PR
        # prose is deliberately never treated as a risk signal.
        expected = predicates["issue_metadata"]
        if isinstance(expected, str):
            expected = [expected]
        if not tags.intersection({str(value).strip().lower() for value in expected}):
            return False
    if "change_class" in predicates:
        expected = predicates["change_class"]
        if isinstance(expected, str):
            expected = [expected]
        if str(metadata.get("change_class", "")).strip().lower() not in {str(value).strip().lower() for value in expected}:
            return False
    return True


def _matches(rule: dict[str, Any], paths: list[str], metadata: dict[str, Any]) -> bool:
    globs = rule.get("paths") or []
    path_match = any(fnmatch.fnmatch(path, pattern) for path in paths for pattern in globs)
    predicates = rule.get("predicates") or {}
    predicate_match = _predicate_matches(predicates, metadata)
    if globs and not path_match:
        return False
    return predicate_match


def _matches_mechanical_path(path: str, pattern: str) -> bool:
    if "/" not in pattern and "/" in path:
        return False
    return fnmatch.fnmatch(path, pattern)


def _base_tier(policy: dict[str, Any], paths: list[str]) -> int:
    base = policy.get("default_tier", 1)
    mechanical_paths = policy.get("mechanical_paths") or []
    if paths and all(any(_matches_mechanical_path(path, pattern) for pattern in mechanical_paths) for path in paths):
        base = 0
    return int(base)


def _is_mechanical_change(policy: dict[str, Any], paths: list[str], metadata: dict[str, Any]) -> bool:
    mechanical_paths = policy.get("mechanical_paths") or []
    return bool(paths) and all(
        any(_matches_mechanical_path(path, pattern) for pattern in mechanical_paths) for path in paths
    )


def minimum_tier(policy: dict[str, Any], paths: list[str], metadata: dict[str, Any] | None = None) -> int:
    metadata = metadata or {}
    # Once an issue/PR adopts the action contract, action/effect determines the
    # tier.  Repository/path ownership remains validation scope, not a hidden
    # Tier-2 floor for reviewable artifacts.
    action_errors = action_metadata_errors(policy, metadata)
    action_contract = bool(metadata.get("enforce_action_metadata"))
    has_tier_two_risk = bool(_risk_tags(metadata).intersection(_tier_two_risk_tags(policy)))
    if action_errors or (action_contract and (_has_live_or_trusted_effect(policy, metadata) or has_tier_two_risk)):
        return 2
    if action_contract:
        # A closed reviewable-artifact/none contract intentionally replaces
        # protected-path Tier-2 floors with actual merge/action risk.
        if _is_pure_bugfix(policy, metadata):
            return 1
        return _base_tier(policy, paths)
    if _is_pure_bugfix(policy, metadata):
        return 1
    floor = _base_tier(policy, paths)
    mechanical = _is_mechanical_change(policy, paths, metadata)
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            continue
        if mechanical and int(rule.get("tier", 2)) == 1:
            continue
        if _matches(rule, paths, metadata):
            floor = max(floor, int(rule.get("tier", 2)))
    return floor


def validate_declared_tier(policy: dict[str, Any], declared: Any, paths: list[str], metadata: dict[str, Any] | None = None) -> list[str]:
    metadata = metadata or {}
    action_errors = action_metadata_errors(policy, metadata)
    if action_errors:
        return action_errors + ["invalid or conflicting action metadata requires Tier 2"]
    if _change_class(metadata) == "bugfix" and _risk_tags(metadata).intersection(_tier_two_risk_tags(policy)):
        return ["bugfix change class cannot include Tier 2 risk tags; split risk-bearing actions into separately tiered work"]
    tier = declared_tier(declared)
    if tier is None:
        return ["declared tier is missing or ambiguous; Tier 2 is required"]
    if _is_pure_bugfix(policy, metadata) and tier > 1:
        return ["pure bugfixes must declare Tier 1 or lower"]
    floor = minimum_tier(policy, paths, metadata)
    if tier < floor:
        return [f"declared Tier {tier} is below minimum required Tier {floor}"]
    return []
