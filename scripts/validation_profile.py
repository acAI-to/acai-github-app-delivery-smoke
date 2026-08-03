#!/usr/bin/env python3
"""Select and validate deterministic repository validation profiles."""

from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import Path
from typing import Any

PROFILES = ("mechanical", "targeted", "full", "full-plus-runtime")
PROFILE_RANK = {profile: index for index, profile in enumerate(PROFILES)}
DEFAULT_POLICY = Path("governance/validation-policy.json")


def load_policy(root: Path) -> dict[str, Any]:
    path = root / DEFAULT_POLICY
    if not path.is_file():
        raise ValueError(f"missing tracked validation policy: {DEFAULT_POLICY}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("validation policy version must be 1")
    for key in ("default_profile", "unknown_profile"):
        if data.get(key) not in PROFILES:
            raise ValueError(f"validation policy {key} must be one of {PROFILES}")
    ci_test_mode = data.get("ci_test_mode")
    if not isinstance(ci_test_mode, dict) or set(ci_test_mode) != set(PROFILES):
        raise ValueError("validation policy ci_test_mode must map every validation profile")
    if ci_test_mode.get("mechanical") != "success":
        raise ValueError("mechanical validation profile must emit explicit test success")
    if any(ci_test_mode.get(profile) != "run" for profile in PROFILES if profile != "mechanical"):
        raise ValueError("non-mechanical validation profiles must run the test job")
    return data


def _tags(metadata: dict[str, Any]) -> set[str]:
    raw = metadata.get("risk_tags", [])
    if isinstance(raw, str):
        values = raw.split(",")
    elif isinstance(raw, list):
        values = raw
    else:
        values = []
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _matches_any(paths: list[str], patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for path in paths for pattern in patterns)


def _matches_all_known(paths: list[str], policy: dict[str, Any]) -> bool:
    patterns = (
        list(policy.get("mechanical_paths", []))
        + list(policy.get("targeted_paths", []))
        + list(policy.get("full_paths", []))
    )
    return bool(paths) and all(_matches_any([path], patterns) for path in paths)


def _matches_all(paths: list[str], patterns: list[str]) -> bool:
    return bool(paths) and all(_matches_any([path], patterns) for path in paths)


def _repository_default_profile(policy: dict[str, Any], metadata: dict[str, Any]) -> str:
    kind = str(metadata.get("repository_kind") or policy.get("repository_kind") or "")
    defaults = policy.get("repository_defaults", {})
    if isinstance(defaults, dict) and isinstance(defaults.get(kind), dict):
        profile = defaults[kind].get("default_profile")
        if profile in PROFILES:
            return profile
    return str(policy.get("default_profile", "targeted"))


def _native_commands(policy: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("native_commands")
    if isinstance(raw, list):
        return [str(command) for command in raw if str(command).strip()]
    kind = str(metadata.get("repository_kind") or policy.get("repository_kind") or "")
    defaults = policy.get("repository_defaults", {})
    if isinstance(defaults, dict) and isinstance(defaults.get(kind), dict):
        commands = defaults[kind].get("native_commands", [])
        if isinstance(commands, list):
            return [str(command) for command in commands if str(command).strip()]
    return []


def _required_profile(policy: dict[str, Any], paths: list[str], metadata: dict[str, Any]) -> tuple[str, str]:
    tags = _tags(metadata)
    if tags.intersection(set(policy.get("runtime_risk_tags", []))):
        candidate, rationale = "full-plus-runtime", "runtime or irreversible risk tag requires runtime evidence"
    elif tags.intersection(set(policy.get("full_risk_tags", []))):
        candidate, rationale = "full", "high-risk tag requires full validation"
    elif _matches_any(paths, list(policy.get("full_paths", []))):
        candidate, rationale = "full", "shared governance or workflow path requires full validation"
    elif str(metadata.get("change_class", "")).strip().lower() == "mechanical" and _matches_all(paths, list(policy.get("mechanical_paths", []))):
        candidate, rationale = "mechanical", "explicit mechanical change on known mechanical paths"
    elif _matches_all_known(paths, policy) and _matches_any(paths, list(policy.get("targeted_paths", []))):
        candidate, rationale = "targeted", "known isolated path uses targeted validation"
    else:
        candidate, rationale = str(policy.get("unknown_profile", "full")), "unknown or ambiguous path mapping escalates to full"

    if candidate == "targeted" and not _native_commands(policy, metadata):
        return "full", "focused validation command mapping is unavailable; escalate to full"

    default = _repository_default_profile(policy, metadata)
    if metadata.get("change_class") != "mechanical" and PROFILE_RANK[default] > PROFILE_RANK[candidate]:
        return default, f"repository default profile {default} is broader than {candidate}"
    return candidate, rationale


def select_profile(policy: dict[str, Any], paths: list[str], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    required, rationale = _required_profile(policy, paths, metadata)
    # Validation is selected from immutable policy inputs, never from free-form
    # issue or PR prose.  Old records may retain ``validation_profile`` for
    # audit readability, but it is deliberately ignored: a stale declaration
    # must not select or cap validation.
    profile = required
    escalated = any(marker in rationale.lower() for marker in ("unknown or ambiguous", "unavailable"))

    repository_kind = str(metadata.get("repository_kind") or policy.get("repository_kind") or "")
    required_suites = list(policy.get("required_suites", {}).get(profile, [profile]))
    ci_test_mode = str(policy["ci_test_mode"][profile])
    native_commands = _native_commands(policy, metadata)
    return {
        "profile": profile,
        "rationale": rationale,
        "required_suites": required_suites,
        "status_contexts": ["test"],
        "ci_test_mode": ci_test_mode,
        "native_commands": [str(command) for command in native_commands],
        "residual_risk": "explicitly record any untested consumers or runtime behavior",
        "escalated": escalated,
        "repository_kind": repository_kind or None,
    }


def validate_declared_profile(policy: dict[str, Any], paths: list[str], metadata: dict[str, Any] | None = None) -> list[str]:
    """Compatibility shim for v1 records.

    Profile declarations are historic evidence only.  Keeping this callable
    lets old clients parse v1/v2 records without silently turning a missing
    field into a failure, while every caller obtains the authoritative result
    through :func:`select_profile`.
    """
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--path", dest="paths", action="append", required=True)
    parser.add_argument("--metadata-json", default="{}")
    args = parser.parse_args()
    metadata = json.loads(args.metadata_json)
    print(json.dumps(select_profile(load_policy(args.root), args.paths, metadata), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
