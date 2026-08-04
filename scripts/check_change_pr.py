#!/usr/bin/env python3
"""Evaluate issue-first plan/rubric governance for a GitHub pull request."""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable

import plan_approval
import tier_policy
import validation_profile

ISSUE_LINK_RE = re.compile(r"(?im)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|issue)\s*:?[ \t]+#(\d+)\b")
METADATA_LINE_RE = re.compile(r"(?im)^\s*(Risk tags|Validation profile|Repository kind|Change class|GitHub status|Action phase|Merge effect|Parent issue|Parent rubric digest|No live mutation)\s*:\s*(.*?)\s*$")
ISSUE_FORM_FIELD_RE = re.compile(
    r"(?ims)^\s*###\s*(Tier|Risk tags|Validation profile|Repository kind|Change class|GitHub status|Adversarial profile|Changed paths|Justification|Action phase|Merge effect|Parent issue|Parent rubric digest|No live mutation)\s*$\n+(.*?)(?=^\s*###\s|\Z)"
)
VALID_GITHUB_STATUSES = {"enforced", "advisory/pre-enforcement", "unknown"}


def parse_governance_metadata(pr_body: str, issue_body: str) -> dict[str, Any]:
    """Parse only explicit machine-readable governance fields from prose."""
    values: dict[str, str] = {}
    risk_tags: set[str] = set()
    per_source: dict[str, dict[str, list[str]]] = {"issue": {}, "pr": {}}
    for source, body in (("issue", issue_body or ""), ("pr", pr_body or "")):
        explicit_fields = list(ISSUE_FORM_FIELD_RE.finditer(body)) + list(METADATA_LINE_RE.finditer(body))
        for match in explicit_fields:
            key, value = match.group(1).lower(), match.group(2).strip()
            if value.startswith("<") and value.endswith(">"):
                continue
            if key == "risk tags":
                risk_tags.update(tag.strip().lower() for tag in value.split(",") if tag.strip())
            elif value and key not in values:
                values[key] = value.lower()
            if key in {"action phase", "merge effect", "parent issue", "parent rubric digest", "no live mutation", "change class"}:
                per_source[source].setdefault(key, []).append(value.lower())
    action_errors: list[str] = []
    matching: dict[str, str] = {}
    for key in ("action phase", "merge effect"):
        issue_values, pr_values = per_source["issue"].get(key, []), per_source["pr"].get(key, [])
        if len(issue_values) != 1 or len(pr_values) != 1:
            action_errors.append(f"{key.title()} must appear exactly once on both issue and PR")
        elif issue_values[0] != pr_values[0]:
            action_errors.append(f"{key.title()} conflicts between issue and PR")
        else:
            matching[key] = issue_values[0]
    issue_classes, pr_classes = per_source["issue"].get("change class", []), per_source["pr"].get("change class", [])
    if (issue_classes and len(issue_classes) != 1) or (pr_classes and len(pr_classes) != 1):
        action_errors.append("Change class must appear exactly once on both issue and PR")
    elif issue_classes and pr_classes and issue_classes[0] != pr_classes[0]:
        action_errors.append("Change class conflicts between issue and PR")
    elif issue_classes or pr_classes:
        matching["change class"] = (issue_classes or pr_classes)[0]
    parent_errors: list[str] = []
    for key in ("parent issue", "parent rubric digest", "no live mutation"):
        issue_values, pr_values = per_source["issue"].get(key, []), per_source["pr"].get(key, [])
        if bool(issue_values) != bool(pr_values) or (issue_values and (len(issue_values) != 1 or len(pr_values) != 1 or issue_values[0] != pr_values[0])):
            parent_errors.append(f"{key.title()} must be a single matching issue/PR value")
        elif issue_values:
            matching[key] = issue_values[0]
    profile = values.get("validation profile")
    return {
        "risk_tags": sorted(risk_tags),
        "validation_profile": profile,
        "repository_kind": values.get("repository kind"),
        "change_class": matching.get("change class") or ("mechanical" if profile == "mechanical" else None),
        "github_status": values.get("github status"),
        "action_phase": matching.get("action phase"),
        "merge_effect": matching.get("merge effect"),
        "action_metadata_errors": action_errors,
        "enforce_action_metadata": True,
        "parent_issue": matching.get("parent issue"),
        "parent_rubric_digest": matching.get("parent rubric digest"),
        "no_live_mutation": matching.get("no live mutation"),
        "parent_metadata_errors": parent_errors,
    }


def validate_parent_child_scope(metadata: dict[str, Any], tier: int) -> list[str]:
    """A parent link is coordination only; child approvals are always independent."""
    reasons = list(metadata.get("parent_metadata_errors", []))
    parent = str(metadata.get("parent_issue") or "")
    if not parent:
        return reasons
    if tier != 1:
        reasons.append("linked child delivery must declare Tier 1")
    if not re.fullmatch(r"#?[1-9][0-9]*", parent):
        reasons.append("Parent issue must be a positive issue number")
    if not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("parent_rubric_digest") or "")):
        reasons.append("linked child requires a 64-character Parent rubric digest")
    if metadata.get("no_live_mutation") != "true":
        reasons.append("linked child requires No live mutation: true")
    if metadata.get("action_phase") != "reviewable-artifact" or metadata.get("merge_effect") != "none":
        reasons.append("linked child must remain reviewable-artifact with Merge effect none")
    return list(dict.fromkeys(reasons))


def declared_tier(pr: dict[str, Any], issue_body: str = "") -> int | None:
    for text in (str(pr.get("body", "")), issue_body or ""):
        match = re.search(r"(?im)^\s*(?:Tier|Declared tier)\s*:\s*(?:governance/tier-)?([012])\s*$", text)
        if match:
            return int(match.group(1))
        for field in ISSUE_FORM_FIELD_RE.finditer(text):
            if field.group(1).lower() == "tier":
                value = field.group(2).strip().lower()
                match = re.fullmatch(r"(?:governance/tier-)?([012])", value)
                if match:
                    return int(match.group(1))
    return None


def linked_issue(body: str) -> int | None:
    match = ISSUE_LINK_RE.search(body or "")
    return int(match.group(1)) if match else None


def _latest(comments: list[dict[str, Any]], marker: str) -> dict[str, Any] | None:
    found = [c for c in comments if isinstance(c, dict) and marker in str(c.get("body", ""))]
    return max(found, key=lambda c: str(c.get("updated_at") or c.get("created_at") or ""), default=None)


def evaluate_strict(
    pr: dict[str, Any],
    issue: dict[str, Any],
    comments: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    allowlist: set[str],
    review_logins: set[str],
    source_run_validator: Callable[[str, str, str, str], list[str]] | None = None,
    enforce_tier: bool = False,
) -> tuple[bool, str]:
    number = linked_issue(str(pr.get("body", "")))
    if number is None or number != issue.get("number"):
        return False, "PR body must close/fix/resolve or identify its governed issue"
    branch = str(pr.get("headRefName", ""))
    base = str(pr.get("baseRefName", ""))
    if not branch or branch == base or str(number) not in branch:
        return False, "PR head must be a non-default issue-linked branch"
    issue_body = str(issue.get("body", ""))
    if "## Plan" not in issue_body or "## Fixed rubric" not in issue_body:
        return False, "linked issue must contain `## Plan` and `## Fixed rubric`"
    repository = str(pr.get("repository", ""))
    declared = declared_tier(pr, issue_body)
    tier = declared
    if tier is None:
        if enforce_tier:
            return False, "declared tier is missing or ambiguous; Tier 2 is required"
        tier = 2
    try:
        policy = tier_policy.load_policy(__import__("pathlib").Path.cwd())
        paths = [str(p) for p in pr.get("changed_paths", [])]
        metadata = parse_governance_metadata(str(pr.get("body", "")), issue_body)
        floor_reasons = tier_policy.validate_declared_tier(policy, tier, paths, metadata)
        if floor_reasons:
            return False, "; ".join(floor_reasons)
        parent_reasons = validate_parent_child_scope(metadata, tier)
        if parent_reasons:
            return False, "; ".join(parent_reasons)
        selected_profile = validation_profile.select_profile(
            validation_profile.load_policy(__import__("pathlib").Path.cwd()), paths, metadata
        )
        if tier == 2 and declared == 2:
            if metadata.get("github_status") not in VALID_GITHUB_STATUSES:
                return False, "GitHub status must be enforced, advisory/pre-enforcement, or unknown"
            if metadata.get("github_status") == "unknown":
                return False, "unknown GitHub status cannot satisfy enforcement evidence"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, f"tier policy unavailable: {exc}"
    if tier == 0:
        return True, f"issue-first governance PASS for #{number} (Tier 0 Gate A only)"
    if tier == 1:
        return True, f"issue-first governance PASS for #{number} (Tier 1 Gate A; Gate B waived)"
    approval = plan_approval.latest_plan_review(comments)
    review_reasons = plan_approval.validate_plan_review(
        repository=repository, issue=issue, comment=approval, allowlist=review_logins,
    )
    if review_reasons:
        return False, "; ".join(review_reasons)
    approval_reasons = plan_approval.validate_approval(repository=repository, issue=issue, comments=comments, timeline=timeline, allowlist=allowlist, source_run_validator=source_run_validator)
    if approval_reasons:
        return False, "; ".join(approval_reasons)
    return True, f"issue-first governance PASS for #{number} (Tier 2 independent review + digest-bound operator label; validation={selected_profile['profile']})"


def evaluate(
    pr: dict[str, Any],
    issue: dict[str, Any],
    comments: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    allowlist: set[str],
    review_logins: set[str],
    source_run_validator: Callable[[str, str, str, str], list[str]] | None = None,
    enforce_tier: bool = False,
) -> tuple[bool, str]:
    ok, reason = evaluate_strict(
        pr, issue, comments, timeline, allowlist, review_logins, source_run_validator,
        enforce_tier
    )
    if not ok and bool(pr.get("isDraft")):
        return True, f"Change governance pending: draft PR — {reason}"
    return ok, reason


def main() -> int:
    try:
        raw_payload = sys.stdin.read()
        if not raw_payload.strip():
            raise ValueError("empty change-governance payload — upstream jq/collection step failed")
        payload = json.loads(raw_payload)
        pr = payload["pr"]
        issue = payload["issue"]
        comments = payload["comments"]
        timeline = payload["timeline"]
        allowlist = set(payload.get("operator_logins", []))
        independent_review_logins = set(payload.get("independent_review_logins", []))
        ok, reason = evaluate(
            pr, issue, comments, timeline, allowlist, independent_review_logins,
            enforce_tier=True,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        ok, reason = False, f"malformed change-governance payload: {exc}"
    print(reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
