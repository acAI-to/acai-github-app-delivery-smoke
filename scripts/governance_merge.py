#!/usr/bin/env python3
"""Trusted-default, fail-closed decision helper for autonomous Tier-0/1 merges.

This module deliberately consumes API metadata only.  It never checks out or
executes a pull-request head; the workflow that invokes it is pinned to the
default branch and supplies the GitHub atomic expected-head value separately.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any


REQUIRED_CHECK_RUNS = {
    "change-governance": {"check": "issue-first", "workflow": ".github/workflows/change-governance.yml"},
    "test": {"check": "test", "workflow": ".github/workflows/ci.yml"},
}
PROPAGATION_SOURCE = re.compile(r"(?im)^\s*ACAI-Propagation-Source:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)\s*$")


def parse_propagation_source(body: str) -> tuple[str | None, int | None, list[str]]:
    """Return the single declared source, or deterministic refusal reasons."""
    declarations = PROPAGATION_SOURCE.findall(body or "")
    marker_present = "ACAI-Propagation-Source:" in (body or "")
    if not marker_present:
        return None, None, []
    if len(declarations) != 1:
        return None, None, ["propagation PR must declare exactly one well-formed ACAI-Propagation-Source"]
    repository, number = declarations[0]
    return repository, int(number), []


def _check_runs(check_runs: list[dict[str, Any]], *, head: str, branch: str, repository: str) -> set[str]:
    """Return required checks backed by their actual trusted workflow runs.

    A job display name and a check's ``details_url`` are attacker-controlled
    identifiers for this purpose. The caller attaches the REST workflow run
    record, which is then bound to the check, repository, exact PR event,
    branch and head before it can satisfy a merge requirement.
    """
    satisfied: set[str] = set()
    for key, expected in REQUIRED_CHECK_RUNS.items():
        matching = [item for item in check_runs if isinstance(item, dict) and item.get("name") == expected["check"]]
        for check in matching:
            run = check.get("run") if isinstance(check.get("run"), dict) else {}
            app = check.get("app") if isinstance(check.get("app"), dict) else {}
            run_repo = (run.get("repository") or {}).get("full_name")
            actor = (run.get("actor") or {}).get("login")
            expected_url = f"https://github.com/{repository}/actions/runs/{run.get('id')}"
            details_url_matches = bool(
                re.fullmatch(
                    re.escape(expected_url) + r"(?:/job/[1-9][0-9]*)?",
                    str(check.get("details_url") or ""),
                )
            )
            if (
                details_url_matches
                and str(check.get("head_sha", "")) == head
                and check.get("status") == "completed"
                and check.get("conclusion") == "success"
                and app.get("slug") == "github-actions"
                and str((app.get("owner") or {}).get("login", "")) in {"github", "github-actions"}
                and run.get("id")
                and run.get("html_url") == expected_url
                and run_repo == repository
                and run.get("event") == "pull_request"
                and run.get("head_branch") == branch
                and run.get("head_sha") == head
                and str(run.get("path", "")).split("@", 1)[0] == expected["workflow"]
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and isinstance(run.get("run_attempt"), int) and run["run_attempt"] >= 1
                and isinstance(actor, str) and bool(actor)
            ):
                satisfied.add(key)
    return satisfied


def evaluate_merge(payload: dict[str, Any]) -> list[str]:
    """Return deterministic refusal reasons; an empty list permits one PUT merge.

    Callers must serialize by repository/base before evaluating and use the
    returned ``head_sha`` as GitHub's ``sha`` expected-head guard.
    """
    pr = payload.get("pr") if isinstance(payload.get("pr"), dict) else {}
    governance = payload.get("governance") if isinstance(payload.get("governance"), dict) else {}
    tier = governance.get("tier")
    reasons: list[str] = []
    if tier not in (0, 1):
        reasons.append("orchestrator merge is limited to Tier 0/1; Tier 2 remains operator-only")
    if governance.get("action_phase") != "reviewable-artifact" or governance.get("merge_effect") != "none":
        reasons.append("autonomous merge requires closed reviewable-artifact/none metadata")
    if governance.get("metadata_valid") is not True:
        reasons.append("governance metadata is missing, invalid, duplicate, or conflicting")
    if governance.get("approval_valid") is not True:
        reasons.append("current tier-specific approval is unavailable or stale")
    if governance.get("trusted_run_valid") is not True:
        reasons.append("current trusted-default workflow evidence is unavailable or stale")
    if governance.get("trusted_check_definitions_valid") is not True:
        reasons.append("required check workflow definitions differ from the trusted base")
    if pr.get("isDraft"):
        reasons.append("draft PRs cannot be orchestrator-merged")
    if str(pr.get("state", "")).upper() != "OPEN":
        reasons.append("only open PRs can be orchestrator-merged")
    if str(pr.get("mergeable", "")).upper() not in {"MERGEABLE", "TRUE"}:
        reasons.append("PR is conflicted or mergeability is unknown")
    if str(pr.get("mergeStateStatus", "")).upper() not in {"CLEAN", "HAS_HOOKS"}:
        reasons.append("PR is behind base, blocked, or not clean")
    if not pr.get("headRefOid") or not pr.get("baseRefOid"):
        reasons.append("PR head/base SHA evidence is incomplete")
    head = str(pr.get("headRefOid") or "")
    source_repository, source_pr, propagation_reasons = parse_propagation_source(str(pr.get("body", "")))
    reasons.extend(propagation_reasons)
    if source_repository and source_pr and governance.get("propagation_valid") is not True:
        reasons.append("exact current-head propagation verification is unavailable or failed")
    successful_runs = _check_runs(payload.get("check_runs") if isinstance(payload.get("check_runs"), list) else [], head=head, branch=str(pr.get("headRefName", "")), repository=str(pr.get("repository", "")))
    missing_runs = sorted(set(REQUIRED_CHECK_RUNS) - successful_runs)
    if missing_runs:
        reasons.append("required trusted current-head check runs are not green: " + ", ".join(missing_runs))
    for review in payload.get("reviews") if isinstance(payload.get("reviews"), list) else []:
        if isinstance(review, dict) and str(review.get("state", "")).upper() == "CHANGES_REQUESTED":
            reasons.append("PR has blocking requested changes")
            break
    return list(dict.fromkeys(reasons))


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        reasons = evaluate_merge(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        reasons = [f"malformed trusted-default merge payload: {exc}"]
    print(json.dumps({"ok": not reasons, "reasons": reasons}, sort_keys=True))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
