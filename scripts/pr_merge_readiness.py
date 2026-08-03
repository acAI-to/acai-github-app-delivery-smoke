#!/usr/bin/env python3
"""Evaluate whether a pull request has fresh, exact-head merge evidence."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
from typing import Any


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


_TIER = re.compile(r"(?im)^\s*Tier:\s*governance/tier-([012])\s*$")


def parse_tier(body: object) -> tuple[int | None, list[str]]:
    text = body if isinstance(body, str) else ""
    declarations = _TIER.findall(text)
    if len(declarations) != 1:
        return None, ["PR body must declare exactly one well-formed governance tier"]
    return int(declarations[0]), []


def evaluate(pr: dict[str, Any], checks: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    tier: int | None = None
    if contract.get("version") == 2:
        tier, tier_blockers = parse_tier(pr.get("body"))
        blockers.extend(tier_blockers)
    if pr.get("state") != "OPEN":
        blockers.append("PR is not open")
    if pr.get("is_draft") is not False:
        blockers.append("PR is still a draft")
    ready_event = pr.get("ready_event")
    if not isinstance(ready_event, dict) or not ready_event.get("created_at"):
        blockers.append("latest ReadyForReviewEvent is missing")
        ready_at = None
    else:
        try:
            ready_at = _time(str(ready_event["created_at"]))
        except ValueError:
            blockers.append("latest ReadyForReviewEvent has an invalid timestamp")
            ready_at = None
    for requirement in contract["checks"]:
        if contract.get("version") == 2:
            tiers = requirement.get("tiers")
            if (
                not isinstance(tiers, list)
                or not tiers
                or any(type(item) is not int or item not in {0, 1, 2} for item in tiers)
                or len(set(tiers)) != len(tiers)
            ):
                blockers.append(f"required check has invalid tier applicability: {requirement.get('name')}")
                continue
            if tier is None or tier not in tiers:
                continue
        names = requirement.get("names")
        if names is None:
            names = [requirement.get("name")]
        if not isinstance(names, list) or not names or not all(isinstance(name, str) and name for name in names):
            blockers.append(f"required check has invalid names: {requirement.get('name')}")
            continue
        label = requirement.get("name") or "|".join(names)
        name_matches = [
            check for check in checks
            if check.get("kind") == requirement.get("kind")
            and check.get("name") in names
            and check.get("head_sha") == pr.get("head_sha")
        ]
        # Workflow state and conclusion are an outcome, not provenance: a failed
        # retry from the same trusted workflow must not poison a later successful
        # retry on the unchanged PR head.  Select the newest trusted retry below
        # and evaluate its terminal outcome there.
        identity_fields = ("publisher", "workflow_event", "workflow_ref")
        workflows = requirement.get("workflows")
        if workflows is None:
            workflows = [requirement.get("workflow")]
        if not isinstance(workflows, list) or not workflows or not all(isinstance(item, str) and item for item in workflows):
            blockers.append(f"required check has invalid workflow provenance: {label}")
            continue
        candidates = [check for check in name_matches if all(check.get(field) == requirement.get(field) for field in identity_fields) and check.get("workflow") in workflows]
        if requirement.get("cardinality", "exactly_one_latest") != "exactly_one_latest":
            blockers.append(f"required check has invalid cardinality: {label}")
            continue
        if len(candidates) != len(name_matches):
            blockers.append(f"required check has unexpected provenance: {label}")
            continue
        if not candidates:
            blockers.append(f"required check is missing: {label}")
            continue
        # Alternative names identify a repository's native CI jobs.  They are
        # not interchangeable outcomes: every observed allowed job must have
        # one unambiguous latest green retry after the ready transition.
        grouped: dict[str, list[dict[str, Any]]] = {}
        for candidate in candidates:
            grouped.setdefault(str(candidate["name"]), []).append(candidate)
        for candidate_name, group in sorted(grouped.items()):
            item_label = label if len(grouped) == 1 else f"{label} ({candidate_name})"
            try:
                completion_times = [(check, _time(str(check["completed_at"]))) for check in group]
            except (KeyError, TypeError, ValueError):
                blockers.append(f"required check has an invalid completion timestamp: {item_label}")
                continue
            latest_at = max(completed_at for _, completed_at in completion_times)
            latest = [check for check, completed_at in completion_times if completed_at == latest_at]
            if len(latest) != 1:
                blockers.append(f"required check has ambiguous latest retry: {item_label}")
                continue
            check = latest[0]
            if check.get("status") != "completed" or check.get("conclusion") != requirement.get("conclusion", "success"):
                blockers.append(f"required check is not successful: {item_label}")
            elif ready_at is not None and latest_at <= ready_at:
                blockers.append(f"required check did not complete after ready event: {item_label}")
    return {"status": "blocked" if blockers else "ready", "blockers": blockers}


def evaluate_snapshots(initial: dict[str, Any], final: dict[str, Any], checks: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    result = evaluate(initial, checks, contract)
    if contract.get("version") == 2:
        initial_tier, _ = parse_tier(initial.get("body"))
        final_tier, final_tier_blockers = parse_tier(final.get("body"))
        result["blockers"].extend(final_tier_blockers)
        if initial_tier is not None and final_tier is not None and initial_tier != final_tier:
            result["blockers"].append("PR tier changed during verification")
    if initial.get("head_sha") != final.get("head_sha"):
        result["blockers"].append("PR head changed during verification")
    if initial.get("body") != final.get("body"):
        result["blockers"].append("PR body changed during verification")
    if initial.get("is_draft") != final.get("is_draft"):
        result["blockers"].append("PR draft state changed during verification")
    if initial.get("state") != final.get("state"):
        result["blockers"].append("PR state changed during verification")
    initial_event = (initial.get("ready_event") or {}).get("id")
    final_event = (final.get("ready_event") or {}).get("id")
    if initial_event != final_event:
        result["blockers"].append("PR ready-event changed during verification")
    if result["blockers"]:
        result["status"] = "blocked"
    return result


def _gh(*args: str) -> Any:
    proc = subprocess.run(["gh", *args], check=False, text=True, capture_output=True)
    if proc.returncode:
        raise ValueError(proc.stderr.strip() or "GitHub query failed")
    return json.loads(proc.stdout)


_ACTION_RUN_URL = re.compile(r"^https://github\.com/[^/]+/[^/]+/actions/runs/(\d+)(?:/|$)")


def _workflow_identity_from_url(repository: str, url: object, head_sha: str, default_branch: str, cache: dict[str, dict[str, str | None] | None]) -> dict[str, str | None] | None:
    """Return immutable workflow provenance for a same-head GitHub Actions run URL."""
    match = _ACTION_RUN_URL.match(url) if isinstance(url, str) else None
    if match is None:
        return None
    run_id = match.group(1)
    if run_id not in cache:
        run = _gh("api", f"repos/{repository}/actions/runs/{run_id}")
        path = str(run.get("path") or "").split("@", 1)[0]
        if run.get("event") == "pull_request" and run.get("head_sha") == head_sha:
            workflow_ref = "head"
        elif run.get("event") == "workflow_dispatch" and run.get("head_branch") == default_branch:
            workflow_ref = "default_branch"
        else:
            workflow_ref = None
        cache[run_id] = {
            "workflow": path,
            "workflow_event": run.get("event"),
            "workflow_ref": workflow_ref,
            "workflow_status": run.get("status"),
            "workflow_conclusion": run.get("conclusion"),
        } if (
            isinstance(path, str)
            and workflow_ref is not None
        ) else None
    return cache[run_id]


def _workflow_fields(repository: str, url: object, head_sha: str, default_branch: str, cache: dict[str, dict[str, str | None] | None]) -> dict[str, str | None]:
    identity = _workflow_identity_from_url(repository, url, head_sha, default_branch, cache)
    return identity or {"workflow": None, "workflow_event": None, "workflow_ref": None, "workflow_status": None, "workflow_conclusion": None}


def _snapshot(repository: str, number: int) -> dict[str, Any]:
    pr = _gh("pr", "view", str(number), "--repo", repository, "--json", "state,isDraft,headRefOid,body")
    owner, name = repository.split("/", 1)
    query = "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){timelineItems(last:100,itemTypes:READY_FOR_REVIEW_EVENT){nodes{... on ReadyForReviewEvent{id createdAt}}}}}}"
    events = _gh("api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={name}", "-F", f"number={number}")
    nodes = events["data"]["repository"]["pullRequest"]["timelineItems"]["nodes"]
    ready_event = max(nodes, key=lambda item: item["createdAt"], default=None)
    return {"state": pr["state"], "is_draft": pr["isDraft"], "head_sha": pr["headRefOid"], "body": pr.get("body", ""), "ready_event": None if ready_event is None else {"id": ready_event["id"], "created_at": ready_event["createdAt"]}}


def collect_live_evidence(repository: str, number: int) -> dict[str, Any]:
    initial = _snapshot(repository, number)
    sha = initial["head_sha"]
    default_branch = _gh("api", f"repos/{repository}").get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ValueError("repository default branch is unavailable")
    check_run_response = _gh("api", f"repos/{repository}/commits/{sha}/check-runs?per_page=100")
    check_runs = check_run_response.get("check_runs", [])
    if check_run_response.get("total_count") != len(check_runs):
        raise ValueError("check-run pagination is incomplete")
    status_response = _gh("api", f"repos/{repository}/commits/{sha}/status")
    statuses = status_response.get("statuses", [])
    if status_response.get("total_count") != len(statuses):
        raise ValueError("commit-status pagination is incomplete")
    workflow_cache: dict[str, dict[str, str | None] | None] = {}
    checks = [{"id": item.get("id"), "kind": "check_run", "name": item.get("name"), "publisher": (item.get("app") or {}).get("slug"), "status": item.get("status"), "conclusion": item.get("conclusion"), "head_sha": sha, "completed_at": item.get("completed_at"), **_workflow_fields(repository, item.get("details_url"), sha, default_branch, workflow_cache)} for item in check_runs]
    checks += [{"id": item.get("id"), "kind": "commit_status", "name": item.get("context"), "publisher": (item.get("creator") or {}).get("login"), "status": "completed", "conclusion": "success" if item.get("state") == "success" else item.get("state"), "head_sha": sha, "completed_at": item.get("updated_at"), **_workflow_fields(repository, item.get("target_url"), sha, default_branch, workflow_cache)} for item in statuses]
    return {"initial": initial, "checks": checks, "final": _snapshot(repository, number)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-json", type=Path, help="normalized read-only GitHub evidence")
    source.add_argument("--pr", type=int, help="live pull request number")
    parser.add_argument("--repo", help="owner/repository for --pr")
    parser.add_argument("--contract", type=Path, default=Path("governance/merge-readiness-checks.json"))
    args = parser.parse_args()
    try:
        evidence = json.loads(args.input_json.read_text(encoding="utf-8")) if args.input_json else collect_live_evidence(args.repo or "", args.pr)
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        result = evaluate_snapshots(evidence["initial"], evidence["final"], evidence["checks"], contract)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "blocked", "blockers": [f"readiness evidence is invalid: {exc}"]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
