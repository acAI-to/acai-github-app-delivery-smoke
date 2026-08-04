#!/usr/bin/env python3
"""Evaluate the ACAI Gate-B adversarial-review artifact on a pull request.

The harness governance loop requires an independent adversarial (Gate-B) review
before a change is presented for merge. This makes that gate machine-checkable:
a configured independent reviewer posts a
PR comment following the Gate-B contract, and CI turns the comment into a
required `governance/gate-b` commit status.

Contract for the Gate-B comment (see docs/harness-governance-enforcement.md):

    <!-- ACAI-GATE-B -->
    Gate-B: PASS
    Commit: <full 40-character head sha reviewed>
    Reviewer: independent-review
    <findings / rationale>

Rules:
- The most recently created-or-edited comment carrying the `<!-- ACAI-GATE-B -->`
  marker decides (editing an earlier verdict re-ranks it).
- It must record a `Gate-B: PASS` verdict.
- It must record the full 40-character `Commit:` it reviewed, and that commit
  must equal the current PR head. A new commit therefore invalidates a prior
  Gate-B and a fresh review is required (this is what stops "review once, then
  push anything, then merge"). A short sha is rejected because it could collide
  with a different commit.

Reads a JSON array of PR issue comments on stdin. Head sha comes from argv[1]
or $GATE_B_HEAD_SHA. `--draft` returns a non-failing pending result because a
draft cannot merge; marking ready reruns the strict head-bound evaluation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Callable

MARKER = "<!-- ACAI-GATE-B -->"
VERDICT_RE = re.compile(r"gate[-\s]?b\s*[:\-]\s*(pass|fail)\b", re.IGNORECASE)
# Capture up to 40 hex; evaluate() requires the FULL head sha, never a prefix.
COMMIT_RE = re.compile(r"commit\s*[:\-]\s*([0-9a-f]{7,40})\b", re.IGNORECASE)
RUN_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/actions/runs/(\d+)$")
BOT_LOGINS = {"github-actions[bot]", "github-actions"}


def _field(body: str, name: str) -> str:
    match = re.search(rf"(?im)^{re.escape(name)}:\s*(.+?)\s*$", body)
    return match.group(1).strip() if match else ""


def validate_relay_run(source_url: str, repository: str, relay_actor: str, allowed: set[str], reviewer: str) -> list[str]:
    match = RUN_URL_RE.fullmatch(source_url)
    if not match or match.group(1) != repository:
        return ["Gate-B source must be a same-repository Actions run"]
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/actions/runs/{match.group(2)}"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return ["Gate-B relay Actions run is unavailable"]
    try:
        run = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ["Gate-B relay Actions run returned malformed JSON"]
    reasons: list[str] = []
    workflow = str(run.get("path", "")).split("@", 1)[0]
    expected_workflow = ".github/workflows/independent-review-gate-b-relay.yml"
    if run.get("event") != "workflow_dispatch" or workflow != expected_workflow:
        reasons.append("Gate-B source is not a trusted role-routed relay workflow")
    if run.get("html_url") != source_url:
        reasons.append("Gate-B relay run URL does not match")
    actual_actor = str((run.get("triggering_actor") or {}).get("login", ""))
    if relay_actor not in allowed or actual_actor != relay_actor:
        reasons.append("Gate-B relay actor is not allowlisted or source-bound")
    if run.get("status") == "completed" and run.get("conclusion") != "success":
        reasons.append("Gate-B relay workflow did not succeed")
    return reasons


def _comment_order_key(comment):
    # An edited comment must be able to override an earlier one, so rank by last
    # update time, falling back to creation time.
    return comment.get("updated_at") or comment.get("created_at") or ""


def evaluate(
    comments,
    head_sha: str,
    reviewer_logins: set[str] | None = None,
    repository: str = "",
    source_validator: Callable[[str, str, str, set[str]], list[str]] | None = None,
    independent_reviewer_logins: set[str] | None = None,
):
    """Return (passed: bool, reason: str) for the Gate-B artifact.

    Fails closed: any unexpected shape is treated as "no valid artifact".
    """
    if not isinstance(comments, list):
        return False, "comments payload was not a JSON array"

    marked = [
        c
        for c in comments
        if isinstance(c, dict) and MARKER in (c.get("body") or "")
    ]
    if not marked:
        return False, "no Gate-B artifact: missing an `<!-- ACAI-GATE-B -->` review comment"

    marked.sort(key=_comment_order_key)
    latest = marked[-1]
    body = latest.get("body") or ""

    author = str((latest.get("user") or {}).get("login", ""))
    if author not in BOT_LOGINS:
        return False, "latest Gate-B artifact must be authored by the trusted GitHub Actions relay"
    reviewer = _field(body, "Reviewer")
    if reviewer != "independent-review":
        return False, "latest Gate-B artifact does not identify Reviewer: independent-review"
    if _field(body, "Contract-Version") != "3":
        return False, "independent Gate-B contract version is missing or stale"
    allowed = independent_reviewer_logins or reviewer_logins or set()
    relay_actor = _field(body, "Relay-Actor")
    source_url = _field(body, "Source-URL")
    session = _field(body, "Session")
    if _field(body, "Source-Event") != "workflow_dispatch":
        return False, "latest Gate-B artifact must record Source-Event: workflow_dispatch"
    if not allowed or not repository or not relay_actor or not source_url or not session:
        return False, "latest Gate-B artifact lacks trusted relay provenance fields"
    if source_validator is None and relay_actor not in allowed:
        return False, "latest Gate-B relay actor is not allowlisted"
    if source_validator:
        source_reasons = source_validator(source_url, repository, relay_actor, allowed)
    else:
        source_reasons = validate_relay_run(source_url, repository, relay_actor, allowed, reviewer)
    if source_reasons:
        return False, "; ".join(source_reasons)

    verdict_match = VERDICT_RE.search(body)
    if not verdict_match:
        return False, "latest Gate-B comment has no `Gate-B: PASS|FAIL` verdict line"
    verdict = verdict_match.group(1).upper()
    if verdict != "PASS":
        return False, f"latest Gate-B verdict is {verdict}, not PASS"

    if head_sha:
        head = head_sha.lower()
        commit_match = COMMIT_RE.search(body)
        if not commit_match:
            return False, "latest Gate-B comment does not record the reviewed `Commit: <sha>`"
        reviewed = commit_match.group(1).lower()
        # Require the full 40-char head sha, not a prefix: a short sha can collide
        # with a different commit and wrongly satisfy the gate for this head.
        if len(reviewed) < 40:
            return (
                False,
                "Gate-B `Commit:` must be the full 40-character head sha "
                f"(got short sha {reviewed})",
            )
        if reviewed != head:
            return (
                False,
                f"Gate-B reviewed commit {reviewed[:12]} != head {head[:12]}; "
                "re-review required after new commits",
            )

    where = head_sha[:12] if head_sha else "PR"
    return True, f"Gate-B PASS for {where}"


def evaluate_pr(
    comments, head_sha: str, *, is_draft: bool, reviewer_logins: set[str] | None = None,
    repository: str = "", source_validator: Callable[[str, str, str, set[str]], list[str]] | None = None,
    independent_reviewer_logins: set[str] | None = None,
):
    if is_draft:
        return True, "Gate B pending: draft PR"
    return evaluate(comments, head_sha, reviewer_logins, repository, source_validator, independent_reviewer_logins)


def main() -> int:
    args = [arg for arg in sys.argv[1:] if arg != "--draft"]
    is_draft = "--draft" in sys.argv[1:]
    head_sha = args[0] if args else os.environ.get("GATE_B_HEAD_SHA", "")
    raw = sys.stdin.read().strip() or "[]"
    try:
        comments = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        print(f"could not parse comments JSON: {exc}")
        return 1
    if not isinstance(comments, list):
        print("comments payload was not a JSON array")
        return 1
    allowed = {value.strip() for value in os.environ.get("ACAI_INDEPENDENT_REVIEW_GITHUB_LOGINS", "").split(",") if value.strip()}
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    passed, reason = evaluate_pr(comments, head_sha, is_draft=is_draft, reviewer_logins=allowed, repository=repository)
    print(reason)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
