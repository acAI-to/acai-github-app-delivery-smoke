#!/usr/bin/env python3
"""Versioned, fail-closed provenance for trusted-default governance releases.

The attestation is deliberately a canonical JSON document in a bot-authored
issue comment.  GitHub Actions is the issuer; immutable git object ids and
fresh GitHub API reads provide the transport integrity, not a home-grown key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import plan_approval

MARKER = "<!-- ACAI-GOVERNANCE-RELEASE -->"
DEPLOYMENT_INVOCATION_MARKER = (
    "<!-- ACAI-GOVERNANCE-DEPLOYMENT-INVOCATION -->"
)
SCHEMA = "acai-governance-release/v2"
DEPLOYMENT_INVOCATION_SCHEMA = "acai-governance-deployment-invocation/v2"
MANIFEST_PATH = ".acai/governance-bootstrap-manifest.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def manifest_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_historical_closure_variants(manifest: dict[str, Any]) -> list[str]:
    """Validate optional complete V3 closure overlays in an attested V4 manifest."""
    if not isinstance(manifest, dict) or manifest.get("manifest_version", manifest.get("version")) != 4:
        return []
    settings = manifest.get("settings") if isinstance(manifest, dict) else None
    migration = settings.get("v3_migration") if isinstance(settings, dict) else None
    histories = migration.get("historical_manifests") if isinstance(migration, dict) else None
    if not isinstance(histories, list) or not histories:
        return ["release manifest historical closure records are missing or malformed"]
    carriers: set[str] = set()
    for item in histories:
        if not isinstance(item, dict) or set(item) not in (
            {"source_commit", "manifest_sha256"},
            {"source_commit", "manifest_sha256", "variants"},
        ):
            return ["release manifest historical closure records are missing or malformed"]
        carrier, digest, variants = item.get("source_commit"), item.get("manifest_sha256"), item.get("variants", [])
        if (
            not isinstance(carrier, str) or not SHA.fullmatch(carrier) or carrier in carriers
            or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            or not isinstance(variants, list) or ("variants" in item and not variants)
        ):
            return ["release manifest historical closure records are missing or malformed"]
        carriers.add(carrier)
        paths: set[str] = set()
        for override in variants:
            if not isinstance(override, dict) or set(override) != {"path", "mode", "sha256"}:
                return ["release manifest historical closure variants are malformed"]
            path, mode, sha = override.get("path"), override.get("mode"), override.get("sha256")
            if (
                not isinstance(path, str) or not path or path in paths
                or not isinstance(mode, str) or mode not in {"100644", "100755"}
                or not isinstance(sha, str) or not DIGEST.fullmatch(sha)
            ):
                return ["release manifest historical closure variants are malformed"]
            paths.add(path)
    return []


def render(payload: dict[str, Any]) -> str:
    return f"{MARKER}\n{canonical(payload)}\n"


def parse(body: str) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(body, str) or MARKER not in body:
        return None, ["governance release marker is missing"]
    remainder = body.split(MARKER, 1)[1].strip()
    try:
        decoder = json.JSONDecoder()
        payload, offset = decoder.raw_decode(remainder)
    except (ValueError, TypeError) as exc:
        return None, [f"governance release attestation JSON is malformed: {exc}"]
    if remainder[offset:].strip() or not isinstance(payload, dict) or canonical(payload) != remainder:
        return None, ["governance release attestation is not canonical JSON"]
    return payload, []


def _comment(comments: list[dict[str, Any]], identifier: Any, url: Any) -> dict[str, Any] | None:
    matches = [c for c in comments if isinstance(c, dict) and str(c.get("id", "")) == str(identifier) and c.get("html_url", c.get("url")) == url]
    return matches[0] if len(matches) == 1 else None


def _unedited(comment: dict[str, Any] | None, *, bot: bool = False) -> bool:
    if not comment or comment.get("created_at") != comment.get("updated_at", comment.get("created_at")):
        return False
    login = str((comment.get("user") or {}).get("login", ""))
    return not bot or login in {"github-actions", "github-actions[bot]"}


def _payload_attestation(comment: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    payload, reasons = parse(str(comment.get("body", "")))
    if not _unedited(comment, bot=True):
        reasons.append("release attestation is edited or not authored by GitHub Actions")
    return payload, reasons


def _tree_manifest(manifest: dict[str, Any], tree: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    wanted = {str(e.get("path")): e for e in manifest.get("files", []) if isinstance(e, dict) and e.get("path")}
    actual = {str(e.get("path")): e for e in tree if isinstance(e, dict) and e.get("path")}
    if not wanted or set(wanted) != set(actual):
        return ["attested tree paths do not exactly match the commit-pinned manifest"]
    for path, entry in wanted.items():
        item = actual[path]
        if item.get("deleted") is not False or item.get("type") != "blob" or item.get("mode") != entry.get("mode") or item.get("sha256") != entry.get("sha256"):
            reasons.append(f"attested tree mode/type/hash/deletion mismatch: {path}")
    return reasons


def _deployment_invocation(
    comments: list[dict[str, Any]],
    *,
    source_release: dict[str, Any],
    source_manifest: dict[str, Any],
    target_repository: str,
    target_pr: int,
    target_head: str,
    target_base: str,
    target_body: str,
    target_state_digest: str,
    target_diff_digest: str,
    target_settings_digest: str,
    target_old_closure_digest: str = "",
    target_new_closure_digest: str = "",
) -> tuple[dict[str, Any] | None, list[str]]:
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    manifest = (
        source_release.get("manifest")
        if isinstance(source_release.get("manifest"), dict)
        else {}
    )
    approval = (
        source_release.get("operator_approval")
        if isinstance(source_release.get("operator_approval"), dict)
        else {}
    )
    operator_actor = str(approval.get("actor", ""))
    expected = {
        "target_repository": target_repository,
        "target_pr": target_pr,
        "target_head": target_head,
        "target_base": target_base,
        "source_repository": source_release.get("repository"),
        "source_pr": source_release.get("pr"),
        "source_merge_sha": source_release.get("merge_commit"),
        "manifest_sha256": manifest.get("sha256"),
        # This is the release-pin carrier commit, not the manifest's asset
        # commit.  Assets are fetched from ``source_manifest.source_commit``.
        "manifest_source_commit": manifest.get("commit"),
        "operator_actor": operator_actor,
    }
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        body = str(comment.get("body", ""))
        if DEPLOYMENT_INVOCATION_MARKER not in body:
            continue
        try:
            payload = json.loads(body.split(DEPLOYMENT_INVOCATION_MARKER, 1)[1].strip())
        except ValueError:
            continue
        if isinstance(payload, dict):
            candidates.append((payload, comment))
    if len(candidates) != 1:
        return None, ["deployment invocation is missing, duplicate, legacy, or stale"]
    invocation, comment = candidates[0]
    if not all(invocation.get(name) == value for name, value in expected.items()):
        return None, ["deployment invocation is missing, duplicate, legacy, or stale"]
    invocation_text = str(comment.get("body", "")).split(
        DEPLOYMENT_INVOCATION_MARKER, 1
    )[1].strip()
    if invocation_text != canonical(invocation):
        return None, ["deployment invocation is not canonical JSON"]
    required_fields = {
        "schema",
        "target_repository",
        "target_pr",
        "target_head",
        "target_base",
        "source_repository",
        "source_pr",
        "source_merge_sha",
        "manifest_sha256",
        "manifest_source_commit",
        "operator_actor",
        "old_closure_digest",
        "new_closure_digest",
        "body_digest",
        "state_digest",
        "diff_digest",
        "settings_digest",
        "digest",
    }
    if (
        frozenset(invocation) != frozenset(required_fields)
        or not all(
            re.fullmatch(r"[0-9a-f]{64}", str(invocation.get(field, "")))
            for field in ("old_closure_digest", "new_closure_digest", "body_digest", "state_digest", "diff_digest", "settings_digest")
        )
    ):
        return None, [
            "deployment invocation fields are missing, unknown, or malformed"
        ]
    if invocation.get("schema") != DEPLOYMENT_INVOCATION_SCHEMA:
        return None, ["deployment invocation is missing, duplicate, legacy, or stale"]
    if (
        invocation["state_digest"] != target_state_digest
        or invocation["diff_digest"] != target_diff_digest
        or invocation["settings_digest"] != target_settings_digest
        or invocation["old_closure_digest"] != target_old_closure_digest
        or invocation["new_closure_digest"] != target_new_closure_digest
    ):
        return None, ["target state, diff, or settings digest is missing or stale"]
    comment_actor = str((comment.get("user") or {}).get("login", ""))
    if (
        comment.get("created_at") != comment.get(
            "updated_at", comment.get("created_at")
        )
        or comment_actor.casefold() != operator_actor.casefold()
    ):
        return None, [
            "deployment invocation is edited or not authored by the source operator"
        ]
    digest = str(invocation.get("digest", ""))
    unsigned = dict(invocation)
    unsigned.pop("digest", None)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", digest)
        or hashlib.sha256(canonical(unsigned).encode()).hexdigest() != digest
    ):
        return None, ["deployment invocation digest is malformed or mismatched"]
    if (
        hashlib.sha256(target_body.encode()).hexdigest() != invocation["body_digest"]
        or not re.search(r"(?m)^skip-checks:\s*true\s*$", target_body)
    ):
        return None, ["target body or skip-checks provenance is missing or stale"]
    return invocation, []


def _approval_reasons(payload: dict[str, Any], issue: dict[str, Any], comments: list[dict[str, Any]], timeline: list[dict[str, Any]], repository: str) -> list[str]:
    approval = payload.get("operator_approval") if isinstance(payload.get("operator_approval"), dict) else {}
    terra = payload.get("terra_review") if isinstance(payload.get("terra_review"), dict) else {}
    reasons: list[str] = []
    comment = _comment(comments, approval.get("comment_id"), approval.get("url"))
    if not _unedited(comment, bot=True):
        reasons.append("current operator digest attestation is missing, edited, or untrusted")
    elif comment:
        fields, parse_reasons = plan_approval.parse_attestation(comment)
        reasons.extend(parse_reasons)
        if fields.get("Digest-SHA256") != approval.get("digest_sha256") or fields.get("Actor") != approval.get("actor"):
            reasons.append("current operator digest does not match release attestation")
    # The release workflow has already applied its repository allowlist.  On a
    # target, bind the same freshly fetched label event and digest rather than
    # trusting copied prose or a stale comment.
    actor = str(approval.get("actor", ""))
    reasons.extend(plan_approval.validate_approval(repository=repository, issue=issue, comments=comments, timeline=timeline, allowlist={actor} if actor else set()))
    review = _comment(comments, terra.get("comment_id"), terra.get("url"))
    if not _unedited(review):
        reasons.append("current Terra plan review is missing or edited")
    elif review:
        digest = plan_approval.plan_review_digest(str(issue.get("body", "")))
        # The trusted release workflow already checked the repository's Terra
        # allowlist before binding this immutable comment.  Target-side
        # verification must bind that exact unedited comment and its declared
        # reviewer, rather than treating the semantic reviewer field as a
        # GitHub-login allowlist entry.
        reviewer = str(terra.get("reviewer", ""))
        author = str((review.get("user") or {}).get("login", ""))
        reasons.extend(plan_approval.validate_plan_review(repository=repository, issue=issue, comment=review, allowlist={author} if author else set()))
        fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in str(review.get("body", "")).splitlines() if ":" in line}
        if fields.get("Reviewer") != reviewer:
            reasons.append("current Terra plan review reviewer does not match release attestation")
        if fields.get("Digest-SHA256") != digest or fields.get("Digest-SHA256") != terra.get("digest_sha256"):
            reasons.append("current Terra plan review digest does not match release attestation")
    return list(dict.fromkeys(reasons))


def validate_release_attestation(attestation: dict[str, Any], source_pr: dict[str, Any], *, repository: str, manifest: Path | None = None, default_branch: str = "main", diff_paths: list[str] | None = None, file_details: dict[str, Any] | None = None, issue: dict[str, Any] | None = None, comments: list[dict[str, Any]] | None = None, timeline: list[dict[str, Any]] | None = None, run: dict[str, Any] | None = None, source_manifest_bytes: bytes | None = None, source_tree: list[dict[str, Any]] | None = None, default_contained: bool | None = None, associated_prs: list[dict[str, Any]] | None = None, deployment_comments: list[dict[str, Any]] | None = None, target_repository: str = "", target_pr: int = 0, target_head: str = "", target_base: str = "", target_body: str = "", target_state_digest: str = "", target_diff_digest: str = "", target_settings_digest: str = "", target_old_closure_digest: str = "", target_new_closure_digest: str = "", target_old_closure: dict[str, dict[str, str]] | None = None) -> list[str]:
    """Validate a v2 comment and independently collected source API facts."""
    raw = attestation if isinstance(attestation, dict) else {}
    payload, reasons = _payload_attestation(raw)
    if not payload:
        return list(dict.fromkeys(reasons))
    required = {"schema", "repository", "issue", "pr", "approved_head", "merge_commit", "default_branch", "operator_approval", "terra_review", "trusted_workflow", "manifest", "tree"}
    if set(payload) != required or payload.get("schema") != SCHEMA:
        reasons.append("release attestation schema is missing, unknown, or has extra fields")
        return list(dict.fromkeys(reasons))
    if payload.get("repository") != repository or payload.get("default_branch") != default_branch:
        reasons.append("release repository/default branch does not match")
    if not isinstance(payload.get("issue"), int) or not isinstance(payload.get("pr"), int) or not SHA.fullmatch(str(payload.get("approved_head", ""))) or not SHA.fullmatch(str(payload.get("merge_commit", ""))):
        reasons.append("release issue/PR/commit identifiers are malformed")
    merge = source_pr.get("merge_commit_sha") or (source_pr.get("mergeCommit") or {}).get("oid")
    head = (source_pr.get("head") or {}).get("sha") or source_pr.get("headRefOid")
    base = (source_pr.get("base") or {}).get("ref") or source_pr.get("baseRefName")
    if not (source_pr.get("merged") is True or source_pr.get("merged_at")) or base != default_branch or head != payload.get("approved_head") or merge != payload.get("merge_commit"):
        reasons.append("source PR did not merge the approved head into the recorded default branch")
    if default_contained is not True or not isinstance(associated_prs, list) or not any(int(p.get("number", -1)) == payload.get("pr") for p in associated_prs if isinstance(p, dict)):
        reasons.append("source default containment or direct-push exclusion is unavailable")
    workflow = payload.get("trusted_workflow") if isinstance(payload.get("trusted_workflow"), dict) else {}
    if set(workflow) != {"run_id", "url", "event", "ref", "sha", "actor", "workflow_path"} or not isinstance(workflow.get("run_id"), int) or workflow.get("event") != "workflow_dispatch" or workflow.get("ref") != default_branch or not SHA.fullmatch(str(workflow.get("sha", ""))) or workflow.get("workflow_path") != ".github/workflows/governance-release-attestation.yml" or not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/actions/runs/\d+", str(workflow.get("url", ""))):
        reasons.append("trusted workflow identity is malformed")
    run = run if isinstance(run, dict) else raw.get("run") if isinstance(raw.get("run"), dict) else {}
    actor = (run.get("actor") or {}).get("login") or run.get("actor")
    if run.get("id") != workflow.get("run_id") or run.get("html_url") != workflow.get("url") or run.get("event") != workflow.get("event") or run.get("head_branch") != workflow.get("ref") or run.get("head_sha") != workflow.get("sha") or actor != workflow.get("actor") or run.get("conclusion") != "success" or str(run.get("path", "")).split("@", 1)[0] != workflow.get("workflow_path"):
        reasons.append("trusted workflow run is unavailable, edited, or mismatched")
    manifest_info = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
    required_manifest = {"commit", "path", "sha256", "bytes_base64"}
    if set(manifest_info) != required_manifest or not SHA.fullmatch(str(manifest_info.get("commit", ""))) or manifest_info.get("path") != MANIFEST_PATH:
        reasons.append("commit-pinned manifest identity is malformed")
    try:
        manifest_bytes = base64.b64decode(str(manifest_info.get("bytes_base64", "")), validate=True)
        parsed_manifest = json.loads(manifest_bytes)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        manifest_bytes, parsed_manifest = b"", {}
        reasons.append("commit-pinned manifest bytes are malformed")
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_info.get("sha256") or (source_manifest_bytes is not None and source_manifest_bytes != manifest_bytes):
        reasons.append("commit-pinned manifest bytes/SHA do not match source API evidence")
    if manifest is not None and manifest.exists() and manifest_sha(manifest) != manifest_info.get("sha256"):
        reasons.append("target manifest bytes/SHA do not match attested source manifest")
    tree = payload.get("tree") if isinstance(payload.get("tree"), list) else []
    reasons.extend(validate_historical_closure_variants(parsed_manifest if isinstance(parsed_manifest, dict) else {}))
    reasons.extend(_tree_manifest(parsed_manifest if isinstance(parsed_manifest, dict) else {}, tree))
    if source_tree is not None and canonical(sorted(source_tree, key=lambda item: str(item.get("path", "")))) != canonical(sorted(tree, key=lambda item: str(item.get("path", "")))):
        reasons.append("source commit tree does not match attested tree")
    if deployment_comments is not None:
        _, invocation_reasons = _deployment_invocation(
            deployment_comments,
            source_release=payload,
            source_manifest=parsed_manifest if isinstance(parsed_manifest, dict) else {},
            target_repository=target_repository,
            target_pr=target_pr,
            target_head=target_head,
            target_base=target_base,
            target_body=target_body,
            target_state_digest=target_state_digest,
            target_diff_digest=target_diff_digest,
            target_settings_digest=target_settings_digest,
            target_old_closure_digest=target_old_closure_digest,
            target_new_closure_digest=target_new_closure_digest,
        )
        reasons.extend(invocation_reasons)
    if diff_paths is not None:
        reasons.extend(validate_manifest_only_diff(
            diff_paths,
            parsed_manifest if isinstance(parsed_manifest, dict) else {},
            file_details=file_details,
            old_closure=target_old_closure,
            bootstrap_state_sha256=target_state_digest or None,
        ))
    if issue is not None and comments is not None and timeline is not None:
        if issue.get("number") != payload.get("issue"):
            reasons.append("source issue does not match release attestation")
        else:
            reasons.extend(_approval_reasons(payload, issue, comments, timeline, repository))
    return list(dict.fromkeys(reasons))


def validate_manifest_only_diff(
    diff_paths: list[str], manifest: dict[str, Any], *, file_details: dict[str, Any] | None = None,
    old_closure: dict[str, dict[str, str]] | None = None,
    bootstrap_state_sha256: str | None = None,
) -> list[str]:
    entries = {str(e.get("path")): e for e in manifest.get("files", []) if isinstance(e, dict) and e.get("path")}
    actual = set(diff_paths)
    reasons: list[str] = []
    bootstrap_state = ".acai/governance-bootstrap.json"
    old = old_closure if isinstance(old_closure, dict) else {}
    extras = actual - set(entries) - set(old) - {bootstrap_state}
    if not entries:
        reasons.append("target propagation manifest is empty")
    if extras:
        reasons.append("target propagation has paths outside the governed closure")
    if not isinstance(file_details, dict):
        return reasons + ["target propagation file details are unavailable"]
    for path, entry in entries.items():
        detail = file_details.get(path)
        if not isinstance(detail, dict) or detail.get("status") == "D" or detail.get("deleted") is not False or detail.get("type") != "blob" or detail.get("mode") != entry.get("mode") or detail.get("sha256") != entry.get("sha256"):
            reasons.append(f"manifest asset mode/type/hash/deletion mismatch: {path}")
        if old and old.get(path) != {"mode": entry.get("mode"), "sha256": entry.get("sha256")} and path not in actual:
            reasons.append(f"changed manifest asset is absent from target propagation diff: {path}")
    if old_closure is not None:
        for path, entry in old.items():
            if path in entries:
                continue
            detail = file_details.get(path)
            if path not in actual or not isinstance(detail, dict) or detail.get("status") != "D" or detail.get("deleted") is not True or detail.get("mode") != entry.get("mode") or detail.get("sha256") != entry.get("sha256"):
                reasons.append(f"retired attested closure deletion mismatch: {path}")
        bootstrap = file_details.get(bootstrap_state)
        if bootstrap_state not in actual or not isinstance(bootstrap, dict) or bootstrap.get("deleted") is not False or bootstrap.get("type") != "blob" or bootstrap.get("mode") != "100644" or (bootstrap_state_sha256 is not None and bootstrap.get("sha256") != bootstrap_state_sha256):
            reasons.append("target bootstrap state is absent, deleted, or mismatched")
    return list(dict.fromkeys(reasons))


def build_release_payload(data: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Build a v2 payload in the trusted workflow after validating fresh APIs."""
    repository, default_branch = str(data.get("repository", "")), str(data.get("default_branch", ""))
    pr = data.get("source_pr") if isinstance(data.get("source_pr"), dict) else {}
    issue = data.get("issue") if isinstance(data.get("issue"), dict) else {}
    comments = data.get("comments") if isinstance(data.get("comments"), list) else []
    timeline = data.get("timeline") if isinstance(data.get("timeline"), list) else []
    run = data.get("run") if isinstance(data.get("run"), dict) else {}
    manifest_path = Path(str(data.get("manifest_path", "")))
    tree = data.get("tree") if isinstance(data.get("tree"), list) else []
    manifest_carrier = str(data.get("manifest_carrier", ""))
    manifest_asset_commit = str(data.get("manifest_asset_commit", ""))
    expected_manifest_sha256 = str(data.get("expected_manifest_sha256", ""))
    reasons: list[str] = []
    issue_number = issue.get("number")
    if not repository or not default_branch or not isinstance(issue_number, int) or not manifest_path.is_file():
        return None, ["trusted release workflow inputs are incomplete"]
    head = (pr.get("head") or {}).get("sha") or pr.get("headRefOid")
    merge = pr.get("merge_commit_sha") or (pr.get("mergeCommit") or {}).get("oid")
    base = (pr.get("base") or {}).get("ref") or pr.get("baseRefName")
    if not (pr.get("merged") is True or pr.get("merged_at")) or base != default_branch or not SHA.fullmatch(str(head)) or not SHA.fullmatch(str(merge)):
        reasons.append("trusted release requires a merged default-branch PR with immutable SHAs")
    if not re.search(r"(?im)^\s*(?:Tier|Declared tier)\s*:\s*(?:governance/tier-)?2\s*$", str(pr.get("body", ""))):
        reasons.append("trusted release dispatch is limited to Tier 2 source PRs")
    # ``source_contained`` and ``associated_prs`` deliberately describe the
    # *manifest carrier*, not the PR merge commit.  A release can be pinned by
    # a follow-up carrier commit while retaining the original PR merge as its
    # provenance; accepting the merge facts here would otherwise make every
    # propagated deployment fail its carrier check downstream.
    associated = data.get("associated_prs") if isinstance(data.get("associated_prs"), list) else []
    if data.get("source_contained") is not True or not any(int(item.get("number", -1)) == pr.get("number") for item in associated if isinstance(item, dict)):
        reasons.append("manifest carrier is not contained in the trusted dispatch ref or is direct-push ambiguous")
    if not SHA.fullmatch(manifest_carrier):
        reasons.append("manifest carrier commit is malformed")
    if not SHA.fullmatch(manifest_asset_commit):
        reasons.append("manifest asset commit is malformed")
    content = manifest_path.read_bytes()
    try:
        parsed_manifest = json.loads(content)
    except (ValueError, UnicodeDecodeError):
        parsed_manifest = {}
        reasons.append("manifest carrier bytes are malformed")
    if hashlib.sha256(content).hexdigest() != expected_manifest_sha256:
        reasons.append("manifest carrier digest does not match the trusted release pin")
    if not isinstance(parsed_manifest, dict) or parsed_manifest.get("source_commit") != manifest_asset_commit:
        reasons.append("manifest asset commit does not match the carrier-pinned manifest")
    reasons.extend(validate_historical_closure_variants(parsed_manifest if isinstance(parsed_manifest, dict) else {}))
    if data.get("manifest_asset_contained") is not True:
        reasons.append("manifest asset commit is not contained in the manifest carrier history")
    operator_allow = {str(v) for v in data.get("operator_logins", []) if str(v)}
    terra_allow = {str(v) for v in data.get("terra_high_review_logins", []) if str(v)}
    reasons.extend(plan_approval.validate_approval(repository=repository, issue=issue, comments=comments, timeline=timeline, allowlist=operator_allow))
    review = max((c for c in comments if isinstance(c, dict) and "<!-- ACAI-TERRA-HIGH-PLAN-REVIEW -->" in str(c.get("body", ""))), key=lambda c: str(c.get("updated_at") or c.get("created_at") or ""), default=None)
    reasons.extend(plan_approval.validate_plan_review(repository=repository, issue=issue, comment=review, allowlist=terra_allow))
    approval = max((c for c in comments if isinstance(c, dict) and "<!-- ACAI-PLAN-APPROVAL -->" in str(c.get("body", ""))), key=lambda c: str(c.get("updated_at") or c.get("created_at") or ""), default=None)
    if not _unedited(approval, bot=True) or not _unedited(review):
        reasons.append("trusted release approval or Terra evidence is edited/unavailable")
    if reasons:
        return None, list(dict.fromkeys(reasons))
    approval_fields, _ = plan_approval.parse_attestation(approval)
    review_fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in str(review.get("body", "")).splitlines() if ":" in line}
    payload = {
        "schema": SCHEMA, "repository": repository, "issue": issue_number, "pr": pr.get("number"),
        "approved_head": head, "merge_commit": merge, "default_branch": default_branch,
        "operator_approval": {"comment_id": approval.get("id"), "url": approval.get("html_url", approval.get("url")), "digest_sha256": approval_fields.get("Digest-SHA256"), "actor": approval_fields.get("Actor")},
        "terra_review": {"comment_id": review.get("id"), "url": review.get("html_url", review.get("url")), "digest_sha256": review_fields.get("Digest-SHA256"), "reviewer": review_fields.get("Reviewer")},
        "trusted_workflow": {"run_id": run.get("id"), "url": run.get("html_url"), "event": run.get("event"), "ref": run.get("head_branch"), "sha": run.get("head_sha"), "actor": (run.get("actor") or {}).get("login"), "workflow_path": str(run.get("path", "")).split("@", 1)[0]},
        "manifest": {"commit": manifest_carrier, "path": MANIFEST_PATH, "sha256": hashlib.sha256(content).hexdigest(), "bytes_base64": base64.b64encode(content).decode("ascii")},
        "tree": tree,
    }
    # Validate the object we are about to publish: this catches malformed run
    # facts before a bot comment becomes transport evidence.
    return payload, []


def main() -> int:
    # Intentionally tiny CLI contract: target workflows feed one normalized
    # JSON object and consume only this deterministic eligibility document.
    try:
        data = json.load(sys.stdin)
        if len(sys.argv) > 1 and sys.argv[1] == "publish":
            payload, reasons = build_release_payload(data)
            if not reasons and payload:
                print(render(payload), end="")
                return 0
        else:
            reasons = validate_release_attestation(**data)
    except (TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        reasons = [f"malformed release provenance payload: {exc}"]
    print(canonical({"ok": not reasons, "reasons": reasons}))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
