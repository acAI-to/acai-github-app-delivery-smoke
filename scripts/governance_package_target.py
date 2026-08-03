#!/usr/bin/env python3
"""Fixed interface-v1 target verifier.

This is the only executable copied into target repositories.  The central
package evaluator is read-only; every target write remains after this verifier.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SHA = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTENT_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "acai-governance-package-target-trust/v1"
WORKFLOW = ".github/workflows/acai-governance-package-evaluator.yml"
MODES = frozenset({"evaluate", "approval", "status", "merge", "smoke"})
RELEASE_SCHEMA = "application/vnd.acai.governance.release.v1+json"
OCI_MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA = "application/vnd.acai.governance.config.v1+json"
ENVELOPE_MEDIA = "application/vnd.acai.governance.envelope.v1+json"
BUNDLE_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
ARTIFACT_TYPE = "application/vnd.acai.governance.package.v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def signer_subject(signer_sha: str) -> str:
    if not SHA.fullmatch(str(signer_sha)):
        raise ValueError("immutable signer SHA is malformed")
    return (
        "https://github.com/acAI-to/acai-harness/.github/workflows/"
        f"governance-package-signer.yml@{signer_sha}"
    )


def _descriptor(media_type: str, payload: bytes) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def build_oci_artifact(
    envelope: dict[str, Any], bundle: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, bytes]]:
    config_bytes = canonical_json({
        "artifactType": ARTIFACT_TYPE, "schema": "acai-governance-oci/v1",
    })
    envelope_bytes, bundle_bytes = canonical_json(envelope), canonical_json(bundle)
    config = _descriptor(CONFIG_MEDIA, config_bytes)
    layers = [
        _descriptor(ENVELOPE_MEDIA, envelope_bytes),
        _descriptor(BUNDLE_MEDIA, bundle_bytes),
    ]
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA,
        "artifactType": ARTIFACT_TYPE,
        "config": config,
        "layers": layers,
    }
    return manifest, {
        config["digest"]: config_bytes,
        layers[0]["digest"]: envelope_bytes,
        layers[1]["digest"]: bundle_bytes,
    }


def _canonical_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError(f"{label} is not UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical_json(value) != payload:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def validate_oci_artifact(
    manifest: Any, blobs: Any
) -> list[str]:
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schemaVersion", "mediaType", "artifactType", "config", "layers"
        }
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA
        or manifest.get("artifactType") != ARTIFACT_TYPE
        or not isinstance(manifest.get("layers"), list)
        or len(manifest["layers"]) != 2
    ):
        return ["OCI manifest media or cardinality is invalid"]
    descriptors = [manifest["config"], *manifest["layers"]]
    media = [CONFIG_MEDIA, ENVELOPE_MEDIA, BUNDLE_MEDIA]
    reasons: list[str] = []
    for item, expected_media in zip(descriptors, media):
        if (
            not isinstance(item, dict)
            or set(item) != {"mediaType", "digest", "size"}
            or item.get("mediaType") != expected_media
            or not OCI_DIGEST.fullmatch(str(item.get("digest", "")))
            or not isinstance(item.get("size"), int)
        ):
            reasons.append("OCI descriptor media, size, or digest is invalid")
            continue
        payload = blobs.get(item["digest"]) if isinstance(blobs, dict) else None
        if (
            not isinstance(payload, bytes)
            or len(payload) != item["size"]
            or "sha256:" + hashlib.sha256(payload).hexdigest() != item["digest"]
        ):
            reasons.append("OCI blob digest or size does not match descriptor")
    return list(dict.fromkeys(reasons))


def verify_public_release(
    client: Any,
    crypto: Any,
    *,
    tag: str,
    expected_signer_sha: str,
) -> dict[str, Any]:
    envelope, _ = resolve_public_release(
        client,
        crypto,
        tag=tag,
        expected_signer_sha=expected_signer_sha,
    )
    return envelope


def resolve_public_release(
    client: Any,
    crypto: Any,
    *,
    tag: str,
    expected_signer_sha: str,
) -> tuple[dict[str, Any], str]:
    if not re.fullmatch(r"release-[0-9a-f]{40}", str(tag)):
        raise ValueError("release discovery tag is malformed")
    digest = client.resolve_tag(tag, anonymous=True)
    if not OCI_DIGEST.fullmatch(str(digest)):
        raise ValueError("release tag did not resolve to one immutable digest")
    envelope = verify_public_release_digest(
        client,
        crypto,
        digest=digest,
        expected_signer_sha=expected_signer_sha,
    )
    if tag != "release-" + envelope["release_commit_sha"]:
        raise ValueError("release tag and signed release SHA are confused")
    return envelope, digest


def verify_public_release_digest(
    client: Any,
    crypto: Any,
    *,
    digest: str,
    expected_signer_sha: str,
) -> dict[str, Any]:
    identity = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": signer_subject(expected_signer_sha),
        "job_workflow_sha": expected_signer_sha,
    }
    if not OCI_DIGEST.fullmatch(str(digest)):
        raise ValueError("release manifest digest is malformed")
    manifest, blobs = client.pull_digest(digest, anonymous=True)
    reasons = validate_oci_artifact(manifest, blobs)
    if reasons:
        raise ValueError("; ".join(reasons))
    envelope_bytes = blobs[manifest["layers"][0]["digest"]]
    bundle_bytes = blobs[manifest["layers"][1]["digest"]]
    envelope = _canonical_object(envelope_bytes, "release envelope")
    bundle = _canonical_object(bundle_bytes, "Sigstore bundle")
    signer_identity = envelope.get("signer_identity")
    expected_identity = {
        "issuer": identity["issuer"],
        "subject": identity["subject"],
        "job_workflow_ref": (
            "acAI-to/acai-harness/.github/workflows/"
            f"governance-package-signer.yml@{expected_signer_sha}"
        ),
        "job_workflow_sha": expected_signer_sha,
        "caller_repository": "acAI-to/acai-harness",
    }
    if (
        envelope.get("schema") != RELEASE_SCHEMA
        or envelope.get("state") != "PUBLISHED"
        or not SHA.fullmatch(str(envelope.get("release_commit_sha", "")))
        or not CONTENT_DIGEST.fullmatch(
            str(envelope.get("package_content_digest", ""))
        )
        or not isinstance(signer_identity, dict)
        or any(
            signer_identity.get(name) != value
            for name, value in expected_identity.items()
        )
        or not str(signer_identity.get("caller_repository_id", "")).isdigit()
        or not str(signer_identity.get("run_id", "")).isdigit()
        or not str(signer_identity.get("run_attempt", "")).isdigit()
        or signer_identity.get("event_name") != "workflow_run"
        or signer_identity.get("ref") != "refs/heads/main"
        or bundle.get("mediaType") != BUNDLE_MEDIA
    ):
        raise ValueError("signed release envelope identity or schema is invalid")
    crypto.verify(envelope_bytes, bundle, identity)
    return envelope


class PublicRegistryClient:
    """Anonymous GHCR reader; bearer challenges never receive a credential."""

    def __init__(self, repository: str = "acai-to/acai-governance-package"):
        self.repository = repository
        self.base = f"https://ghcr.io/v2/{repository}"
        self.bearer = ""

    def _request(
        self, url: str, *, accept: str = "", allow_missing: bool = False
    ) -> Any:
        headers = {"Accept": accept} if accept else {}
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        try:
            return urlopen(Request(url, headers=headers), timeout=30)
        except HTTPError as exc:
            if exc.code == 404 and allow_missing:
                return None
            if exc.code != 401:
                raise
            challenge = str(exc.headers.get("WWW-Authenticate", ""))
            match = re.match(r'Bearer\s+realm="([^"]+)"(.*)', challenge)
            if not match:
                raise ValueError("public registry challenge is malformed") from exc
            realm, tail = match.groups()
            params = dict(re.findall(r',?\s*([a-z]+)="([^"]*)"', tail))
            query = urlencode({
                key: value for key, value in {
                    "service": params.get("service"),
                    "scope": params.get("scope")
                    or f"repository:{self.repository}:pull",
                }.items() if value
            })
            # This token exchange is anonymous: no Basic token or repository
            # credential is ever attached.
            with urlopen(Request(f"{realm}?{query}"), timeout=30) as response:
                token = json.load(response)
            self.bearer = token.get("token") or token.get("access_token") or ""
            if not self.bearer:
                raise ValueError("public registry token is missing")
            headers["Authorization"] = "Bearer " + self.bearer
            return urlopen(Request(url, headers=headers), timeout=30)

    def resolve_tag(self, tag: str, *, anonymous: bool) -> str:
        if not anonymous:
            raise ValueError("target registry discovery must be anonymous")
        response = self._request(
            f"{self.base}/manifests/{tag}",
            accept=OCI_MANIFEST_MEDIA,
        )
        payload = response.read()
        digest = response.headers.get("Docker-Content-Digest", "")
        if (
            not OCI_DIGEST.fullmatch(digest)
            or "sha256:" + hashlib.sha256(payload).hexdigest() != digest
        ):
            raise ValueError("registry discovery digest is missing or false")
        return digest

    def pull_digest(
        self, digest: str, *, anonymous: bool
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        if not anonymous or not OCI_DIGEST.fullmatch(str(digest)):
            raise ValueError("target OCI pull must be anonymous and digest-addressed")
        response = self._request(
            f"{self.base}/manifests/{digest}",
            accept=OCI_MANIFEST_MEDIA,
        )
        manifest_bytes = response.read()
        if (
            response.headers.get("Docker-Content-Digest") != digest
            or "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != digest
        ):
            raise ValueError("digest-addressed manifest changed")
        manifest = _canonical_object(manifest_bytes, "OCI manifest")
        blobs: dict[str, bytes] = {}
        for descriptor in [manifest.get("config"), *manifest.get("layers", [])]:
            value = descriptor.get("digest") if isinstance(descriptor, dict) else ""
            if not OCI_DIGEST.fullmatch(str(value)):
                raise ValueError("OCI descriptor digest is invalid")
            blobs[value] = self._request(f"{self.base}/blobs/{value}").read()
        return manifest, blobs


class CosignVerifier:
    def __init__(self, trusted_root: str = ""):
        self.trusted_root = trusted_root

    def verify(
        self, payload: bytes, bundle: dict[str, Any], identity: dict[str, str]
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "release.json"
            bundle_path = Path(directory) / "bundle.json"
            source.write_bytes(payload)
            bundle_path.write_bytes(canonical_json(bundle))
            command = [
                "cosign", "verify-blob", "--bundle", str(bundle_path),
                "--certificate-oidc-issuer", identity["issuer"],
                "--certificate-identity", identity["subject"],
            ]
            if self.trusted_root:
                command += ["--trusted-root", self.trusted_root]
            command.append(str(source))
            result = subprocess.run(
                command, text=True, capture_output=True, check=False
            )
        if result.returncode:
            raise ValueError("Sigstore/Fulcio/Rekor verification failed")


def validate_trust(value: Any, *, mode: str, fork: bool) -> list[str]:
    legacy_fields = {
        "schema", "source_repository", "workflow_path",
        "workflow_ref", "release_commit_sha", "interface",
    }
    signed_fields = legacy_fields | {
        "oci_manifest_digest", "signer_sha", "package_content_digest",
    }
    if (
        not isinstance(value, dict)
        or frozenset(value) not in {
            frozenset(legacy_fields), frozenset(signed_fields)
        }
        or value.get("schema") != SCHEMA
        or not re.fullmatch(r"[^/]+/[^/]+", str(value.get("source_repository", "")))
        or value.get("workflow_path") != WORKFLOW
        or (
            value.get("workflow_ref") != "stable"
            and value.get("workflow_ref") != value.get("release_commit_sha")
        )
        or not SHA.fullmatch(str(value.get("release_commit_sha", "")))
        or value.get("interface") != "v1"
    ):
        return ["target trust document is unknown or malformed"]
    reasons: list[str] = []
    if set(value) == signed_fields and (
        not OCI_DIGEST.fullmatch(str(value.get("oci_manifest_digest", "")))
        or not SHA.fullmatch(str(value.get("signer_sha", "")))
        or not CONTENT_DIGEST.fullmatch(
            str(value.get("package_content_digest", ""))
        )
    ):
        reasons.append("signed target trust digests are malformed")
    if mode not in MODES:
        reasons.append("caller mode is unknown or unsupported")
    if fork is not False:
        reasons.append("fork pull requests are forbidden")
    return reasons


def validate_run(trust: dict[str, Any], run: Any, *, run_id: int) -> list[str]:
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("event") not in {"pull_request", "issue_comment", "workflow_dispatch"}
    ):
        return ["current caller run identity is missing or stale"]
    expected = (
        f"{trust['source_repository']}/{trust['workflow_path']}@{trust['workflow_ref']}"
    )
    references = run.get("referenced_workflows")
    matches = [
        item for item in references
        if isinstance(item, dict) and item.get("path") == expected
    ] if isinstance(references, list) else []
    if len(matches) != 1:
        return ["GitHub referenced workflow evidence is missing or ambiguous"]
    if matches[0].get("sha") != trust["release_commit_sha"]:
        return ["GitHub referenced workflow SHA is not the exact attested release"]
    return []


def validate_post(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["target evidence is malformed"]
    trust = data.get("trust")
    reasons = validate_trust(
        trust, mode=data.get("mode"), fork=data.get("fork")
    )
    if reasons:
        return reasons
    try:
        run_id = int(data.get("run_id"))
    except (TypeError, ValueError):
        return ["run id is malformed"]
    return validate_run(trust, data.get("run"), run_id=run_id)


def main() -> int:
    commands = {"target-pre", "target-post", "resolve-release", "verify-release"}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(
            "usage: governance_package_target.py "
            "target-pre|target-post|resolve-release|verify-release",
            file=sys.stderr,
        )
        return 2
    try:
        data = json.load(sys.stdin)
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"target evidence is invalid JSON: {exc}", file=sys.stderr)
        return 1
    if sys.argv[1] in {"resolve-release", "verify-release"}:
        try:
            signer_sha = str(data.get("expected_signer_sha", ""))
            client = PublicRegistryClient()
            crypto = CosignVerifier(
                os.environ.get("ACAI_SIGSTORE_TRUSTED_ROOT", "")
            )
            if sys.argv[1] == "resolve-release":
                tag = str(data.get("tag", ""))
                envelope, digest = resolve_public_release(
                    client, crypto, tag=tag, expected_signer_sha=signer_sha,
                )
            else:
                digest = str(data.get("oci_manifest_digest", ""))
                envelope = verify_public_release_digest(
                    client,
                    crypto,
                    digest=digest,
                    expected_signer_sha=signer_sha,
                )
            trust = {
                "schema": SCHEMA,
                "source_repository": "acAI-to/acai-harness",
                "workflow_path": WORKFLOW,
                "workflow_ref": "stable",
                "release_commit_sha": envelope["release_commit_sha"],
                "interface": "v1",
                "oci_manifest_digest": digest,
                "signer_sha": signer_sha,
                "package_content_digest": envelope["package_content_digest"],
            }
            print(canonical_json({"trust": trust}).decode("utf-8"))
            return 0
        except (HTTPError, OSError, RuntimeError, ValueError) as exc:
            print(f"signed release rejected: {exc}", file=sys.stderr)
            return 1
    reasons = (
        validate_post(data)
        if sys.argv[1] == "target-post"
        else validate_trust(
            data.get("trust"), mode=data.get("mode"), fork=data.get("fork")
        ) if isinstance(data, dict) else ["target evidence is malformed"]
    )
    trust = data.get("trust") if isinstance(data, dict) else None
    if (
        not reasons
        and sys.argv[1] == "target-post"
        and isinstance(trust, dict)
        and "oci_manifest_digest" in trust
    ):
        try:
            envelope = verify_public_release_digest(
                PublicRegistryClient(),
                CosignVerifier(
                    os.environ.get("ACAI_SIGSTORE_TRUSTED_ROOT", "")
                ),
                digest=trust["oci_manifest_digest"],
                expected_signer_sha=trust["signer_sha"],
            )
            if (
                envelope["release_commit_sha"] != trust["release_commit_sha"]
                or envelope["package_content_digest"]
                != trust["package_content_digest"]
            ):
                reasons.append("post-write release evidence changed")
        except (HTTPError, OSError, RuntimeError, ValueError) as exc:
            reasons.append(f"post-write signed release verification failed: {exc}")
    if reasons:
        print("; ".join(reasons), file=sys.stderr)
        return 1
    print(json.dumps({"result": "eligible" if sys.argv[1] == "target-pre" else "verified"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
