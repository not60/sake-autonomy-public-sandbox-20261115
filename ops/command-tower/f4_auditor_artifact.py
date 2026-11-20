"""Build a signed Cycle 1 Auditor envelope from independently verified evidence."""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

from f4_cycle_control import (
    AUDIT_WORKFLOW_PATH, CycleControlHold, _validate_audit_payload,
    _verify_revocation_status, build_cycle1_auditor_artifact,
)
from f4_go_gate import F4GoHold, verify_f4_go_candidate, verified_f4_go_sha256
from trusted_key_registry import TrustedVerificationKey, load_trusted_verification_keys
from f4_limited_delegation import verify_auditor_candidate_authorization


def verify_limited_delegation(*, delegation_envelope, trusted_owner_keys,
                              expected_execution_revision, expected_cycle_tasks,
                              revocation_status, verify_revocation_status,
                              authorization, evidence, verify_candidate_evidence,
                              now=None) -> str:
    """Auditor-side entry point; caller supplies an independent read-only verifier."""
    return verify_auditor_candidate_authorization(
        delegation_envelope=delegation_envelope,
        trusted_owner_keys=trusted_owner_keys,
        expected_execution_revision=expected_execution_revision,
        expected_cycle_tasks=expected_cycle_tasks, revocation_status=revocation_status,
        verify_revocation_status=verify_revocation_status,
        authorization=authorization, evidence=evidence,
        verify_candidate_evidence=verify_candidate_evidence, now=now,
    )


def _read_json(path: str | Path) -> object:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("input_file_missing_or_unsafe")
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("input_json_invalid") from None


def build_payload(*, evidence: object, candidate: object, workspace: str | Path,
                  expected_base_sha: str, trusted_keys: object,
                  auditor_key_document: object, revocation_envelope: object,
                  workflow_run_id: str, run_attempt: int, source_commit_sha: str,
                  now: datetime | None = None) -> tuple[dict[str, object], str]:
    owner_keys = load_trusted_verification_keys(trusted_keys)
    if (not isinstance(auditor_key_document, dict)
            or set(auditor_key_document) != {"key_id", "role", "public_key"}
            or auditor_key_document.get("role") != "auditor"
            or not isinstance(auditor_key_document.get("key_id"), str)
            or not auditor_key_document["key_id"]
            or not isinstance(auditor_key_document.get("public_key"), str)):
        raise ValueError("auditor_trust_key_invalid")
    try:
        auditor_public = base64.b64decode(auditor_key_document["public_key"], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("auditor_trust_key_encoding_invalid") from None
    if (len(auditor_public) != 32 or auditor_key_document["key_id"] in owner_keys
            or auditor_public in {key.public_key for key in owner_keys.values()}):
        raise ValueError("auditor_key_not_independent")
    auditor_key = TrustedVerificationKey(auditor_key_document["key_id"], "auditor", auditor_public)

    if not isinstance(revocation_envelope, dict) or not isinstance(revocation_envelope.get("payload"), dict):
        raise ValueError("signed_revocation_status_missing")
    status_payload = revocation_envelope["payload"]
    simple_status = {key: status_payload.get(key) for key in ("approval_id", "sequence", "status")}
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("clock_untrusted")
    instant = instant.astimezone(timezone.utc)
    try:
        go = verify_f4_go_candidate(
            candidate=candidate, workspace=workspace,
            expected_repository_id=1458303357, expected_base_sha=expected_base_sha,
            trusted_keys=owner_keys, revocation_status=simple_status,
            verify_revocation_status=lambda value: value == simple_status,
            now=instant,
        )
        go_sha = verified_f4_go_sha256(candidate, go)
        _verify_revocation_status(
            revocation_envelope, go=go, go_sha256=go_sha,
            trusted_keys=owner_keys, now=instant,
        )
    except F4GoHold as exc:
        raise ValueError(exc.reason) from None
    except CycleControlHold as exc:
        raise ValueError(exc.reason) from None
    except (TypeError, ValueError) as exc:
        raise ValueError("signed_go_or_revocation_invalid:" + type(exc).__name__) from None

    if not isinstance(evidence, dict) or set(evidence) != {
        "schema", "repository_id", "base_sha", "worker_run_id", "candidate_digest",
        "permit_id", "witness_digest", "journal_revision", "journal_head_sha256",
        "pr_number", "pr_state", "pr_is_draft", "pr_merged", "pr_head_sha",
        "pr_base_sha", "readonly_ci_run_id", "readonly_ci_conclusion",
    }:
        raise ValueError("auditor_evidence_fields_invalid")
    expiry = min(instant + timedelta(minutes=10), go.expires_at)
    if expiry <= instant:
        raise ValueError("go_expired_before_auditor_signing")
    if (evidence.get("schema") != 1 or evidence.get("repository_id") != 1458303357
            or evidence.get("base_sha") != go.base_sha
            or evidence.get("pr_base_sha") != go.base_sha
            or evidence.get("pr_state") != "open" or evidence.get("pr_is_draft") is not True
            or evidence.get("pr_merged") is not False
            or evidence.get("readonly_ci_conclusion") != "success"
            or evidence.get("pr_number") != 1
            or not isinstance(workflow_run_id, str) or not workflow_run_id.isdigit()
            or isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1
            or not isinstance(source_commit_sha, str) or len(source_commit_sha) != 40
            or any(char not in "0123456789abcdef" for char in source_commit_sha)):
        raise ValueError("auditor_evidence_scope_mismatch")

    payload = {
        "schema": 1, "kind": "F4_CYCLE_AUDIT", "repository_id": 1458303357,
        "approval_id": go.approval_id, "go_sha256": go_sha, "cycle_number": 1,
        "worker_run_id": evidence["worker_run_id"],
        "auditor_run_id": f"{workflow_run_id}:{run_attempt}:auditor",
        "workflow_run_id": workflow_run_id, "run_attempt": run_attempt,
        "workflow_path": AUDIT_WORKFLOW_PATH, "source_commit_sha": source_commit_sha,
        "base_sha": evidence["base_sha"], "pr_number": evidence["pr_number"],
        "pr_state": evidence["pr_state"], "pr_is_draft": evidence["pr_is_draft"],
        "pr_merged": evidence["pr_merged"], "pr_head_sha": evidence["pr_head_sha"],
        "pr_base_sha": evidence["pr_base_sha"],
        "readonly_ci_run_id": evidence["readonly_ci_run_id"],
        "readonly_ci_conclusion": evidence["readonly_ci_conclusion"],
        "permit_id": evidence["permit_id"], "candidate_digest": evidence["candidate_digest"],
        "witness_digest": evidence["witness_digest"],
        "journal_revision": evidence["journal_revision"],
        "journal_head_sha256": evidence["journal_head_sha256"],
        "result": "PASS", "issued_at": instant.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": expiry.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    try:
        _validate_audit_payload(payload)
    except CycleControlHold:
        raise ValueError("auditor_payload_contract_invalid") from None
    return payload, go_sha


class _SignerProxy:
    """Loads a short-lived signing key only inside this process and checks its public key."""
    def __init__(self, trusted_key: TrustedVerificationKey,
                 owner_keys: object) -> None:
        encoded = os.environ.get("B09_F4_AUDITOR_PRIVATE_KEY_PKCS8_B64", "")
        if not encoded:
            raise ValueError("auditor_signing_credential_missing")
        try:
            raw = base64.b64decode(encoded, validate=True)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = serialization.load_der_private_key(raw, password=None)
        except Exception:
            raise ValueError("auditor_signing_credential_invalid") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("auditor_signing_key_type_invalid")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if public != trusted_key.public_key:
            raise ValueError("auditor_signing_key_mismatch")
        if public in {item.public_key for item in owner_keys.values()}:
            raise ValueError("auditor_signing_key_not_independent")
        self._key = key

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def create_artifact(*, evidence: object, candidate: object, workspace: str | Path,
                    expected_base_sha: str, trusted_keys: object,
                    auditor_key_document: object, revocation_envelope: object,
                    workflow_run_id: str, run_attempt: int, source_commit_sha: str,
                    output: str | Path, now: datetime | None = None) -> str:
    if Path(output).exists() or Path(output).is_symlink():
        raise FileExistsError("refusing to overwrite existing Auditor artifact")
    payload, go_sha = build_payload(
        evidence=evidence, candidate=candidate, workspace=workspace,
        expected_base_sha=expected_base_sha, trusted_keys=trusted_keys,
        auditor_key_document=auditor_key_document, revocation_envelope=revocation_envelope,
        workflow_run_id=workflow_run_id, run_attempt=run_attempt,
        source_commit_sha=source_commit_sha, now=now,
    )
    auditor_document = auditor_key_document
    if not isinstance(auditor_document, dict):
        raise ValueError("auditor_trust_key_invalid")
    public_key = base64.b64decode(auditor_document["public_key"], validate=True)
    owner_keys = load_trusted_verification_keys(trusted_keys)
    signer = _SignerProxy(TrustedVerificationKey(
        auditor_document["key_id"], "auditor", public_key), owner_keys)
    envelope = build_cycle1_auditor_artifact(
        payload=payload, key_id=auditor_document["key_id"], private_key=signer,
    )
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return go_sha


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "candidate", "workspace", "expected-base-sha", "trusted-keys", "auditor-key", "revocation", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--source-commit-sha", required=True)
    args = parser.parse_args()
    try:
        go_sha = create_artifact(
            evidence=_read_json(args.evidence), candidate=_read_json(args.candidate),
            workspace=args.workspace, expected_base_sha=args.expected_base_sha,
            trusted_keys=_read_json(args.trusted_keys),
            auditor_key_document=_read_json(args.auditor_key),
            revocation_envelope=_read_json(args.revocation),
            workflow_run_id=args.workflow_run_id, run_attempt=args.run_attempt,
            source_commit_sha=args.source_commit_sha, output=args.output,
        )
    except (OSError, ValueError, TypeError) as exc:
        print("HOLD:" + str(exc))
        return 78
    print("F4_AUDITOR_ARTIFACT_READY:" + go_sha)
    return 0



def sign_cycle2_audit(*, payload, key_id, private_key):
    """Sign the Cycle2 contract after protected Auditor readback."""
    from attestations import sign_envelope
    from f4_cycle_control import _validate_audit_payload

    _validate_audit_payload(payload, cycle=2)
    return sign_envelope(key_id=key_id, private_key=private_key, payload=dict(payload))

if __name__ == "__main__":
    raise SystemExit(main())
