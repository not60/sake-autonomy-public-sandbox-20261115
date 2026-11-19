"""Candidate F4 two-cycle GO contract; never starts a Worker or writes remotely."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from pathlib import Path
from typing import Callable, Mapping

from attestations import canonical_json
from trusted_key_registry import SIGNING_ROLES, TrustedVerificationKey


REPOSITORY_ID = 1458303357
REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"
F4_SOURCE_PATHS = (
    "ops/command-tower/policy-public-runner.draft.json",
    "ops/command-tower/runtime-public-runner.draft.json",
    "ops/command-tower/backlog-public-runner.draft.json",
    ".github/workflows/public-runner-draft.yml",
)
F4_SCOPE = {
    "max_worker_cycles": 2,
    "cycle_2_requires_cycle_1_independent_audit_pass": True,
    "publication": "existing_draft_pr_only",
    "ci": "existing_pull_request_read_only",
    "main_write": False,
    "pr_merge": False,
    "workflow_activation": False,
}
F4_SAFE_STOPS = (
    "source_sha_or_base_mismatch",
    "missing_invalid_or_expired_go_signature",
    "revocation_status_missing_or_invalid",
    "permit_witness_or_cas_failure",
    "artifact_scope_or_permission_mismatch",
    "draft_pr_or_read_only_ci_failure",
    "cycle_1_audit_missing_or_failed_before_cycle_2",
    "ambiguous_result_or_duplicate_cycle_claim",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_GO_KEYS = frozenset({
    "schema", "decision", "approval_id", "repository_id", "repository",
    "base_sha", "source_sha256s", "scope", "validity", "revocation",
    "safe_stop_conditions",
})
_ENVELOPE_KEYS = {"key_id", "signature", "payload"}
_GO_SEAL = object()


class F4GoHold(RuntimeError):
    """F4 authorization or sequential-cycle evidence is not valid."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class VerifiedF4Go:
    approval_id: str
    repository_id: int
    base_sha: str
    source_sha256s: tuple[tuple[str, str], ...]
    candidate_sha256: str
    max_worker_cycles: int
    revocation_sequence: int
    not_before: datetime
    expires_at: datetime
    _seal: object | None = None


def build_f4_go_candidate(*, workspace: str | Path, base_sha: str,
                          approval_id: str, not_before: str, expires_at: str,
                          revocation_sequence: int) -> dict[str, object]:
    """Build an unsigned, DRAFT_HOLD payload from exact local source bytes."""
    if not _GIT_SHA.fullmatch(base_sha):
        raise ValueError("base SHA must be a full Git commit SHA")
    if not isinstance(approval_id, str) or not approval_id or len(approval_id) > 128:
        raise ValueError("approval ID is required")
    if isinstance(revocation_sequence, bool) or not isinstance(revocation_sequence, int) or revocation_sequence < 1:
        raise ValueError("revocation sequence must be a positive integer")
    start = _parse_utc(not_before, "not_before")
    end = _parse_utc(expires_at, "expires_at")
    if end <= start:
        raise ValueError("expiry must follow not-before")

    root = Path(workspace).resolve(strict=True)
    hashes = _read_source_hashes(root)
    payload: dict[str, object] = {
        "schema": 1,
        "decision": "F4_FORMAL_TWO_CYCLE_GO",
        "approval_id": approval_id,
        "repository_id": REPOSITORY_ID,
        "repository": REPOSITORY,
        "base_sha": base_sha,
        "source_sha256s": hashes,
        "scope": dict(F4_SCOPE),
        "validity": {"not_before": not_before, "expires_at": expires_at},
        "revocation": {
            "source": "external_cas_signed_status",
            "sequence": revocation_sequence,
            "check_before_each_cycle": True,
        },
        "safe_stop_conditions": list(F4_SAFE_STOPS),
    }
    return {
        "schema": 1,
        "state": "DRAFT_HOLD",
        "payload": payload,
        "approvals": {},
    }


def verify_f4_go_candidate(*, candidate: object, workspace: str | Path,
                           expected_repository_id: int, expected_base_sha: str,
                           trusted_keys: Mapping[str, TrustedVerificationKey],
                           revocation_status: object,
                           verify_revocation_status: Callable[[object], bool] | None,
                           now: datetime | None = None) -> VerifiedF4Go:
    """Verify a separately signed F4 GO; every unavailable check fails closed."""
    if (not isinstance(candidate, dict)
            or set(candidate) != {"schema", "state", "payload", "approvals"}
            or candidate.get("schema") != 1 or candidate.get("state") != "SIGNED_GO"):
        raise F4GoHold("f4_go_candidate_not_owner_signed")
    payload = candidate.get("payload")
    approvals = candidate.get("approvals")
    if not isinstance(payload, dict) or set(payload) != _GO_KEYS:
        raise F4GoHold("f4_go_payload_invalid")
    if payload.get("schema") != 1 or payload.get("decision") != "F4_FORMAL_TWO_CYCLE_GO":
        raise F4GoHold("f4_go_decision_invalid")
    approval_id = payload.get("approval_id")
    if not isinstance(approval_id, str) or not approval_id or len(approval_id) > 128:
        raise F4GoHold("f4_go_approval_id_invalid")
    repo_id = payload.get("repository_id")
    if (isinstance(repo_id, bool) or repo_id != REPOSITORY_ID
            or repo_id != expected_repository_id or payload.get("repository") != REPOSITORY):
        raise F4GoHold("f4_go_repository_mismatch")
    base_sha = payload.get("base_sha")
    if (not isinstance(base_sha, str) or not _GIT_SHA.fullmatch(base_sha)
            or base_sha != expected_base_sha):
        raise F4GoHold("f4_go_base_sha_mismatch")

    try:
        observed_hashes = _read_source_hashes(Path(workspace).resolve(strict=True))
    except (OSError, ValueError):
        raise F4GoHold("f4_go_source_unavailable") from None
    if payload.get("source_sha256s") != observed_hashes:
        raise F4GoHold("f4_go_source_sha_mismatch")
    if payload.get("scope") != F4_SCOPE:
        raise F4GoHold("f4_go_scope_mismatch")
    if payload.get("safe_stop_conditions") != list(F4_SAFE_STOPS):
        raise F4GoHold("f4_go_safe_stop_contract_mismatch")

    validity = payload.get("validity")
    if not isinstance(validity, dict) or set(validity) != {"not_before", "expires_at"}:
        raise F4GoHold("f4_go_validity_invalid")
    try:
        starts = _parse_utc(validity["not_before"], "not_before")
        ends = _parse_utc(validity["expires_at"], "expires_at")
    except (TypeError, ValueError):
        raise F4GoHold("f4_go_validity_invalid") from None
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise F4GoHold("f4_go_clock_untrusted")
    instant = instant.astimezone(timezone.utc)
    if ends <= starts or instant < starts or instant >= ends:
        raise F4GoHold("f4_go_not_yet_valid_or_expired")

    _verify_revocation_status(
        payload.get("revocation"), revocation_status, approval_id,
        verify_revocation_status,
    )
    if set(key.role for key in trusted_keys.values()) != set(SIGNING_ROLES):
        raise F4GoHold("f4_go_trust_registry_incomplete")
    if len({key.public_key for key in trusted_keys.values()}) != len(trusted_keys):
        raise F4GoHold("f4_go_trust_registry_has_shared_keys")
    owner_keys = _verify_owner_approvals(approvals, payload, trusted_keys)
    if owner_keys[0].public_key == owner_keys[1].public_key:
        raise F4GoHold("f4_go_owner_keys_not_independent")

    return VerifiedF4Go(
        approval_id=approval_id,
        repository_id=repo_id,
        base_sha=base_sha,
        source_sha256s=tuple(sorted(observed_hashes.items())),
        candidate_sha256=hashlib.sha256(canonical_json(candidate)).hexdigest(),
        max_worker_cycles=2,
        revocation_sequence=payload["revocation"]["sequence"],
        not_before=starts,
        expires_at=ends,
        _seal=_GO_SEAL,
    )


def authorize_cycle(*, go: VerifiedF4Go, cycle_number: int,
                    atomic_cycle_claim: Callable[[str, int], bool] | None,
                    revocation_status: object = None,
                    verify_revocation_status: Callable[[object], bool] | None = None,
                    cycle_1_audit_receipt: object = None,
                    verify_audit_receipt: Callable[[object], bool] | None = None,
                    now: datetime | None = None) -> None:
    """Require an external atomic claim; Cycle 2 additionally requires a verified Cycle 1 audit."""
    if not isinstance(go, VerifiedF4Go) or go._seal is not _GO_SEAL:
        raise F4GoHold("f4_go_verification_required")
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise F4GoHold("f4_go_clock_untrusted")
    instant = instant.astimezone(timezone.utc)
    if instant < go.not_before or instant >= go.expires_at:
        raise F4GoHold("f4_go_not_yet_valid_or_expired")
    _verify_revocation_status(
        {"source": "external_cas_signed_status", "sequence": go.revocation_sequence,
         "check_before_each_cycle": True},
        revocation_status, go.approval_id, verify_revocation_status,
    )
    if isinstance(cycle_number, bool) or cycle_number not in (1, 2):
        raise F4GoHold("worker_cycle_outside_f4_scope")
    if cycle_number == 2:
        if cycle_1_audit_receipt is None or verify_audit_receipt is None:
            raise F4GoHold("cycle_1_independent_audit_verifier_missing")
        if not _cycle_1_receipt_matches_go(cycle_1_audit_receipt, go):
            raise F4GoHold("cycle_1_audit_receipt_scope_mismatch")
        try:
            valid_audit = verify_audit_receipt(cycle_1_audit_receipt)
        except Exception:
            valid_audit = False
        if valid_audit is not True:
            raise F4GoHold("cycle_1_independent_audit_not_passed")
    elif cycle_1_audit_receipt is not None:
        raise F4GoHold("cycle_1_must_not_claim_prior_cycle")
    if atomic_cycle_claim is None:
        raise F4GoHold("external_atomic_cycle_claim_missing")
    try:
        claimed = atomic_cycle_claim(go.approval_id, cycle_number)
    except Exception:
        claimed = False
    if claimed is not True:
        raise F4GoHold("duplicate_or_ambiguous_cycle_claim")


def verified_f4_go_sha256(candidate: object, go: VerifiedF4Go) -> str:
    """Return the canonical exact envelope digest only for a matching verified GO."""
    if (not isinstance(go, VerifiedF4Go) or go._seal is not _GO_SEAL
            or not isinstance(candidate, dict)
            or set(candidate) != {"schema", "state", "payload", "approvals"}
            or candidate.get("schema") != 1 or candidate.get("state") != "SIGNED_GO"):
        raise F4GoHold("f4_go_verification_required")
    payload = candidate.get("payload")
    if (not isinstance(payload, dict)
            or payload.get("approval_id") != go.approval_id
            or payload.get("repository_id") != go.repository_id
            or payload.get("base_sha") != go.base_sha
            or payload.get("source_sha256s") != dict(go.source_sha256s)
            or payload.get("decision") != "F4_FORMAL_TWO_CYCLE_GO"):
        raise F4GoHold("f4_go_candidate_binding_mismatch")
    validity = payload.get("validity")
    try:
        starts = _parse_utc(validity["not_before"], "not_before")
        ends = _parse_utc(validity["expires_at"], "expires_at")
    except (TypeError, KeyError, ValueError):
        raise F4GoHold("f4_go_candidate_binding_mismatch") from None
    if starts != go.not_before or ends != go.expires_at:
        raise F4GoHold("f4_go_candidate_binding_mismatch")
    candidate_digest = hashlib.sha256(canonical_json(candidate)).hexdigest()
    if candidate_digest != go.candidate_sha256:
        raise F4GoHold("f4_go_candidate_binding_mismatch")
    return candidate_digest


def _read_source_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in F4_SOURCE_PATHS:
        target = root.joinpath(*relative.split("/"))
        if target.is_symlink() or not target.is_file():
            raise ValueError("required F4 source missing or symlinked")
        try:
            target.resolve(strict=True).relative_to(root)
            data = target.read_bytes()
        except (OSError, ValueError):
            raise ValueError("required F4 source unreadable") from None
        hashes[relative] = hashlib.sha256(data).hexdigest()
    return hashes


def _verify_revocation_status(policy: object, status: object, approval_id: str,
                              verifier: Callable[[object], bool] | None) -> None:
    if (not isinstance(policy, dict) or set(policy) != {"source", "sequence", "check_before_each_cycle"}
            or policy.get("source") != "external_cas_signed_status"
            or policy.get("check_before_each_cycle") is not True
            or isinstance(policy.get("sequence"), bool)
            or not isinstance(policy.get("sequence"), int) or policy["sequence"] < 1):
        raise F4GoHold("f4_go_revocation_policy_invalid")
    if verifier is None:
        raise F4GoHold("revocation_status_verifier_missing")
    try:
        authenticated = verifier(status)
    except Exception:
        authenticated = False
    if authenticated is not True:
        raise F4GoHold("revocation_status_not_authenticated")
    if (not isinstance(status, dict)
            or set(status) != {"approval_id", "sequence", "status"}
            or status.get("approval_id") != approval_id
            or status.get("sequence") != policy["sequence"]
            or status.get("status") != "ACTIVE"):
        raise F4GoHold("revocation_status_missing_or_invalid")


def _cycle_1_receipt_matches_go(receipt: object, go: VerifiedF4Go) -> bool:
    required = {
        "approval_id", "cycle_number", "outcome", "repository_id", "base_sha",
        "worker_run_id", "auditor_run_id", "journal_revision", "journal_head_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        return False
    digest = receipt.get("journal_head_sha256")
    return (
        receipt.get("approval_id") == go.approval_id
        and receipt.get("cycle_number") == 1
        and receipt.get("outcome") == "PASS"
        and receipt.get("repository_id") == go.repository_id
        and receipt.get("base_sha") == go.base_sha
        and isinstance(receipt.get("worker_run_id"), str) and bool(receipt["worker_run_id"])
        and isinstance(receipt.get("auditor_run_id"), str) and bool(receipt["auditor_run_id"])
        and isinstance(receipt.get("journal_revision"), int)
        and not isinstance(receipt.get("journal_revision"), bool)
        and receipt["journal_revision"] >= 1
        and isinstance(digest, str) and bool(_SHA256.fullmatch(digest))
    )


def _verify_owner_approvals(approvals: object, payload: dict[str, object],
                            trusted_keys: Mapping[str, TrustedVerificationKey]
                            ) -> tuple[TrustedVerificationKey, TrustedVerificationKey]:
    if not isinstance(approvals, dict) or set(approvals) != {"owner_a", "owner_b"}:
        raise F4GoHold("f4_go_owner_approvals_missing")
    resolved: list[TrustedVerificationKey] = []
    message = canonical_json(payload)
    for role in ("owner_a", "owner_b"):
        envelope = approvals[role]
        if (not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS
                or envelope.get("payload") != payload):
            raise F4GoHold("f4_go_owner_envelope_invalid")
        key_id, signature_text = envelope.get("key_id"), envelope.get("signature")
        key = trusted_keys.get(key_id) if isinstance(key_id, str) else None
        if (key is None or key.key_id != key_id or key.role != role
                or len(key.public_key) != 32 or not isinstance(signature_text, str)):
            raise F4GoHold("f4_go_owner_trust_key_missing_or_wrong_role")
        try:
            import base64
            import binascii
            signature = base64.b64decode(signature_text, validate=True)
        except (binascii.Error, ValueError):
            raise F4GoHold("f4_go_signature_encoding_invalid") from None
        try:
            _verify_ed25519(key.public_key, signature, message)
        except F4GoHold:
            raise
        except Exception:
            raise F4GoHold("f4_go_signature_invalid") from None
        resolved.append(key)
    if resolved[0].key_id == resolved[1].key_id:
        raise F4GoHold("f4_go_owner_signers_not_independent")
    return resolved[0], resolved[1]


def _verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise F4GoHold("ed25519_verifier_unavailable") from None
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        raise F4GoHold("f4_go_signature_invalid") from None


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(field + " must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError(field + " must be a UTC RFC3339 timestamp") from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(field + " must be UTC")
    return parsed
