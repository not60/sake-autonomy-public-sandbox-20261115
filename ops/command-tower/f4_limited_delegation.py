"""DRAFT_HOLD limited delegation and finite two-cycle execution contracts.

This module verifies externally signed authority; it never creates Owner
signatures or keys and never starts a real Worker. External issuer, CAS,
provenance, revocation, and stage adapters must be supplied by the caller.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Callable, Mapping, Protocol

from attestations import canonical_json
from f4_go_gate import F4GoHold, _verify_ed25519
from trusted_key_registry import TrustedVerificationKey

REPOSITORY_ID = 1458303357
MAX_CYCLES = 2
FINITE_STAGES = ("worker", "publish-audit")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONTRACT_KEYS = {
    "schema", "kind", "delegation_id", "repository_id", "repository",
    "execution_revision", "cycle_tasks", "allowed_paths", "max_cycles",
    "validity", "revocation", "delegates",
}
_ENVELOPE_KEYS = {"key_id", "signature", "payload"}
_SIGNATURE_ROLES = ("owner_a", "owner_b")
_DELEGATE_ROLES = ("owner_a_delegate", "owner_b_delegate")
_PROTECTED_PATHS = frozenset({
    ".github/workflows/public-runner-draft.yml",
    "ops/command-tower/policy-public-runner.draft.json",
    "ops/command-tower/runtime-public-runner.draft.json",
    "ops/command-tower/backlog-public-runner.draft.json",
    "ops/command-tower/f4_go_gate.py",
    "ops/command-tower/f4_signing_cli.py",
    "ops/command-tower/f4_signing_provider.py",
    "ops/command-tower/f4-signing-jobs.draft.yml",
    "ops/command-tower/f4_cycle_control.py",
    "ops/command-tower/f4_cycle_runtime.py",
    "ops/command-tower/f4_limited_delegation.py",
    "ops/command-tower/publisher_gate.py",
    "ops/command-tower/trusted_key_registry.py",
    "ops/command-tower/attestations.py",
    "ops/command-tower/cas_journal.py",
    "ops/command-tower/durable_store.py",
    "ops/command-tower/draft_pr_writer.py",
})
_CANDIDATE_FIELDS = {
    "schema", "kind", "delegation_sha256", "repository_id",
    "execution_revision", "task_id", "cycle_number", "run_id",
    "changed_paths", "file_sha256", "candidate_digest", "permit_digest",
    "witness_digest", "cas_revision", "cas_head_sha256",
    "worker_provenance_digest", "cycle1_audit_digest", "issued_at", "expires_at",
}
_EVIDENCE_FIELDS = _CANDIDATE_FIELDS - {"schema", "kind", "delegation_sha256"}
_DELEGATION_SEAL = object()


class DelegationHold(RuntimeError):
    """Delegation or finite-execution evidence is absent or invalid."""


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True)
class VerifiedDelegation:
    delegation_id: str
    repository_id: int
    execution_revision: str
    cycle_tasks: tuple[str, str]
    allowed_paths: tuple[str, ...]
    max_cycles: int
    not_before: datetime
    expires_at: datetime
    revocation_sequence: int
    delegates: Mapping[str, TrustedVerificationKey]
    digest: str
    _seal: object | None = None


@dataclass(frozen=True)
class FiniteExecutionResult:
    cycles_completed: int
    stage_receipts: tuple[object, ...]
    safe_stopped: bool


def build_delegation_payload(*, delegation_id: str, execution_revision: str,
                             cycle_tasks: tuple[str, str], allowed_paths: tuple[str, ...],
                             not_before: str, expires_at: str,
                             revocation_sequence: int,
                             delegates: Mapping[str, Mapping[str, str]]) -> dict[str, object]:
    """Build unsigned owner-review material; output is never an authorization."""
    if not isinstance(delegation_id, str) or not _TASK_ID.fullmatch(delegation_id):
        raise ValueError("delegation_id_invalid")
    if not isinstance(execution_revision, str) or not _GIT_SHA.fullmatch(execution_revision):
        raise ValueError("execution_revision_invalid")
    if (not isinstance(cycle_tasks, tuple) or len(cycle_tasks) != MAX_CYCLES
            or any(not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id)
                   for task_id in cycle_tasks)
            or len(set(cycle_tasks)) != MAX_CYCLES):
        raise ValueError("two_distinct_cycle_tasks_required")
    paths = _validate_paths(allowed_paths)
    starts, ends = _parse_utc(not_before), _parse_utc(expires_at)
    if ends <= starts:
        raise ValueError("delegation_expiry_invalid")
    if (isinstance(revocation_sequence, bool) or not isinstance(revocation_sequence, int)
            or revocation_sequence < 1):
        raise ValueError("revocation_sequence_invalid")
    if not isinstance(delegates, Mapping) or set(delegates) != set(_DELEGATE_ROLES):
        raise ValueError("two_separate_delegate_keys_required")
    normalized: dict[str, dict[str, str]] = {}
    for role in _DELEGATE_ROLES:
        entry = delegates[role]
        if not isinstance(entry, Mapping) or set(entry) != {"key_id", "public_key"}:
            raise ValueError("delegate_entry_invalid")
        key_id, public_key = entry["key_id"], entry["public_key"]
        if (not isinstance(key_id, str) or not _TASK_ID.fullmatch(key_id)
                or not isinstance(public_key, str) or not public_key):
            raise ValueError("delegate_entry_invalid")
        try:
            raw = base64.b64decode(public_key, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("delegate_public_key_encoding_invalid") from None
        if len(raw) != 32:
            raise ValueError("delegate_public_key_size_invalid")
        normalized[role] = {"key_id": key_id, "public_key": public_key}
    if (normalized[_DELEGATE_ROLES[0]]["key_id"] == normalized[_DELEGATE_ROLES[1]]["key_id"]
            or normalized[_DELEGATE_ROLES[0]]["public_key"] == normalized[_DELEGATE_ROLES[1]]["public_key"]):
        raise ValueError("delegate_keys_not_independent")
    return {
        "schema": 2, "kind": "F4_LIMITED_DELEGATION",
        "delegation_id": delegation_id, "repository_id": REPOSITORY_ID,
        "repository": "not60/sake-autonomy-public-sandbox-20261115",
        "execution_revision": execution_revision,
        "cycle_tasks": {str(cycle): task_id for cycle, task_id in enumerate(cycle_tasks, 1)},
        "allowed_paths": list(paths), "max_cycles": MAX_CYCLES,
        "validity": {"not_before": not_before, "expires_at": expires_at},
        "revocation": {"source": "external_cas_signed_status",
                       "sequence": revocation_sequence,
                       "check_before_each_cycle": True},
        "delegates": normalized,
    }


def verify_delegation_contract(*, envelope: object,
                               trusted_owner_keys: Mapping[str, TrustedVerificationKey],
                               expected_execution_revision: str,
                               expected_cycle_tasks: tuple[str, str],
                               revocation_status: object,
                               verify_revocation_status: Callable[[object, Mapping[str, object]], bool] | None,
                               now: datetime | None = None) -> VerifiedDelegation:
    if (not isinstance(envelope, Mapping) or set(envelope) != {"schema", "state", "payload", "approvals"}
            or envelope.get("schema") != 1 or envelope.get("state") != "SIGNED_DELEGATION"):
        raise DelegationHold("delegation_not_owner_signed")
    payload, approvals = envelope["payload"], envelope["approvals"]
    if not isinstance(payload, Mapping) or set(payload) != _CONTRACT_KEYS:
        raise DelegationHold("delegation_payload_invalid")
    if (payload.get("schema") != 2 or payload.get("kind") != "F4_LIMITED_DELEGATION"
            or payload.get("repository_id") != REPOSITORY_ID
            or payload.get("repository") != "not60/sake-autonomy-public-sandbox-20261115"
            or payload.get("execution_revision") != expected_execution_revision
            or payload.get("max_cycles") != MAX_CYCLES):
        raise DelegationHold("delegation_scope_mismatch")
    task_map = payload.get("cycle_tasks")
    if (not isinstance(expected_cycle_tasks, tuple)
            or len(expected_cycle_tasks) != MAX_CYCLES
            or len(set(expected_cycle_tasks)) != MAX_CYCLES
            or any(not isinstance(task, str) or not _TASK_ID.fullmatch(task)
                   for task in expected_cycle_tasks)
            or not isinstance(task_map, Mapping)
            or set(task_map) != {"1", "2"}
            or task_map != {str(cycle): task for cycle, task in enumerate(expected_cycle_tasks, 1)}):
        raise DelegationHold("delegation_cycle_task_scope_mismatch")
    delegation_id = payload.get("delegation_id")
    if not isinstance(delegation_id, str) or not _TASK_ID.fullmatch(delegation_id):
        raise DelegationHold("delegation_id_invalid")
    try:
        paths = _validate_paths(payload.get("allowed_paths"))
    except (TypeError, ValueError):
        raise DelegationHold("delegation_paths_invalid") from None
    validity = payload.get("validity")
    if not isinstance(validity, Mapping) or set(validity) != {"not_before", "expires_at"}:
        raise DelegationHold("delegation_validity_invalid")
    try:
        starts, ends = _parse_utc(validity["not_before"]), _parse_utc(validity["expires_at"])
    except (TypeError, ValueError):
        raise DelegationHold("delegation_validity_invalid") from None
    instant = _now(now)
    if ends <= starts or instant < starts or instant >= ends:
        raise DelegationHold("delegation_not_yet_valid_or_expired")
    revocation = payload.get("revocation")
    if (not isinstance(revocation, Mapping) or set(revocation) != {"source", "sequence", "check_before_each_cycle"}
            or revocation.get("source") != "external_cas_signed_status"
            or revocation.get("check_before_each_cycle") is not True
            or isinstance(revocation.get("sequence"), bool)
            or not isinstance(revocation.get("sequence"), int) or revocation["sequence"] < 1):
        raise DelegationHold("delegation_revocation_policy_invalid")
    if verify_revocation_status is None:
        raise DelegationHold("delegation_revocation_verifier_missing")
    try:
        active = verify_revocation_status(revocation_status, payload)
    except Exception:
        active = False
    if active is not True:
        raise DelegationHold("delegation_revocation_not_authenticated")
    _verify_owner_signatures(approvals, payload, trusted_owner_keys)
    delegates = _load_delegates(payload.get("delegates"), trusted_owner_keys)
    return VerifiedDelegation(
        delegation_id=delegation_id, repository_id=REPOSITORY_ID,
        execution_revision=expected_execution_revision,
        cycle_tasks=expected_cycle_tasks,
        allowed_paths=paths, max_cycles=MAX_CYCLES, not_before=starts,
        expires_at=ends, revocation_sequence=revocation["sequence"],
        delegates=delegates, digest=hashlib.sha256(canonical_json(dict(envelope))).hexdigest(),
        _seal=_DELEGATION_SEAL,
    )


def issue_candidate_authorization_for_role(*, delegation: VerifiedDelegation,
                                           role: str, evidence: object,
                                           verify_candidate_evidence: Callable[[object, VerifiedDelegation], bool] | None,
                                           signer: Signer | None,
                                           now: datetime | None = None) -> dict[str, object]:
    """Issue one delegate fragment; this process receives only one role key."""
    if not _valid_verified_delegation(delegation):
        raise DelegationHold("verified_delegation_required")
    if role not in _DELEGATE_ROLES:
        raise DelegationHold("delegated_signer_role_invalid")
    instant = _now(now)
    if instant < delegation.not_before or instant >= delegation.expires_at:
        raise DelegationHold("delegation_not_yet_valid_or_expired")
    normalized = _validate_evidence(evidence, delegation, instant)
    if verify_candidate_evidence is None:
        raise DelegationHold("candidate_evidence_verifier_missing")
    try:
        verified = verify_candidate_evidence(evidence, delegation)
    except Exception:
        verified = False
    if verified is not True:
        raise DelegationHold("permit_witness_cas_or_provenance_not_verified")
    key = delegation.delegates[role]
    if signer is None or not callable(getattr(signer, "sign", None)):
        raise DelegationHold("delegated_signer_missing")
    payload = {
        "schema": 1, "kind": "F4_DELEGATED_CANDIDATE_AUTHORIZATION",
        "delegation_sha256": delegation.digest, **normalized,
    }
    try:
        signature = signer.sign(canonical_json(payload))
    except Exception:
        raise DelegationHold("delegated_candidate_signing_failed") from None
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise DelegationHold("delegated_candidate_signature_invalid")
    _verify_signature(key.public_key, signature, canonical_json(payload))
    return {
        "schema": 1, "role": role, "payload": payload,
        "signature": {"key_id": key.key_id,
                      "signature": base64.b64encode(signature).decode("ascii")},
    }


def combine_candidate_authorization_fragments(*, delegation: VerifiedDelegation,
                                               fragments: object) -> dict[str, object]:
    """Combine two independently produced fragments after verifying each signature."""
    if not _valid_verified_delegation(delegation):
        raise DelegationHold("verified_delegation_required")
    if not isinstance(fragments, (list, tuple)) or len(fragments) != 2:
        raise DelegationHold("two_delegate_fragments_required")
    by_role: dict[str, Mapping[str, object]] = {}
    common_payload: Mapping[str, object] | None = None
    for fragment in fragments:
        if not isinstance(fragment, Mapping) or set(fragment) != {"schema", "role", "payload", "signature"}:
            raise DelegationHold("delegate_fragment_invalid")
        role = fragment.get("role")
        payload = fragment.get("payload")
        signed = fragment.get("signature")
        if (fragment.get("schema") != 1 or role not in _DELEGATE_ROLES
                or role in by_role or not isinstance(payload, Mapping)
                or set(payload) != _CANDIDATE_FIELDS
                or payload.get("schema") != 1
                or payload.get("kind") != "F4_DELEGATED_CANDIDATE_AUTHORIZATION"
                or payload.get("delegation_sha256") != delegation.digest
                or not isinstance(signed, Mapping) or set(signed) != {"key_id", "signature"}):
            raise DelegationHold("delegate_fragment_scope_invalid")
        key = delegation.delegates[role]
        encoded = signed.get("signature")
        if signed.get("key_id") != key.key_id or not isinstance(encoded, str):
            raise DelegationHold("delegate_fragment_key_mismatch")
        try:
            raw_signature = base64.b64decode(encoded, validate=True)
            _verify_signature(key.public_key, raw_signature, canonical_json(dict(payload)))
        except (binascii.Error, ValueError, DelegationHold):
            raise DelegationHold("delegate_fragment_signature_invalid") from None
        if common_payload is None:
            common_payload = payload
        elif dict(common_payload) != dict(payload):
            raise DelegationHold("delegate_fragment_payload_mismatch")
        by_role[role] = signed
    if set(by_role) != set(_DELEGATE_ROLES) or common_payload is None:
        raise DelegationHold("both_delegated_signatures_required")
    first, second = (delegation.delegates[role].public_key for role in _DELEGATE_ROLES)
    if first == second:
        raise DelegationHold("delegated_signers_not_independent")
    return {"schema": 1, "payload": dict(common_payload),
            "signatures": {role: dict(by_role[role]) for role in _DELEGATE_ROLES}}


def verify_candidate_authorization(*, consumer: str, delegation: VerifiedDelegation,
                                   authorization: object, evidence: object,
                                   verify_candidate_evidence: Callable[[object, VerifiedDelegation], bool] | None,
                                   now: datetime | None = None) -> str:
    if consumer not in {"publisher", "auditor"}:
        raise DelegationHold("delegation_consumer_invalid")
    if not _valid_verified_delegation(delegation):
        raise DelegationHold("verified_delegation_required")
    instant = _now(now)
    normalized = _validate_evidence(evidence, delegation, instant)
    if verify_candidate_evidence is None:
        raise DelegationHold("candidate_evidence_verifier_missing")
    try:
        verified = verify_candidate_evidence(evidence, delegation)
    except Exception:
        verified = False
    if verified is not True:
        raise DelegationHold("permit_witness_cas_or_provenance_not_verified")
    if (not isinstance(authorization, Mapping) or set(authorization) != {"schema", "payload", "signatures"}
            or authorization.get("schema") != 1):
        raise DelegationHold("candidate_authorization_invalid")
    payload = authorization.get("payload")
    expected_payload = {
        "schema": 1, "kind": "F4_DELEGATED_CANDIDATE_AUTHORIZATION",
        "delegation_sha256": delegation.digest, **normalized,
    }
    if not isinstance(payload, Mapping) or dict(payload) != expected_payload:
        raise DelegationHold("candidate_authorization_scope_mismatch")
    signatures = authorization.get("signatures")
    if not isinstance(signatures, Mapping) or set(signatures) != set(_DELEGATE_ROLES):
        raise DelegationHold("both_delegated_signatures_required")
    message = canonical_json(dict(payload))
    resolved: list[bytes] = []
    for role in _DELEGATE_ROLES:
        item = signatures[role]
        key = delegation.delegates[role]
        if (not isinstance(item, Mapping) or set(item) != {"key_id", "signature"}
                or item.get("key_id") != key.key_id or not isinstance(item.get("signature"), str)):
            raise DelegationHold("delegated_signature_scope_invalid")
        try:
            signature = base64.b64decode(item["signature"], validate=True)
            _verify_signature(key.public_key, signature, message)
        except (binascii.Error, ValueError, DelegationHold):
            raise DelegationHold("delegated_candidate_signature_invalid") from None
        resolved.append(key.public_key)
    if resolved[0] == resolved[1]:
        raise DelegationHold("delegated_signers_not_independent")
    return hashlib.sha256(canonical_json(dict(authorization))).hexdigest()


def verify_publisher_candidate_authorization(*, delegation_envelope: object,
                                             trusted_owner_keys: Mapping[str, TrustedVerificationKey],
                                             expected_execution_revision: str,
                                             expected_cycle_tasks: tuple[str, str],
                                             revocation_status: object,
                                             verify_revocation_status: Callable[[object, Mapping[str, object]], bool] | None,
                                             authorization: object, evidence: object,
                                             verify_candidate_evidence: Callable[[object, VerifiedDelegation], bool] | None,
                                             now: datetime | None = None) -> str:
    """Publisher independently verifies Owner delegation, revocation and candidate evidence."""
    verified = verify_delegation_contract(
        envelope=delegation_envelope, trusted_owner_keys=trusted_owner_keys,
        expected_execution_revision=expected_execution_revision,
        expected_cycle_tasks=expected_cycle_tasks, revocation_status=revocation_status,
        verify_revocation_status=verify_revocation_status, now=now,
    )
    return verify_candidate_authorization(
        consumer="publisher", delegation=verified, authorization=authorization,
        evidence=evidence, verify_candidate_evidence=verify_candidate_evidence, now=now,
    )


def verify_auditor_candidate_authorization(*, delegation_envelope: object,
                                           trusted_owner_keys: Mapping[str, TrustedVerificationKey],
                                           expected_execution_revision: str,
                                           expected_cycle_tasks: tuple[str, str],
                                           revocation_status: object,
                                           verify_revocation_status: Callable[[object, Mapping[str, object]], bool] | None,
                                           authorization: object, evidence: object,
                                           verify_candidate_evidence: Callable[[object, VerifiedDelegation], bool] | None,
                                           now: datetime | None = None) -> str:
    """Auditor independently re-verifies the Owner delegation and read-only candidate evidence."""
    verified = verify_delegation_contract(
        envelope=delegation_envelope, trusted_owner_keys=trusted_owner_keys,
        expected_execution_revision=expected_execution_revision,
        expected_cycle_tasks=expected_cycle_tasks, revocation_status=revocation_status,
        verify_revocation_status=verify_revocation_status, now=now,
    )
    return verify_candidate_authorization(
        consumer="auditor", delegation=verified, authorization=authorization,
        evidence=evidence, verify_candidate_evidence=verify_candidate_evidence, now=now,
    )


def execute_finite_two_cycles(*, check_revocation: Callable[[int], bool] | None,
                              verify_worker_result: Callable[[int, object], object] | None,
                              verify_stage_result: Callable[[int, object, object, object], object] | None,
                              verify_cycle_safe_stop: Callable[[int, object, object], object] | None,
                              execute_stage: Callable[[int, str], object] | None,
                              verify_cycle1_audit: Callable[[object], bool] | None,
                              safe_stop: Callable[[], bool] | None) -> FiniteExecutionResult:
    """Run the existing two explicit cross-run stages twice, then SAFE STOP.

    This is an injected candidate coordinator only. The Cycle 1 verifier must
    authenticate both the independent audit PASS and its SAFE STOP receipt.
    Worker result verifier must return a CAS/provenance-verified sealed claim.
    Stage verifier must authenticate signatures/CI/independent audit; stop verifier
    must authenticate the actual stop receipt, not a plain result flag.
    Missing real adapters fail closed; no network, workflow dispatch, or Worker
    is started here.
    """
    if any(not callable(callback) for callback in
           (check_revocation, verify_worker_result, verify_stage_result,
            verify_cycle_safe_stop, verify_cycle1_audit, execute_stage, safe_stop)):
        raise DelegationHold("finite_execution_adapter_missing")
    receipts: list[object] = []
    cycles_completed = 0
    previous_audit = None
    try:
        for cycle in (1, 2):
            try:
                active = check_revocation(cycle)  # type: ignore[misc]
            except Exception:
                active = False
            if active is not True:
                raise DelegationHold("revocation_not_active_before_cycle")
            # execute_stage(worker) owns the only claim write, before Codex.
            # No retry on ambiguous launch, claim, transport or execution outcomes.
            from f4_cycle_control import (
                is_verified_safe_stop, is_verified_stage_audit, is_verified_worker_claim,
            )
            try:
                worker_receipt = execute_stage(cycle, "worker")
                claim = verify_worker_result(cycle, worker_receipt)
            except Exception:
                raise DelegationHold("worker_execution_or_claim_unverified_no_retry") from None
            if not is_verified_worker_claim(claim) or claim.cycle != cycle:
                raise DelegationHold("worker_claim_receipt_unverified")
            if cycle == 2 and (claim.run_id == previous_claim.run_id
                    or claim.source_commit_sha != previous_claim.source_commit_sha
                    or claim.go_sha256 != previous_claim.go_sha256
                    or claim.journal_sequence <= previous_claim.journal_sequence):
                raise DelegationHold("worker_claim_continuity_mismatch")
            previous_claim = claim
            receipts.append(worker_receipt)
            try:
                receipt = execute_stage(cycle, "publish-audit")
                audit = verify_stage_result(cycle, claim, receipt, previous_audit)
            except Exception:
                raise DelegationHold("finite_stage_failed_no_retry") from None
            if receipt is None or not is_verified_stage_audit(audit, claim, previous_audit):
                raise DelegationHold("publisher_signatures_or_audit_unverified")
            receipts.append(receipt)
            cycle_receipts = [worker_receipt, receipt]
            try:
                stopped = verify_cycle_safe_stop(cycle, receipt, audit)
            except Exception:
                stopped = False
            if not is_verified_safe_stop(stopped, audit):
                raise DelegationHold("cycle_safe_stop_unverified")
            if cycle == 1:
                if verify_cycle1_audit is None:
                    raise DelegationHold("cycle1_independent_audit_verifier_missing")
                try:
                    audit_ok = verify_cycle1_audit(cycle_receipts[-1]) is True
                except Exception:
                    audit_ok = False
                if not audit_ok:
                    raise DelegationHold("cycle1_independent_audit_not_passed")
            previous_audit = audit
            cycles_completed += 1
    except Exception as exc:
        stop_ok = _safe_stop(safe_stop)
        if not stop_ok:
            raise DelegationHold("safe_stop_failed_after_hold") from None
        if isinstance(exc, DelegationHold):
            raise
        raise DelegationHold("finite_execution_failed") from None
    if not _safe_stop(safe_stop):
        raise DelegationHold("safe_stop_failed_after_cycle2")
    return FiniteExecutionResult(cycles_completed=cycles_completed,
                                 stage_receipts=tuple(receipts), safe_stopped=True)


def _validate_evidence(evidence: object, delegation: VerifiedDelegation,
                       now: datetime) -> dict[str, object]:
    if not isinstance(evidence, Mapping) or set(evidence) != _EVIDENCE_FIELDS:
        raise DelegationHold("candidate_evidence_fields_invalid")
    cycle = evidence.get("cycle_number")
    if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle not in (1, 2):
        raise DelegationHold("candidate_cycle_outside_delegation")
    if (evidence.get("repository_id") != delegation.repository_id
            or evidence.get("execution_revision") != delegation.execution_revision
            or evidence.get("task_id") != delegation.cycle_tasks[cycle - 1]):
        raise DelegationHold("candidate_scope_mismatch")
    run_id = evidence.get("run_id")
    if not isinstance(run_id, str) or not _TASK_ID.fullmatch(run_id):
        raise DelegationHold("candidate_run_id_invalid")
    try:
        paths = _validate_paths(evidence.get("changed_paths"))
    except (TypeError, ValueError):
        raise DelegationHold("candidate_paths_invalid") from None
    if not set(paths).issubset(set(delegation.allowed_paths)):
        raise DelegationHold("candidate_path_outside_delegation")
    file_hashes = evidence.get("file_sha256")
    if (not isinstance(file_hashes, Mapping) or set(file_hashes) != set(paths)
            or any(not isinstance(value, str) or not _SHA256.fullmatch(value)
                   for value in file_hashes.values())):
        raise DelegationHold("candidate_file_digests_invalid")
    for field in ("candidate_digest", "permit_digest", "witness_digest",
                  "cas_head_sha256", "worker_provenance_digest"):
        if not isinstance(evidence.get(field), str) or not _SHA256.fullmatch(evidence[field]):
            raise DelegationHold("candidate_digest_invalid")
    revision = evidence.get("cas_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise DelegationHold("candidate_cas_revision_invalid")
    cycle1_audit = evidence.get("cycle1_audit_digest")
    if cycle == 1:
        if cycle1_audit is not None:
            raise DelegationHold("cycle1_must_not_bind_prior_audit")
    elif not isinstance(cycle1_audit, str) or not _SHA256.fullmatch(cycle1_audit):
        raise DelegationHold("cycle2_requires_cycle1_audit_digest")
    try:
        issued, expires = _parse_utc(evidence.get("issued_at")), _parse_utc(evidence.get("expires_at"))
    except (TypeError, ValueError):
        raise DelegationHold("candidate_validity_invalid") from None
    if (expires <= issued or now < issued or now >= expires
            or issued < delegation.not_before or expires > delegation.expires_at):
        raise DelegationHold("candidate_expired_or_outside_delegation")
    return {
        "repository_id": delegation.repository_id,
        "execution_revision": delegation.execution_revision,
        "task_id": delegation.cycle_tasks[cycle - 1], "cycle_number": cycle, "run_id": run_id,
        "changed_paths": list(paths),
        "file_sha256": {path: file_hashes[path] for path in paths},
        "candidate_digest": evidence["candidate_digest"],
        "permit_digest": evidence["permit_digest"],
        "witness_digest": evidence["witness_digest"],
        "cas_revision": revision, "cas_head_sha256": evidence["cas_head_sha256"],
        "worker_provenance_digest": evidence["worker_provenance_digest"],
        "cycle1_audit_digest": cycle1_audit,
        "issued_at": evidence["issued_at"], "expires_at": evidence["expires_at"],
    }


def _verify_owner_signatures(approvals: object, payload: Mapping[str, object],
                             trusted: Mapping[str, TrustedVerificationKey]) -> None:
    if not isinstance(approvals, Mapping) or set(approvals) != set(_SIGNATURE_ROLES):
        raise DelegationHold("both_owner_signatures_required")
    resolved: list[bytes] = []
    message = canonical_json(dict(payload))
    for role in _SIGNATURE_ROLES:
        item = approvals[role]
        if (not isinstance(item, Mapping) or set(item) != _ENVELOPE_KEYS
                or item.get("payload") != payload or not isinstance(item.get("key_id"), str)
                or not isinstance(item.get("signature"), str)):
            raise DelegationHold("owner_delegation_envelope_invalid")
        key = trusted.get(item["key_id"])
        if key is None or key.role != role or key.key_id != item["key_id"]:
            raise DelegationHold("owner_delegation_trust_key_invalid")
        try:
            signature = base64.b64decode(item["signature"], validate=True)
            _verify_signature(key.public_key, signature, message)
        except Exception:
            raise DelegationHold("owner_delegation_signature_invalid") from None
        resolved.append(key.public_key)
    if resolved[0] == resolved[1]:
        raise DelegationHold("owner_delegation_signers_not_independent")


def _load_delegates(document: object,
                    trusted: Mapping[str, TrustedVerificationKey]) -> dict[str, TrustedVerificationKey]:
    if not isinstance(document, Mapping) or set(document) != set(_DELEGATE_ROLES):
        raise DelegationHold("delegation_keys_missing")
    base_keys = {key.public_key for key in trusted.values()}
    result: dict[str, TrustedVerificationKey] = {}
    for role in _DELEGATE_ROLES:
        item = document[role]
        if not isinstance(item, Mapping) or set(item) != {"key_id", "public_key"}:
            raise DelegationHold("delegation_key_entry_invalid")
        key_id, encoded = item["key_id"], item["public_key"]
        if not isinstance(key_id, str) or not _TASK_ID.fullmatch(key_id) or not isinstance(encoded, str):
            raise DelegationHold("delegation_key_entry_invalid")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise DelegationHold("delegation_key_encoding_invalid") from None
        if len(raw) != 32 or raw in base_keys or any(key.public_key == raw for key in result.values()):
            raise DelegationHold("delegation_key_not_independent")
        result[role] = TrustedVerificationKey(key_id, role, raw)
    return result


def _verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        _verify_ed25519(public_key, signature, message)
    except F4GoHold:
        raise DelegationHold("ed25519_signature_invalid_or_unavailable") from None


def _validate_paths(paths: object) -> tuple[str, ...]:
    if not isinstance(paths, (list, tuple)) or not paths:
        raise ValueError("paths_required")
    normalized = tuple(paths)
    if (any(not isinstance(path, str) or not path.startswith("ops/command-tower/")
            or "\\" in path or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path.startswith(".github/workflows/") or path in _PROTECTED_PATHS
            for path in normalized)
            or len(set(normalized)) != len(normalized)
            or tuple(sorted(normalized)) != normalized):
        raise ValueError("unsafe_or_noncanonical_path_set")
    return normalized


def _valid_verified_delegation(value: object) -> bool:
    return isinstance(value, VerifiedDelegation) and value._seal is _DELEGATION_SEAL


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp_must_be_utc")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("timestamp_invalid") from None
    if result.utcoffset() != timezone.utc.utcoffset(result):
        raise ValueError("timestamp_must_be_utc")
    return result


def _now(value: datetime | None) -> datetime:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise DelegationHold("clock_untrusted")
    return instant.astimezone(timezone.utc)


def _safe_stop(callback: Callable[[], bool] | None) -> bool:
    if callback is None:
        return False
    try:
        return callback() is True
    except Exception:
        return False
