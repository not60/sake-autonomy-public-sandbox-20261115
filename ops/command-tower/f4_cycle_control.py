"""DRAFT_HOLD cross-run F4 cycle-control and signed Auditor artifact contract.

Uses a dedicated CAS key and the existing conditional CasBackend contract. It
never starts a Worker, retries a conflicted write, or modifies Permit journal
events. Real GitHub artifact provenance and Owner revocation signatures must be
verified by caller-supplied readers; absence of either fails closed.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

from attestations import canonical_json
from cas_journal import CasBackend, CasConflict, CasHold, CasSnapshot, CasValue
from f4_go_gate import (
    F4GoHold,
    VerifiedF4Go,
    _verify_ed25519,
    verified_f4_go_sha256,
)
from trusted_key_registry import SIGNING_ROLES, TrustedVerificationKey


REPOSITORY_ID = 1458303357
CONTROL_KEY = "repositories/1458303357/b09-f4-cycle-control-v1.json"
AUDIT_ARTIFACT_NAME = "b09-f4-cycle1-auditor-evidence"
CYCLE2_AUDIT_ARTIFACT_NAME = "b09-f4-cycle2-auditor-evidence"
AUDIT_WORKFLOW_PATH = ".github/workflows/public-runner-draft.yml"
GITHUB_REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ENVELOPE_KEYS = {"key_id", "signature", "payload"}
_REVOCATION_KEYS = {"payload", "approvals"}
_REVOCATION_PAYLOAD_KEYS = {
    "schema", "kind", "repository_id", "approval_id", "go_sha256",
    "sequence", "status", "valid_from", "valid_until",
}
_AUDIT_PAYLOAD_KEYS = {
    "schema", "kind", "repository_id", "approval_id", "go_sha256",
    "cycle_number", "worker_run_id", "auditor_run_id", "workflow_run_id",
    "run_attempt", "workflow_path", "source_commit_sha", "base_sha",
    "pr_number", "pr_state", "pr_is_draft", "pr_merged", "pr_head_sha",
    "pr_base_sha", "readonly_ci_run_id", "readonly_ci_conclusion",
    "permit_id", "candidate_digest", "witness_digest", "journal_revision",
    "journal_head_sha256", "result", "issued_at", "expires_at",
}
_EVENT_FIELDS = {
    "CONTROL_CREATED": {"event", "revocation_status"},
    "REVOCATION_STATUS": {"event", "revocation_status"},
    "CYCLE_CLAIMED": {
        "event", "cycle_number", "run_id", "go_sha256",
        "revocation_sequence", "revocation_digest", "claimed_at", "source_commit_sha",
    },
    "CYCLE1_AUDITOR_PASS": {
        "event", "artifact_envelope_sha256", "artifact_id",
        "artifact_archive_digest", "workflow_run_id", "run_attempt",
        "worker_run_id", "auditor_run_id", "source_commit_sha", "auditor_envelope",
    },
}


class CycleControlHold(RuntimeError):
    """F4 cycle control or independent evidence did not verify."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class VerifiedAuditorArtifact:
    payload: Mapping[str, object]
    envelope_sha256: str
    artifact_id: int
    artifact_archive_digest: str


_EVIDENCE_SEAL = object()
_CYCLE2_AUDIT_FIELDS = {"cycle1_audit_sha256", "permit_sha256"}


@dataclass(frozen=True)
class VerifiedStageAudit:
    claim: VerifiedWorkerClaim
    envelope_sha256: str
    previous_sha256: str | None
    workflow_run_id: str
    run_attempt: int
    observed_after: datetime
    expires_at: datetime
    auditor_public_key: bytes
    permit_id: str
    ci_run_id: str
    _seal: object


@dataclass(frozen=True)
class VerifiedSafeStop:
    audit: VerifiedStageAudit
    _seal: object


def verify_safe_stop(*, envelope, audit, observer_key, expected_scope, now=None):
    """Verify an independent observer's signed statement about its bounded scope."""
    if (not isinstance(audit, VerifiedStageAudit) or audit._seal is not _EVIDENCE_SEAL
            or not isinstance(observer_key, TrustedVerificationKey)
            or observer_key.role != "stop_observer" or len(observer_key.public_key) != 32
            or observer_key.public_key == audit.auditor_public_key
            or not isinstance(expected_scope, Mapping)
            or set(expected_scope) != {"executor", "process_namespace", "continuation_namespace"}
            or any(not isinstance(value, str) or not value.strip() for value in expected_scope.values())):
        raise CycleControlHold("stop_observer_or_scope_missing")
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS or envelope["key_id"] != observer_key.key_id:
        raise CycleControlHold("stop_envelope_invalid")
    payload = envelope["payload"]
    claim = audit.claim
    expected = {
        "schema": 1, "kind": "F4_SAFE_STOP", "repository_id": REPOSITORY_ID,
        "cycle": claim.cycle, "worker_run_id": claim.run_id,
        "audit_run_id": audit.workflow_run_id, "audit_run_attempt": audit.run_attempt,
        "source_commit_sha": claim.source_commit_sha, "go_sha256": claim.go_sha256,
        "audit_sha256": audit.envelope_sha256, "observation_scope": expected_scope,
        "execution_terminated": True, "live_processes": [], "pending_executions": [],
    }
    if (not isinstance(payload, dict) or set(payload) != set(expected) | {"observed_at"}
            or canonical_json({k: payload[k] for k in expected}) != canonical_json(expected)):
        raise CycleControlHold("stop_evidence_scope_or_state_mismatch")
    observed = _parse_utc(payload["observed_at"])
    instant = _now(now)
    if (observed < audit.observed_after or instant >= audit.expires_at
            or not 0 <= (instant - observed).total_seconds() <= 300):
        raise CycleControlHold("stop_evidence_not_fresh")
    try:
        _verify_ed25519(observer_key.public_key, base64.b64decode(envelope["signature"], validate=True),
                        canonical_json(payload))
    except Exception:
        raise CycleControlHold("stop_observer_signature_invalid") from None
    return VerifiedSafeStop(audit, _EVIDENCE_SEAL)


def build_cycle_safe_stop_verifier(*, observer_key, expected_scope,
                                  trusted_signing_keys, read_signed_observation, now=None):
    """Connect a protected, independent observation reader to finite-cycle control.

    The reader must obtain the signed envelope from the trusted stop-observer
    source. This adapter never invents an observation and consumes each cycle's
    read attempt once; missing, ambiguous, or invalid evidence fails closed.
    """
    if not callable(read_signed_observation):
        raise CycleControlHold("safe_stop_observation_reader_missing")
    if (not isinstance(observer_key, TrustedVerificationKey)
            or observer_key.role != "stop_observer"
            or len(observer_key.public_key) != 32):
        raise CycleControlHold("stop_observer_or_scope_missing")
    if (not isinstance(trusted_signing_keys, Mapping)
            or {key.role for key in trusted_signing_keys.values()
                if isinstance(key, TrustedVerificationKey)} != set(SIGNING_ROLES)
            or any(not isinstance(key, TrustedVerificationKey)
                   for key in trusted_signing_keys.values())
            or observer_key.key_id in trusted_signing_keys
            or observer_key.public_key in {key.public_key for key in trusted_signing_keys.values()}):
        raise CycleControlHold("stop_observer_key_not_independent")
    if (not isinstance(expected_scope, Mapping)
            or set(expected_scope) != {"executor", "process_namespace", "continuation_namespace"}
            or any(not isinstance(value, str) or not value.strip()
                   for value in expected_scope.values())):
        raise CycleControlHold("stop_observer_or_scope_missing")

    attempted_cycles: set[int] = set()
    previous_audit: VerifiedStageAudit | None = None

    def verify(cycle, stage_receipt, audit):
        nonlocal previous_audit
        if (type(cycle) is not int or cycle not in (1, 2)
                or cycle != len(attempted_cycles) + 1 or cycle in attempted_cycles
                or stage_receipt is None
                or not isinstance(audit, VerifiedStageAudit)
                or not is_verified_worker_claim(audit.claim)
                or audit.claim.cycle != cycle
                or not is_verified_stage_audit(audit, audit.claim, previous_audit)):
            raise CycleControlHold("safe_stop_audit_or_cycle_binding_invalid")

        # A reader timeout or malformed response is not retried by this adapter.
        attempted_cycles.add(cycle)
        try:
            envelope = read_signed_observation(
                cycle=cycle, stage_receipt=stage_receipt, audit=audit,
            )
        except Exception:
            raise CycleControlHold("safe_stop_observation_unavailable_no_retry") from None
        if envelope is None:
            raise CycleControlHold("safe_stop_observation_missing")
        verified = verify_safe_stop(
            envelope=envelope, audit=audit, observer_key=observer_key,
            expected_scope=expected_scope, now=now,
        )
        if not is_verified_safe_stop(verified, audit):
            raise CycleControlHold("safe_stop_observation_unverified")
        previous_audit = audit
        return verified

    return verify


def is_verified_stage_audit(value, claim, previous):
    return (isinstance(value, VerifiedStageAudit) and value._seal is _EVIDENCE_SEAL
            and value.claim == claim and value.previous_sha256 == (
                None if previous is None else previous.envelope_sha256))


def is_verified_safe_stop(value, audit):
    return (isinstance(value, VerifiedSafeStop) and value._seal is _EVIDENCE_SEAL
            and value.audit == audit)


@dataclass(frozen=True)
class CycleControlState:
    approval_id: str
    go_sha256: str
    base_sha: str
    go_revocation_sequence: int
    revocation_sequence: int
    sequence: int
    head_sha256: str
    version: str | None
    events: tuple[dict[str, object], ...]


_CLAIM_RECEIPT_SEAL = object()


@dataclass(frozen=True)
class VerifiedWorkerClaim:
    cycle: int
    run_id: str
    source_commit_sha: str
    go_sha256: str
    journal_sequence: int
    journal_head_sha256: str
    worker_provenance_sha256: str
    _seal: object | None = None


def is_verified_worker_claim(value: object) -> bool:
    return isinstance(value, VerifiedWorkerClaim) and value._seal is _CLAIM_RECEIPT_SEAL


class F4CycleControlJournal:
    """CAS-backed run claims separate from PERMIT_ISSUED/PERMIT_CONSUMED."""

    def __init__(self, backend: CasBackend, *, trusted_signing_keys: Mapping[str, TrustedVerificationKey],
                 trusted_auditor_key: TrustedVerificationKey) -> None:
        self._backend = backend
        signing_keys = dict(trusted_signing_keys)
        roles = [key.role for key in signing_keys.values()]
        if (set(roles) != set(SIGNING_ROLES) or len(roles) != len(SIGNING_ROLES)
                or len({key.public_key for key in signing_keys.values()}) != len(signing_keys)):
            raise ValueError("the four existing independent F4 signing keys are required")
        self._owner_keys = {key_id: key for key_id, key in signing_keys.items()
                            if key.role in {"owner_a", "owner_b"}}
        self._auditor_key = trusted_auditor_key
        if trusted_auditor_key.role != "auditor" or len(trusted_auditor_key.public_key) != 32:
            raise ValueError("a distinct trusted Auditor verification key is required")
        if trusted_auditor_key.public_key in {key.public_key for key in signing_keys.values()}:
            raise ValueError("Owner and Auditor verification keys must be independent")

    def initialize(self, *, candidate: object, go: VerifiedF4Go,
                   revocation_status: object, now: datetime | None = None) -> CycleControlState:
        go_sha = _go_sha(candidate, go)
        payload = _verify_revocation_status(
            revocation_status, go=go, go_sha256=go_sha,
            trusted_keys=self._owner_keys, now=now,
        )
        if payload["status"] != "ACTIVE" or payload["sequence"] != go.revocation_sequence:
            raise CycleControlHold("initial_revocation_status_not_active_or_scoped")
        document = _empty_document(go, go_sha, revocation_status)
        try:
            version = self._backend.compare_and_swap(CONTROL_KEY, None, canonical_json(document))
        except CasConflict:
            raise CycleControlHold("cycle_control_already_initialized_or_cas_conflict") from None
        except CasHold:
            raise CycleControlHold("cycle_control_cas_unavailable") from None
        return self._decode(CasValue(canonical_json(document), version))

    def set_revocation(self, *, candidate: object, go: VerifiedF4Go,
                       revocation_status: object,
                       now: datetime | None = None) -> CycleControlState:
        state, current = self._load_for_go(candidate, go)
        current_payload = _current_revocation(state.events)
        incoming = _verify_revocation_status(
            revocation_status, go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=now,
        )
        current_status = _verify_revocation_status(
            current_payload, go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=now,
        )
        if (incoming["sequence"] != current_status["sequence"] + 1
                or current_status["status"] != "ACTIVE"
                or incoming["status"] not in {"REVOKED", "STOPPED"}):
            raise CycleControlHold("revocation_transition_invalid")
        return self._append(state, current, {
            "event": "REVOCATION_STATUS", "revocation_status": revocation_status,
        })

    def claim_cycle(self, *, candidate: object, go: VerifiedF4Go, cycle_number: int,
                    run_id: str, source_commit_sha: str,
                    now: datetime | None = None,
                    cycle1_auditor_artifact: object = None,
                    verify_github_artifact: Callable[[Mapping[str, object]], object] | None = None
                    ) -> CycleControlState:
        state, current = self._load_for_go(candidate, go)
        instant = _now(now)
        if instant >= go.expires_at or instant < go.not_before:
            raise CycleControlHold("f4_go_expired_or_not_yet_valid")
        revocation_envelope = _current_revocation(state.events)
        revocation = _verify_revocation_status(
            revocation_envelope, go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant,
        )
        if revocation["status"] != "ACTIVE":
            raise CycleControlHold("f4_go_revoked_or_stopped")
        if (isinstance(cycle_number, bool) or cycle_number not in (1, 2)
                or not isinstance(run_id, str) or not run_id or len(run_id) > 160
                or not isinstance(source_commit_sha, str) or not _GIT_SHA.fullmatch(source_commit_sha)):
            raise CycleControlHold("cycle_claim_scope_invalid")
        claims, audits = _cycle_history(state.events)
        if any(entry["run_id"] == run_id for entry in claims):
            raise CycleControlHold("cycle_run_id_reused")
        expected_cycle = len(claims) + 1
        if cycle_number != expected_cycle:
            raise CycleControlHold("cycle_duplicate_or_out_of_order")
        if cycle_number == 2:
            if len(audits) != 1 or cycle1_auditor_artifact is None:
                raise CycleControlHold("cycle1_auditor_artifact_required")
            verified_artifact = _verify_auditor_artifact(
                cycle1_auditor_artifact, go=go, go_sha256=state.go_sha256,
                trusted_key=self._auditor_key, verify_github_artifact=verify_github_artifact,
                now=instant,
            )
            audit_event = audits[0]
            if (audit_event["artifact_envelope_sha256"] != verified_artifact.envelope_sha256
                    or audit_event["artifact_id"] != verified_artifact.artifact_id
                    or audit_event["artifact_archive_digest"] != verified_artifact.artifact_archive_digest
                    or audit_event["worker_run_id"] != verified_artifact.payload["worker_run_id"]):
                raise CycleControlHold("cycle1_auditor_artifact_mismatch")
        elif cycle1_auditor_artifact is not None:
            raise CycleControlHold("cycle1_claim_cannot_include_prior_audit")
        status_digest = _sha256(canonical_json(revocation_envelope))
        event = {
            "event": "CYCLE_CLAIMED", "cycle_number": cycle_number,
            "run_id": run_id, "go_sha256": state.go_sha256,
            "revocation_sequence": revocation["sequence"],
            "revocation_digest": status_digest,
            "claimed_at": _format_utc(instant),
            "source_commit_sha": source_commit_sha,
        }
        return self._append(state, current, event)

    def verify_worker_claim(self, *, candidate, go, receipt, manifest,
                            expected_cycle, expected_run_id, expected_execution_sha,
                            github_read_token, now=None, github_opener=None):
        """Read-only receipt verification; only Worker claim_cycle writes CAS.

        Expected run identity comes from the trusted execution adapter, never the
        receipt itself. Completed Worker provenance is required before publishing.
        The receipt is a projection of the state returned by claim_cycle.
        """
        from github_worker_provenance import verify_worker_artifact_provenance
        state, _stored = self._load_for_go(candidate, go)
        instant = _now(now)
        status = _verify_revocation_status(
            _current_revocation(state.events), go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant)
        if status["status"] != "ACTIVE" or not go.not_before <= instant < go.expires_at:
            raise CycleControlHold("claim_receipt_go_inactive")
        if type(expected_cycle) is not int or expected_cycle not in (1, 2):
            raise CycleControlHold("claim_receipt_cycle_invalid")
        identity = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)-cycle-([12])", expected_run_id or "")
        if identity is None or int(identity.group(3)) != expected_cycle:
            raise CycleControlHold("claim_receipt_expected_run_invalid")
        if not isinstance(expected_execution_sha, str) or not _GIT_SHA.fullmatch(expected_execution_sha):
            raise CycleControlHold("claim_receipt_revision_invalid")
        claims, _audits = _cycle_history(state.events)
        if (len(claims) != expected_cycle
                or len({p["run_id"] for p in claims}) != len(claims)
                or [p["cycle_number"] for p in claims] != list(range(1, expected_cycle + 1))):
            raise CycleControlHold("claim_receipt_duplicate_or_order_invalid")
        claim = claims[-1]
        if (claim["run_id"] != expected_run_id or claim["source_commit_sha"] != expected_execution_sha
                or claim["go_sha256"] != state.go_sha256):
            raise CycleControlHold("claim_receipt_scope_mismatch")
        expected = {"repository_id": REPOSITORY_ID, "cycle": expected_cycle,
                    "run_id": expected_run_id, "source_commit_sha": expected_execution_sha,
                    "go_sha256": state.go_sha256, "journal_sequence": state.sequence,
                    "journal_head_sha256": state.head_sha256, "journal_version": state.version}
        if not isinstance(receipt, Mapping) or dict(receipt) != expected:
            raise CycleControlHold("claim_receipt_journal_mismatch")
        kwargs = {} if github_opener is None else {"opener": github_opener}
        proof = verify_worker_artifact_provenance(
            manifest, expected_run_id=identity.group(1), expected_base_sha=go.base_sha,
            expected_execution_sha=expected_execution_sha, expected_cycle=expected_cycle,
            bearer_token=github_read_token, **kwargs)
        return VerifiedWorkerClaim(expected_cycle, expected_run_id, expected_execution_sha,
            state.go_sha256, state.sequence, state.head_sha256,
            _sha256(canonical_json(proof)), _CLAIM_RECEIPT_SEAL)

    def verify_historical_cycle1_claim(self, *, candidate, go, receipt, manifest,
                                       expected_run_id, expected_execution_sha,
                                       github_read_token, now=None, github_opener=None):
        """Re-verify Cycle 1 provenance against its immutable claim event after Cycle 2.

        The journal event, not the historical CAS ETag, is authoritative for the
        old claim. The receipt's original version is required as a schema field but
        cannot be compared with the current CAS version after later appends.
        """
        from github_worker_provenance import verify_worker_artifact_provenance

        state, _stored = self._load_for_go(candidate, go)
        instant = _now(now)
        status = _verify_revocation_status(
            _current_revocation(state.events), go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant,
        )
        if status["status"] != "ACTIVE" or not go.not_before <= instant < go.expires_at:
            raise CycleControlHold("historical_claim_go_inactive")
        if (not isinstance(expected_run_id, str)
                or re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)-cycle-1", expected_run_id) is None
                or not isinstance(expected_execution_sha, str)
                or not _GIT_SHA.fullmatch(expected_execution_sha)):
            raise CycleControlHold("historical_claim_expected_identity_invalid")

        claims, audits = _cycle_history(state.events)
        if (len(claims) not in (1, 2) or not audits
                or claims[0].get("cycle_number") != 1
                or claims[0].get("run_id") != expected_run_id
                or claims[0].get("source_commit_sha") != expected_execution_sha
                or claims[0].get("go_sha256") != state.go_sha256):
            raise CycleControlHold("historical_claim_journal_binding_mismatch")
        event = next((item for item in state.events
                      if item["payload"].get("event") == "CYCLE_CLAIMED"
                      and item["payload"].get("cycle_number") == 1), None)
        if event is None:
            raise CycleControlHold("historical_claim_event_missing")
        expected = {
            "repository_id": REPOSITORY_ID, "cycle": 1,
            "run_id": expected_run_id,
            "source_commit_sha": expected_execution_sha,
            "go_sha256": state.go_sha256,
            "journal_sequence": event["sequence"],
            "journal_head_sha256": event["event_sha256"],
        }
        if (not isinstance(receipt, Mapping)
                or set(receipt) != {*expected, "journal_version"}
                or any(receipt.get(key) != value for key, value in expected.items())
                or not isinstance(receipt.get("journal_version"), str)
                or not receipt["journal_version"]):
            raise CycleControlHold("historical_claim_receipt_mismatch")

        identity = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)-cycle-1", expected_run_id)
        kwargs = {} if github_opener is None else {"opener": github_opener}
        try:
            proof = verify_worker_artifact_provenance(
                manifest, expected_run_id=identity.group(1),
                expected_base_sha=go.base_sha,
                expected_execution_sha=expected_execution_sha, expected_cycle=1,
                bearer_token=github_read_token, **kwargs,
            )
        except Exception:
            raise CycleControlHold("historical_worker_provenance_unverified") from None
        return VerifiedWorkerClaim(
            cycle=1, run_id=expected_run_id,
            source_commit_sha=expected_execution_sha, go_sha256=state.go_sha256,
            journal_sequence=event["sequence"],
            journal_head_sha256=event["event_sha256"],
            worker_provenance_sha256=_sha256(canonical_json(proof)),
            _seal=_CLAIM_RECEIPT_SEAL,
        )

    def verify_stage_audit(self, *, candidate, go, claim, artifact, previous,
                           verify_github_artifact, read_verified_publication, now=None):
        """Bind the signed audit to the CAS claim and independently read publication evidence.

        The protected reader must verify the exact Draft PR, CI, candidate bytes and
        signed Permit/Witness against the Permit journal, and return matched fields.
        """
        if not is_verified_worker_claim(claim) or not callable(read_verified_publication):
            raise CycleControlHold("stage_audit_input_missing")
        state, _ = self._load_for_go(candidate, go)
        instant = _now(now)
        status = _verify_revocation_status(
            _current_revocation(state.events), go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant)
        if status["status"] != "ACTIVE" or not go.not_before <= instant < go.expires_at:
            raise CycleControlHold("stage_audit_go_inactive")
        claims, audits = _cycle_history(state.events)
        if (claim.go_sha256 != state.go_sha256 or len(claims) != claim.cycle
                or claims[-1]["run_id"] != claim.run_id
                or not 1 <= claim.journal_sequence <= state.sequence
                or state.events[claim.journal_sequence - 1]["event_sha256"] != claim.journal_head_sha256):
            raise CycleControlHold("stage_audit_claim_mismatch")
        verified = _verify_auditor_artifact(
            artifact, go=go, go_sha256=state.go_sha256, trusted_key=self._auditor_key,
            verify_github_artifact=verify_github_artifact, now=instant, cycle=claim.cycle)
        payload = verified.payload
        if claim.cycle == 2 and (not re.fullmatch(r"[1-9][0-9]*", payload["workflow_run_id"])
                or payload["auditor_run_id"] != f'{payload["workflow_run_id"]}:{payload["run_attempt"]}:auditor'
                or payload["workflow_run_id"] == claim.run_id.split("-", 1)[0]):
            raise CycleControlHold("stage_audit_attempt_identity_mismatch")
        if payload["worker_run_id"] != claim.run_id or payload["source_commit_sha"] != claim.source_commit_sha:
            raise CycleControlHold("stage_audit_run_mismatch")
        prior = None
        if claim.cycle == 1:
            if previous is not None or len(audits) != 1 or audits[0]["artifact_envelope_sha256"] != verified.envelope_sha256:
                raise CycleControlHold("stage_audit_cycle1_journal_mismatch")
        else:
            if (not isinstance(previous, VerifiedStageAudit) or previous._seal is not _EVIDENCE_SEAL
                    or previous.claim.cycle != 1 or previous.claim.go_sha256 != claim.go_sha256
                    or previous.claim.run_id != claims[0]["run_id"]
                    or len(audits) != 1 or audits[0]["artifact_envelope_sha256"] != previous.envelope_sha256
                    or payload["cycle1_audit_sha256"] != previous.envelope_sha256
                    or payload["workflow_run_id"] == previous.workflow_run_id
                    or payload["permit_id"] == previous.permit_id
                    or payload["readonly_ci_run_id"] == previous.ci_run_id):
                raise CycleControlHold("stage_audit_cycle1_binding_mismatch")
            prior = previous.envelope_sha256
        fields = ("worker_run_id", "go_sha256", "pr_number", "pr_head_sha", "pr_base_sha",
                  "pr_state", "pr_is_draft", "pr_merged", "readonly_ci_run_id", "readonly_ci_conclusion",
                  "permit_id", "candidate_digest", "witness_digest", "journal_revision", "journal_head_sha256")
        expected = {key: payload[key] for key in fields}
        if claim.cycle == 2:
            expected["permit_sha256"] = payload["permit_sha256"]
        readback = read_verified_publication(claim, payload)
        if not isinstance(readback, Mapping) or canonical_json(dict(readback)) != canonical_json(expected):
            raise CycleControlHold("stage_audit_publication_unverified")
        return VerifiedStageAudit(claim, verified.envelope_sha256, prior,
                                  payload["workflow_run_id"], payload["run_attempt"],
                                  _parse_utc(payload["issued_at"]), _parse_utc(payload["expires_at"]),
                                  self._auditor_key.public_key, payload["permit_id"],
                                  payload["readonly_ci_run_id"], _EVIDENCE_SEAL)

    def record_cycle1_auditor_pass(self, *, candidate: object, go: VerifiedF4Go,
                                   artifact: object,
                                   verify_github_artifact: Callable[[Mapping[str, object]], object] | None,
                                   now: datetime | None = None) -> CycleControlState:
        state, current = self._load_for_go(candidate, go)
        instant = _now(now)
        revocation = _verify_revocation_status(
            _current_revocation(state.events), go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant,
        )
        if revocation["status"] != "ACTIVE" or instant >= go.expires_at:
            raise CycleControlHold("f4_go_revoked_or_expired_before_audit")
        claims, audits = _cycle_history(state.events)
        if len(claims) != 1 or claims[0]["cycle_number"] != 1:
            raise CycleControlHold("cycle1_claim_missing_or_cycle2_already_started")
        if audits:
            raise CycleControlHold("cycle1_auditor_evidence_replayed")
        verified = _verify_auditor_artifact(
            artifact, go=go, go_sha256=state.go_sha256,
            trusted_key=self._auditor_key,
            verify_github_artifact=verify_github_artifact, now=instant,
        )
        payload = verified.payload
        if (payload["worker_run_id"] != claims[0]["run_id"]
                or payload["source_commit_sha"] != claims[0]["source_commit_sha"]):
            raise CycleControlHold("cycle1_auditor_evidence_run_mismatch")
        event = {
            "event": "CYCLE1_AUDITOR_PASS",
            "artifact_envelope_sha256": verified.envelope_sha256,
            "artifact_id": verified.artifact_id,
            "artifact_archive_digest": verified.artifact_archive_digest,
            "workflow_run_id": payload["workflow_run_id"],
            "run_attempt": payload["run_attempt"],
            "worker_run_id": payload["worker_run_id"],
            "auditor_run_id": payload["auditor_run_id"],
            "source_commit_sha": payload["source_commit_sha"],
            "auditor_envelope": artifact,
        }
        return self._append(state, current, event)

    def rehydrate_cycle1_stage_audit(self, *, candidate: object, go: VerifiedF4Go,
                                     verify_github_artifact: Callable[[Mapping[str, object]], object] | None,
                                     claim: VerifiedWorkerClaim,
                                     now: datetime | None = None) -> VerifiedStageAudit:
        """Rebuild the sealed Cycle 1 audit only from the authenticated CAS record.

        This supports a later, separate Cycle 2 invocation. The signed envelope,
        its exact CAS event, the hash-chained Cycle 1 claim, current GO/revocation,
        and the original completed GitHub artifact metadata must all still verify.
        It performs no CAS writes and does not pretend an expired artifact remains
        valid.
        """
        if getattr(verify_github_artifact, "_allow_in_progress", False) is True:
            raise CycleControlHold("cycle1_rehydrate_requires_completed_artifact_reader")
        state, _stored = self._load_for_go(candidate, go)
        instant = _now(now)
        revocation = _verify_revocation_status(
            _current_revocation(state.events), go=go, go_sha256=state.go_sha256,
            trusted_keys=self._owner_keys, now=instant,
        )
        if (revocation["status"] != "ACTIVE" or not go.not_before <= instant < go.expires_at):
            raise CycleControlHold("cycle1_rehydrate_go_inactive")

        claims, audits = _cycle_history(state.events)
        if (not claims or claims[0].get("cycle_number") != 1
                or len(claims) not in (1, 2)
                or [item.get("cycle_number") for item in claims] != list(range(1, len(claims) + 1))
                or len(audits) != 1):
            raise CycleControlHold("cycle1_rehydrate_journal_state_invalid")

        claim_event = next((event for event in state.events
                            if event["payload"].get("event") == "CYCLE_CLAIMED"
                            and event["payload"].get("cycle_number") == 1), None)
        audit_event = next((event for event in state.events
                            if event["payload"].get("event") == "CYCLE1_AUDITOR_PASS"), None)
        if claim_event is None or audit_event is None:
            raise CycleControlHold("cycle1_rehydrate_events_missing")
        recorded = audit_event["payload"]
        envelope = recorded.get("auditor_envelope")
        verified = _verify_auditor_artifact(
            envelope, go=go, go_sha256=state.go_sha256,
            trusted_key=self._auditor_key,
            verify_github_artifact=verify_github_artifact, now=instant, cycle=1,
        )
        payload = verified.payload
        claim_payload = claim_event["payload"]
        if (verified.envelope_sha256 != recorded.get("artifact_envelope_sha256")
                or verified.artifact_id != recorded.get("artifact_id")
                or verified.artifact_archive_digest != recorded.get("artifact_archive_digest")
                or payload.get("workflow_run_id") != recorded.get("workflow_run_id")
                or payload.get("run_attempt") != recorded.get("run_attempt")
                or payload.get("worker_run_id") != recorded.get("worker_run_id")
                or payload.get("auditor_run_id") != recorded.get("auditor_run_id")
                or payload.get("source_commit_sha") != recorded.get("source_commit_sha")
                or payload.get("worker_run_id") != claim_payload.get("run_id")
                or payload.get("source_commit_sha") != claim_payload.get("source_commit_sha")
                or claim_payload.get("go_sha256") != state.go_sha256):
            raise CycleControlHold("cycle1_rehydrate_record_binding_mismatch")

        if (not is_verified_worker_claim(claim) or claim.cycle != 1
                or claim.run_id != claim_payload["run_id"]
                or claim.source_commit_sha != claim_payload["source_commit_sha"]
                or claim.go_sha256 != state.go_sha256
                or claim.journal_sequence != claim_event["sequence"]
                or claim.journal_head_sha256 != claim_event["event_sha256"]):
            raise CycleControlHold("cycle1_rehydrate_claim_receipt_mismatch")
        return VerifiedStageAudit(
            claim=claim, envelope_sha256=verified.envelope_sha256,
            previous_sha256=None, workflow_run_id=payload["workflow_run_id"],
            run_attempt=payload["run_attempt"], observed_after=_parse_utc(payload["issued_at"]),
            expires_at=_parse_utc(payload["expires_at"]),
            auditor_public_key=self._auditor_key.public_key,
            permit_id=payload["permit_id"], ci_run_id=payload["readonly_ci_run_id"],
            _seal=_EVIDENCE_SEAL,
        )

    def read(self) -> CycleControlState | None:
        try:
            stored = self._backend.read(CONTROL_KEY)
        except CasHold:
            raise CycleControlHold("cycle_control_read_unavailable") from None
        return None if stored is None else self._decode(stored)

    def _load_for_go(self, candidate: object, go: VerifiedF4Go
                     ) -> tuple[CycleControlState, CasValue]:
        go_sha = _go_sha(candidate, go)
        try:
            stored = self._backend.read(CONTROL_KEY)
        except CasHold:
            raise CycleControlHold("cycle_control_read_unavailable") from None
        if stored is None:
            raise CycleControlHold("cycle_control_not_initialized")
        state = self._decode(stored)
        if (state.approval_id != go.approval_id or state.go_sha256 != go_sha
                or state.base_sha != go.base_sha):
            raise CycleControlHold("cycle_control_go_binding_mismatch")
        return state, stored

    def _append(self, state: CycleControlState, current: CasValue,
                payload: dict[str, object]) -> CycleControlState:
        event_body = {
            "sequence": state.sequence + 1,
            "previous_sha256": state.head_sha256,
            "payload": payload,
        }
        digest = _sha256(canonical_json(event_body))
        event = {**event_body, "event_sha256": digest}
        events = [*state.events, event]
        revocation_sequence = state.revocation_sequence
        if payload.get("event") == "REVOCATION_STATUS":
            next_status = payload.get("revocation_status")
            next_payload = next_status.get("payload") if isinstance(next_status, Mapping) else None
            if not isinstance(next_payload, Mapping) or not isinstance(next_payload.get("sequence"), int):
                raise CycleControlHold("revocation_status_sequence_invalid")
            revocation_sequence = next_payload["sequence"]
        document = {
            "schema": 1, "repository_id": REPOSITORY_ID,
            "approval_id": state.approval_id, "go_sha256": state.go_sha256,
            "base_sha": state.base_sha,
            "go_revocation_sequence": state.go_revocation_sequence,
            "revocation_sequence": revocation_sequence,
            "sequence": len(events),
            "head_sha256": digest, "events": events,
        }
        try:
            version = self._backend.compare_and_swap(
                CONTROL_KEY, current.version, canonical_json(document),
            )
        except CasConflict:
            raise CycleControlHold("cycle_control_cas_conflict_no_retry") from None
        except CasHold:
            raise CycleControlHold("cycle_control_cas_unavailable_no_retry") from None
        return self._decode(CasValue(canonical_json(document), version))

    @staticmethod
    def _decode(stored: CasValue) -> CycleControlState:
        try:
            import json
            document = json.loads(stored.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, TypeError):
            raise CycleControlHold("cycle_control_document_invalid") from None
        required = {
            "schema", "repository_id", "approval_id", "go_sha256", "base_sha",
            "go_revocation_sequence", "revocation_sequence", "sequence", "head_sha256", "events",
        }
        if (not isinstance(document, dict) or set(document) != required
                or document["schema"] != 1 or document["repository_id"] != REPOSITORY_ID
                or not isinstance(document["approval_id"], str)
                or not isinstance(document["go_sha256"], str) or not _SHA256.fullmatch(document["go_sha256"])
                or not isinstance(document["base_sha"], str) or not _GIT_SHA.fullmatch(document["base_sha"])
                or isinstance(document["go_revocation_sequence"], bool)
                or not isinstance(document["go_revocation_sequence"], int)
                or document["go_revocation_sequence"] < 1
                or isinstance(document["revocation_sequence"], bool)
                or not isinstance(document["revocation_sequence"], int)
                or document["revocation_sequence"] < 1
                or not isinstance(document["events"], list)):
            raise CycleControlHold("cycle_control_document_scope_invalid")
        previous = "0" * 64
        for index, event in enumerate(document["events"], 1):
            if (not isinstance(event, dict) or set(event) != {
                    "sequence", "previous_sha256", "payload", "event_sha256"}
                    or event["sequence"] != index or event["previous_sha256"] != previous
                    or not isinstance(event["payload"], dict)):
                raise CycleControlHold("cycle_control_event_chain_invalid")
            event_type = event["payload"].get("event")
            if event_type not in _EVENT_FIELDS or set(event["payload"]) != _EVENT_FIELDS[event_type]:
                raise CycleControlHold("cycle_control_event_shape_invalid")
            body = {key: event[key] for key in ("sequence", "previous_sha256", "payload")}
            digest = _sha256(canonical_json(body))
            if event["event_sha256"] != digest:
                raise CycleControlHold("cycle_control_event_digest_mismatch")
            previous = digest
        if (not document["events"] or document["sequence"] != len(document["events"])
                or document["head_sha256"] != previous):
            raise CycleControlHold("cycle_control_head_mismatch")
        _validate_event_transitions(document["events"], document)
        return CycleControlState(
            approval_id=document["approval_id"], go_sha256=document["go_sha256"],
            base_sha=document["base_sha"],
            go_revocation_sequence=document["go_revocation_sequence"],
            revocation_sequence=document["revocation_sequence"],
            sequence=document["sequence"],
            head_sha256=previous, version=stored.version,
            events=tuple(document["events"]),
        )


class GitHubArtifactProvenanceReader:
    """Read-only verifier for exact run/artifact provenance; in-progress is opt-in for its own Auditor job."""

    def __init__(self, *, bearer_token: str, timeout: float = 5.0,
                 opener: Callable[..., object] = urlopen,
                 allow_in_progress: bool = False) -> None:
        if not bearer_token or timeout <= 0:
            raise ValueError("read-only GitHub credential and positive timeout are required")
        self._token = bearer_token
        self._timeout = timeout
        self._opener = opener
        self._allow_in_progress = allow_in_progress

    def __call__(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        run_id = payload.get("workflow_run_id")
        if not isinstance(run_id, str) or not run_id.isdigit():
            raise CycleControlHold("github_artifact_run_id_invalid")
        run = self._get_json(
            f"/repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}",
        )
        artifacts = self._get_json(
            f"/repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}/artifacts",
        )
        repository = run.get("repository") if isinstance(run, Mapping) else None
        if (not isinstance(run, Mapping) or not isinstance(repository, Mapping)
                or repository.get("id") != REPOSITORY_ID
                or run.get("id") != int(run_id)
                or run.get("run_attempt") != payload.get("run_attempt")
                or run.get("path") != AUDIT_WORKFLOW_PATH
                or run.get("head_sha") != payload.get("source_commit_sha")
                or not (run.get("status") == "completed" and run.get("conclusion") == "success"
                        or self._allow_in_progress and run.get("status") == "in_progress"
                           and run.get("conclusion") is None)
                or not isinstance(artifacts, Mapping)
                or not isinstance(artifacts.get("artifacts"), list)):
            raise CycleControlHold("github_artifact_workflow_run_mismatch")
        name = CYCLE2_AUDIT_ARTIFACT_NAME if payload.get("cycle_number") == 2 else AUDIT_ARTIFACT_NAME
        matches = [item for item in artifacts["artifacts"]
                   if isinstance(item, Mapping) and item.get("name") == name]
        if len(matches) != 1:
            raise CycleControlHold("github_artifact_missing_or_duplicated")
        artifact = matches[0]
        linked_run = artifact.get("workflow_run")
        if (not isinstance(linked_run, Mapping)
                or linked_run.get("id") != int(run_id)
                or artifact.get("expired") is not False
                or not isinstance(artifact.get("id"), int)
                or isinstance(artifact.get("id"), bool)
                or not isinstance(artifact.get("digest"), str)):
            raise CycleControlHold("github_artifact_metadata_invalid")
        return {
            "repository_id": REPOSITORY_ID,
            "workflow_run_id": run_id,
            "run_attempt": payload["run_attempt"],
            "workflow_path": AUDIT_WORKFLOW_PATH,
            "source_commit_sha": payload["source_commit_sha"],
            "artifact_name": name,
            "artifact_id": artifact["id"],
            "archive_digest": artifact["digest"],
            "expired": artifact["expired"],
        }

    def read_cycle2_archive(self, archive: bytes, *, run_id: str, attempt: int,
                            execution_sha: str):
        """Bind an existing Actions ZIP to the exact completed run and signed envelope."""
        if self._allow_in_progress or not isinstance(archive, bytes) or len(archive) > 2 * 1024 * 1024:
            raise CycleControlHold("cycle2_archive_input_invalid")
        try:
            with ZipFile(io.BytesIO(archive)) as bundle:
                entries = bundle.infolist()
                if (len(entries) != 1 or entries[0].filename != "auditor-envelope.json"
                        or entries[0].file_size > 2 * 1024 * 1024):
                    raise ValueError
                envelope = json.loads(bundle.read(entries[0]))
            payload = envelope["payload"]
            _validate_audit_payload(payload, cycle=2)
            if (payload["workflow_run_id"] != run_id or payload["run_attempt"] != attempt
                    or payload["source_commit_sha"] != execution_sha):
                raise ValueError
        except (BadZipFile, KeyError, ValueError, TypeError, RuntimeError, OSError):
            raise CycleControlHold("cycle2_archive_envelope_invalid") from None
        proof = self(payload)
        if proof["archive_digest"] != "sha256:" + _sha256(archive):
            raise CycleControlHold("cycle2_archive_digest_mismatch")
        pinned_payload = canonical_json(payload)

        def verify(value):
            if canonical_json(value) != pinned_payload:
                raise CycleControlHold("cycle2_archive_payload_mismatch")
            return dict(proof)

        return envelope, verify

    def _get_json(self, path: str) -> object:
        request = Request(
            "https://api.github.com" + path,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with self._opener(request, timeout=self._timeout) as response:
                if getattr(response, "status", None) != 200:
                    raise CycleControlHold("github_artifact_read_rejected")
                import json
                return json.loads(response.read().decode("utf-8"))
        except CycleControlHold:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, ValueError, TypeError):
            raise CycleControlHold("github_artifact_read_unavailable") from None


def build_cycle1_auditor_artifact(*, payload: Mapping[str, object], key_id: str,
                                  private_key: object) -> dict[str, object]:
    """Sign a validated Auditor artifact using a caller-owned key; never creates keys."""
    _validate_audit_payload(payload)
    if not isinstance(key_id, str) or not key_id:
        raise CycleControlHold("auditor_signing_key_id_missing")
    try:
        signature = private_key.sign(canonical_json(dict(payload)))
    except Exception:
        raise CycleControlHold("auditor_signing_operation_failed") from None
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise CycleControlHold("auditor_signature_invalid")
    return {
        "key_id": key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
        "payload": dict(payload),
    }


def _verify_auditor_artifact(artifact: object, *, go: VerifiedF4Go, go_sha256: str,
                             trusted_key: TrustedVerificationKey,
                             verify_github_artifact: Callable[[Mapping[str, object]], object] | None,
                             now: datetime, cycle: int = 1) -> VerifiedAuditorArtifact:
    if (not isinstance(artifact, dict) or set(artifact) != _ENVELOPE_KEYS
            or artifact.get("key_id") != trusted_key.key_id
            or not isinstance(artifact.get("signature"), str)):
        raise CycleControlHold("cycle1_auditor_signature_missing_or_wrong_key")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        raise CycleControlHold("cycle1_auditor_payload_invalid")
    _validate_audit_payload(payload, cycle)
    if (payload["repository_id"] != go.repository_id
            or payload["approval_id"] != go.approval_id
            or payload["go_sha256"] != go_sha256
            or payload["cycle_number"] != cycle
            or payload["base_sha"] != go.base_sha):
        raise CycleControlHold("cycle1_auditor_scope_mismatch")
    issued = _parse_utc(payload["issued_at"])
    expires = _parse_utc(payload["expires_at"])
    if expires <= issued or now < issued or now >= expires or expires > go.expires_at:
        raise CycleControlHold("cycle1_auditor_artifact_expired_or_clock_invalid")
    try:
        signature = base64.b64decode(artifact["signature"], validate=True)
    except (binascii.Error, ValueError):
        raise CycleControlHold("cycle1_auditor_signature_encoding_invalid") from None
    try:
        _verify_ed25519(trusted_key.public_key, signature, canonical_json(payload))
    except Exception:
        raise CycleControlHold("cycle1_auditor_signature_invalid") from None
    if verify_github_artifact is None:
        raise CycleControlHold("github_artifact_provenance_verifier_missing")
    try:
        provenance = verify_github_artifact(payload)
    except Exception:
        provenance = None
    required = {
        "repository_id", "workflow_run_id", "run_attempt", "workflow_path",
        "source_commit_sha", "artifact_name", "artifact_id", "archive_digest",
        "expired",
    }
    if (not isinstance(provenance, Mapping) or set(provenance) != required
            or provenance.get("repository_id") != go.repository_id
            or provenance.get("workflow_run_id") != payload["workflow_run_id"]
            or provenance.get("run_attempt") != payload["run_attempt"]
            or provenance.get("workflow_path") != AUDIT_WORKFLOW_PATH
            or provenance.get("source_commit_sha") != payload["source_commit_sha"]
            or provenance.get("artifact_name") != (CYCLE2_AUDIT_ARTIFACT_NAME if cycle == 2 else AUDIT_ARTIFACT_NAME)
            or isinstance(provenance.get("artifact_id"), bool)
            or not isinstance(provenance.get("artifact_id"), int)
            or provenance.get("artifact_id") <= 0
            or not isinstance(provenance.get("archive_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", provenance["archive_digest"])
            or provenance.get("expired") is not False):
        raise CycleControlHold("github_artifact_provenance_invalid")
    return VerifiedAuditorArtifact(
        payload=payload,
        envelope_sha256=_sha256(canonical_json(artifact)),
        artifact_id=provenance["artifact_id"],
        artifact_archive_digest=provenance["archive_digest"],
    )


def _validate_audit_payload(payload: Mapping[str, object], cycle: int = 1) -> None:
    if (set(payload) != (_AUDIT_PAYLOAD_KEYS | (_CYCLE2_AUDIT_FIELDS if cycle == 2 else set()))
            or payload.get("schema") != (2 if cycle == 2 else 1)
            or payload.get("kind") != "F4_CYCLE_AUDIT"
            or payload.get("repository_id") != REPOSITORY_ID
            or type(payload.get("cycle_number")) is not int or payload["cycle_number"] != cycle
            or payload.get("result") != "PASS"
            or payload.get("pr_number") != 1
            or payload.get("pr_state") != "open"
            or payload.get("pr_is_draft") is not True
            or payload.get("pr_merged") is not False
            or payload.get("readonly_ci_conclusion") != "success"
            or payload.get("workflow_path") != AUDIT_WORKFLOW_PATH
            or not isinstance(payload.get("approval_id"), str) or not payload["approval_id"]
            or not isinstance(payload.get("worker_run_id"), str) or not payload["worker_run_id"]
            or not isinstance(payload.get("auditor_run_id"), str) or not payload["auditor_run_id"]
            or payload.get("worker_run_id") == payload.get("auditor_run_id")
            or not isinstance(payload.get("workflow_run_id"), str) or not payload["workflow_run_id"]
            or isinstance(payload.get("run_attempt"), bool)
            or not isinstance(payload.get("run_attempt"), int) or payload["run_attempt"] < 1
            or not isinstance(payload.get("source_commit_sha"), str)
            or not _GIT_SHA.fullmatch(payload["source_commit_sha"])
            or not isinstance(payload.get("pr_head_sha"), str)
            or not _GIT_SHA.fullmatch(payload["pr_head_sha"])
            or payload.get("pr_base_sha") != payload.get("base_sha")
            or not isinstance(payload.get("base_sha"), str) or not _GIT_SHA.fullmatch(payload["base_sha"])
            or not isinstance(payload.get("readonly_ci_run_id"), str) or not payload["readonly_ci_run_id"]
            or not isinstance(payload.get("permit_id"), str) or not payload["permit_id"]
            or not isinstance(payload.get("candidate_digest"), str) or not _SHA256.fullmatch(payload["candidate_digest"])
            or not isinstance(payload.get("witness_digest"), str) or not _SHA256.fullmatch(payload["witness_digest"])
            or isinstance(payload.get("journal_revision"), bool)
            or not isinstance(payload.get("journal_revision"), int) or payload["journal_revision"] < 1
            or not isinstance(payload.get("journal_head_sha256"), str)
            or not _SHA256.fullmatch(payload["journal_head_sha256"])
            or not isinstance(payload.get("go_sha256"), str) or not _SHA256.fullmatch(payload["go_sha256"])):
        raise CycleControlHold("cycle1_auditor_payload_scope_invalid")
    if cycle == 2 and any(not isinstance(payload[key], str) or not _SHA256.fullmatch(payload[key])
                          for key in _CYCLE2_AUDIT_FIELDS):
        raise CycleControlHold("cycle2_auditor_digest_invalid")
    _parse_utc(payload.get("issued_at"))
    _parse_utc(payload.get("expires_at"))


def _verify_revocation_status(status: object, *, go: VerifiedF4Go, go_sha256: str,
                              trusted_keys: Mapping[str, TrustedVerificationKey],
                              now: datetime | None = None) -> Mapping[str, object]:
    if not isinstance(status, Mapping) or set(status) != _REVOCATION_KEYS:
        raise CycleControlHold("revocation_envelope_missing_or_invalid")
    payload, approvals = status["payload"], status["approvals"]
    if (not isinstance(payload, Mapping) or set(payload) != _REVOCATION_PAYLOAD_KEYS
            or payload.get("schema") != 1 or payload.get("kind") != "F4_REVOCATION_STATUS"
            or payload.get("repository_id") != go.repository_id
            or payload.get("approval_id") != go.approval_id
            or payload.get("go_sha256") != go_sha256
            or isinstance(payload.get("sequence"), bool)
            or not isinstance(payload.get("sequence"), int) or payload["sequence"] < 1
            or payload.get("status") not in {"ACTIVE", "REVOKED", "STOPPED"}):
        raise CycleControlHold("revocation_status_scope_invalid")
    valid_from, valid_until = _parse_utc(payload["valid_from"]), _parse_utc(payload["valid_until"])
    instant = _now(now)
    if valid_until <= valid_from or instant < valid_from or instant >= valid_until:
        raise CycleControlHold("revocation_status_expired_or_not_yet_valid")
    if valid_until > go.expires_at:
        raise CycleControlHold("revocation_status_exceeds_go_expiry")
    if not isinstance(approvals, Mapping) or set(approvals) != {"owner_a", "owner_b"}:
        raise CycleControlHold("revocation_owner_signatures_missing")
    signature_keys: list[TrustedVerificationKey] = []
    for role in ("owner_a", "owner_b"):
        envelope = approvals[role]
        if (not isinstance(envelope, Mapping) or set(envelope) != _ENVELOPE_KEYS
                or envelope.get("payload") != payload or not isinstance(envelope.get("key_id"), str)
                or not isinstance(envelope.get("signature"), str)):
            raise CycleControlHold("revocation_owner_envelope_invalid")
        key = trusted_keys.get(envelope["key_id"])
        if key is None or key.role != role or key.key_id != envelope["key_id"] or len(key.public_key) != 32:
            raise CycleControlHold("revocation_owner_trust_key_invalid")
        try:
            signature = base64.b64decode(envelope["signature"], validate=True)
            _verify_ed25519(key.public_key, signature, canonical_json(dict(payload)))
        except Exception:
            raise CycleControlHold("revocation_owner_signature_invalid") from None
        signature_keys.append(key)
    if signature_keys[0].public_key == signature_keys[1].public_key:
        raise CycleControlHold("revocation_owner_keys_not_independent")
    return payload


def _empty_document(go: VerifiedF4Go, go_sha: str, revocation_status: object) -> dict[str, object]:
    body = {
        "sequence": 1, "previous_sha256": "0" * 64,
        "payload": {"event": "CONTROL_CREATED", "revocation_status": revocation_status},
    }
    digest = _sha256(canonical_json(body))
    event = {**body, "event_sha256": digest}
    return {
        "schema": 1, "repository_id": REPOSITORY_ID,
        "approval_id": go.approval_id, "go_sha256": go_sha,
        "base_sha": go.base_sha,
        "go_revocation_sequence": go.revocation_sequence,
        "revocation_sequence": go.revocation_sequence,
        "sequence": 1,
        "head_sha256": digest, "events": [event],
    }


def _validate_event_transitions(events: list[dict[str, object]], document: Mapping[str, object]) -> None:
    if events[0]["payload"].get("event") != "CONTROL_CREATED":
        raise CycleControlHold("cycle_control_initial_event_invalid")
    claims: list[dict[str, object]] = []
    audits: list[dict[str, object]] = []
    status = events[0]["payload"].get("revocation_status")
    status_payload = status.get("payload") if isinstance(status, Mapping) else None
    if (not isinstance(status_payload, Mapping)
            or status_payload.get("status") != "ACTIVE"
            or status_payload.get("sequence") != document["go_revocation_sequence"]
            or status_payload.get("approval_id") != document["approval_id"]
            or status_payload.get("go_sha256") != document["go_sha256"]):
        raise CycleControlHold("cycle_control_initial_revocation_invalid")
    for event in events[1:]:
        payload = event["payload"]
        kind = payload["event"]
        if kind == "REVOCATION_STATUS":
            next_status = payload["revocation_status"]
            next_payload = next_status.get("payload") if isinstance(next_status, Mapping) else None
            current_status_payload = status.get("payload") if isinstance(status, Mapping) else None
            if (not isinstance(next_payload, Mapping) or not isinstance(current_status_payload, Mapping)
                    or current_status_payload.get("status") != "ACTIVE"
                    or next_payload.get("status") not in {"REVOKED", "STOPPED"}
                    or next_payload.get("sequence") != current_status_payload.get("sequence", 0) + 1
                    or next_payload.get("approval_id") != document["approval_id"]
                    or next_payload.get("go_sha256") != document["go_sha256"]):
                raise CycleControlHold("cycle_control_revocation_transition_invalid")
            status = next_status
        elif kind == "CYCLE_CLAIMED":
            cycle = payload.get("cycle_number")
            if (isinstance(cycle, bool) or cycle != len(claims) + 1 or cycle not in (1, 2)
                    or payload.get("go_sha256") != document["go_sha256"]
                    or not isinstance(payload.get("run_id"), str) or not payload["run_id"]
                    or not isinstance(payload.get("source_commit_sha"), str)
                    or not _GIT_SHA.fullmatch(payload["source_commit_sha"])
                    or any(claim["run_id"] == payload["run_id"] for claim in claims)):
                raise CycleControlHold("cycle_control_claim_transition_invalid")
            current_status_payload = status.get("payload") if isinstance(status, Mapping) else None
            if (not isinstance(current_status_payload, Mapping)
                    or current_status_payload.get("status") != "ACTIVE"
                    or payload.get("revocation_sequence") != current_status_payload.get("sequence")
                    or payload.get("revocation_digest") != _sha256(canonical_json(status))):
                raise CycleControlHold("cycle_control_claim_revocation_invalid")
            if cycle == 2 and (len(audits) != 1 or audits[0].get("worker_run_id") != claims[0].get("run_id")):
                raise CycleControlHold("cycle_control_cycle2_without_cycle1_audit")
            claims.append(payload)
        elif kind == "CYCLE1_AUDITOR_PASS":
            if len(claims) != 1 or claims[0].get("cycle_number") != 1 or audits:
                raise CycleControlHold("cycle_control_audit_transition_invalid")
            if (payload.get("worker_run_id") != claims[0].get("run_id")
                    or payload.get("source_commit_sha") != claims[0].get("source_commit_sha")):
                raise CycleControlHold("cycle_control_audit_claim_mismatch")
            if (isinstance(payload.get("artifact_id"), bool)
                    or not isinstance(payload.get("artifact_id"), int) or payload["artifact_id"] <= 0
                    or not isinstance(payload.get("artifact_envelope_sha256"), str)
                    or not _SHA256.fullmatch(payload["artifact_envelope_sha256"])
                    or not isinstance(payload.get("artifact_archive_digest"), str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", payload["artifact_archive_digest"])
                    or not isinstance(payload.get("workflow_run_id"), str)
                    or not isinstance(payload.get("run_attempt"), int)
                    or isinstance(payload.get("run_attempt"), bool)
                    or not isinstance(payload.get("auditor_run_id"), str)
                    or not payload["auditor_run_id"]):
                raise CycleControlHold("cycle_control_audit_event_invalid")
            audits.append(payload)
    if _revocation_sequence(status) != document["revocation_sequence"]:
        raise CycleControlHold("cycle_control_revocation_head_mismatch")


def _cycle_history(events: tuple[dict[str, object], ...]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    claims: list[dict[str, object]] = []
    audits: list[dict[str, object]] = []
    for event in events:
        payload = event["payload"]
        if payload.get("event") == "CYCLE_CLAIMED":
            claims.append(payload)
        elif payload.get("event") == "CYCLE1_AUDITOR_PASS":
            audits.append(payload)
    return claims, audits


def _current_revocation(events: tuple[dict[str, object], ...]) -> object:
    current = None
    for event in events:
        payload = event["payload"]
        if payload.get("event") in {"CONTROL_CREATED", "REVOCATION_STATUS"}:
            current = payload["revocation_status"]
    return current


def _revocation_sequence(status: object) -> object:
    return status.get("payload", {}).get("sequence") if isinstance(status, Mapping) else None


def _go_sha(candidate: object, go: VerifiedF4Go) -> str:
    try:
        return verified_f4_go_sha256(candidate, go)
    except F4GoHold as exc:
        raise CycleControlHold(exc.reason) from None


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CycleControlHold("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise CycleControlHold("timestamp_invalid") from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CycleControlHold("timestamp_invalid")
    return parsed


def _now(value: datetime | None) -> datetime:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise CycleControlHold("clock_untrusted")
    return instant.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
