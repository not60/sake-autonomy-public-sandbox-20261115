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
import re
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
        matches = [item for item in artifacts["artifacts"]
                   if isinstance(item, Mapping) and item.get("name") == AUDIT_ARTIFACT_NAME]
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
            "artifact_name": AUDIT_ARTIFACT_NAME,
            "artifact_id": artifact["id"],
            "archive_digest": artifact["digest"],
            "expired": artifact["expired"],
        }

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
                             now: datetime) -> VerifiedAuditorArtifact:
    if (not isinstance(artifact, dict) or set(artifact) != _ENVELOPE_KEYS
            or artifact.get("key_id") != trusted_key.key_id
            or not isinstance(artifact.get("signature"), str)):
        raise CycleControlHold("cycle1_auditor_signature_missing_or_wrong_key")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        raise CycleControlHold("cycle1_auditor_payload_invalid")
    _validate_audit_payload(payload)
    if (payload["repository_id"] != go.repository_id
            or payload["approval_id"] != go.approval_id
            or payload["go_sha256"] != go_sha256
            or payload["cycle_number"] != 1
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
            or provenance.get("artifact_name") != AUDIT_ARTIFACT_NAME
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


def _validate_audit_payload(payload: Mapping[str, object]) -> None:
    if (set(payload) != _AUDIT_PAYLOAD_KEYS or payload.get("schema") != 1
            or payload.get("kind") != "F4_CYCLE_AUDIT"
            or payload.get("repository_id") != REPOSITORY_ID
            or payload.get("cycle_number") != 1
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
