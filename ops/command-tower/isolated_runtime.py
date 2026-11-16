"""Local-only reference model for the public sandbox execution boundaries.

This module performs no network, filesystem, subprocess, Worker, or GitHub
operations. It models a single in-memory DRAFT_HOLD flow for unit testing; it
does not enforce OS identities or authorize real publication.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Any


SANDBOX_REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"


class Role(str, Enum):
    WORKER = "worker"
    PUBLISHER = "publisher"
    AUDITOR = "auditor"
    WITNESS = "witness"
    PERMIT_AUTHORITY = "permit_authority"


class BoundaryError(ValueError):
    """An actor or artifact violates the local sandbox policy."""


class SafeStop(RuntimeError):
    """The local runtime has stopped after a fail-closed boundary violation."""


@dataclass(frozen=True)
class Principal:
    principal_id: str
    role: Role


@dataclass(frozen=True)
class Candidate:
    repository: str
    branch: str
    paths: tuple[str, ...]
    content_digest: str

    def digest(self) -> str:
        return _digest({
            "repository": self.repository,
            "branch": self.branch,
            "paths": list(self.paths),
            "content_digest": self.content_digest,
            "state": "DRAFT_HOLD",
        })


@dataclass(frozen=True)
class Permit:
    permit_id: str
    candidate_digest: str
    repository: str
    branch: str
    paths: tuple[str, ...]
    issuer_id: str

    def digest(self) -> str:
        return _digest({
            "permit_id": self.permit_id,
            "candidate_digest": self.candidate_digest,
            "repository": self.repository,
            "branch": self.branch,
            "paths": list(self.paths),
            "issuer_id": self.issuer_id,
        })


@dataclass(frozen=True)
class WitnessAttestation:
    permit_digest: str
    witness_id: str


@dataclass(frozen=True)
class PublicationPlan:
    candidate_digest: str
    permit_digest: str
    repository: str
    branch: str
    paths: tuple[str, ...]
    state: str = "DRAFT_HOLD"


@dataclass(frozen=True)
class JournalEntry:
    sequence: int
    event: str
    payload: tuple[tuple[str, str], ...]
    previous_hash: str
    entry_hash: str


class HashJournal:
    """Append-only in-memory event chain with deterministic serialization."""

    def __init__(self) -> None:
        self._entries: list[JournalEntry] = []

    @property
    def entries(self) -> tuple[JournalEntry, ...]:
        return tuple(self._entries)

    def append(self, event: str, **payload: str) -> JournalEntry:
        if not event or any(not isinstance(k, str) or not isinstance(v, str) for k, v in payload.items()):
            raise BoundaryError("journal accepts a named event and string payload only")
        previous = self._entries[-1].entry_hash if self._entries else "0" * 64
        sequence = len(self._entries) + 1
        stable_payload = tuple(sorted(payload.items()))
        body = {
            "sequence": sequence,
            "event": event,
            "payload": list(stable_payload),
            "previous_hash": previous,
        }
        entry = JournalEntry(sequence, event, stable_payload, previous, _digest(body))
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        previous = "0" * 64
        for expected_sequence, entry in enumerate(self._entries, start=1):
            if entry.sequence != expected_sequence or entry.previous_hash != previous:
                return False
            body = {
                "sequence": entry.sequence,
                "event": entry.event,
                "payload": list(entry.payload),
                "previous_hash": entry.previous_hash,
            }
            if entry.entry_hash != _digest(body):
                return False
            previous = entry.entry_hash
        return True


class IsolatedRuntime:
    """DRAFT_HOLD state machine; Publisher only builds a local plan."""

    def __init__(self, *, worker: Principal, publisher: Principal,
                 auditor: Principal, witness: Principal,
                 permit_authority: Principal,
                 allowed_paths: tuple[str, ...], durable_store: Any | None = None) -> None:
        expected = (
            (worker, Role.WORKER), (publisher, Role.PUBLISHER),
            (auditor, Role.AUDITOR), (witness, Role.WITNESS),
            (permit_authority, Role.PERMIT_AUTHORITY),
        )
        if any(principal.role is not role or not principal.principal_id for principal, role in expected):
            raise BoundaryError("principal role mismatch")
        if len({principal.principal_id for principal, _ in expected}) != len(expected):
            raise BoundaryError("execution roles must have distinct principals")
        if not allowed_paths or len(set(allowed_paths)) != len(allowed_paths):
            raise BoundaryError("allowed paths must be nonempty and unique")
        if any(not _safe_path(path) for path in allowed_paths):
            raise BoundaryError("allowed path outside the command-tower sandbox")
        self.worker, self.publisher = worker, publisher
        self.auditor, self.witness = auditor, witness
        self.permit_authority = permit_authority
        self.allowed_paths = tuple(allowed_paths)
        self._durable_store = durable_store
        self.state = durable_store.state if durable_store is not None else "DRAFT_HOLD"
        self.stop_reason: str | None = durable_store.stop_reason if durable_store is not None else None
        self.journal = durable_store.journal if durable_store is not None else HashJournal()
        self._consumed_permits: set[str] = set()
        self._issued_permit_ids: set[str] = set()
        self._witnessed_permits: dict[str, str] = {}

    def create_candidate(self, actor: Principal, *, branch: str,
                         paths: tuple[str, ...], content_digest: str) -> Candidate:
        self._require_active()
        self._require_actor(actor, self.worker, "worker")
        if not branch.startswith("feature/") or ".." in branch or "\\" in branch:
            raise BoundaryError("candidate branch is outside the feature namespace")
        if not paths or len(set(paths)) != len(paths) or any(path not in self.allowed_paths for path in paths):
            raise BoundaryError("candidate paths exceed the approved local allowlist")
        if not content_digest:
            raise BoundaryError("candidate content digest is required")
        candidate = Candidate(SANDBOX_REPOSITORY, branch, tuple(paths), content_digest)
        self._append_event("CANDIDATE_DRAFTED", candidate_digest=candidate.digest(), actor_id=actor.principal_id)
        return candidate

    def issue_permit(self, actor: Principal, candidate: Candidate, *, permit_id: str) -> Permit:
        self._require_active()
        self._require_actor(actor, self.permit_authority, "permit authority")
        self._validate_candidate(candidate)
        if not permit_id or permit_id in self._issued_permit_ids:
            raise BoundaryError("permit id must be unique and nonempty")
        permit = Permit(permit_id, candidate.digest(), candidate.repository,
                        candidate.branch, candidate.paths, actor.principal_id)
        self._append_event("PERMIT_ISSUED", permit_digest=permit.digest(), issuer_id=actor.principal_id)
        self._issued_permit_ids.add(permit_id)
        return permit

    def witness_permit(self, actor: Principal, permit: Permit) -> WitnessAttestation:
        self._require_active()
        self._require_actor(actor, self.witness, "witness")
        self._validate_permit(permit)
        attestation = WitnessAttestation(permit.digest(), actor.principal_id)
        self._witnessed_permits[attestation.permit_digest] = actor.principal_id
        self._append_event("PERMIT_WITNESSED", permit_digest=attestation.permit_digest,
                           witness_id=actor.principal_id)
        return attestation

    def prepare_publication(self, actor: Principal, candidate: Candidate,
                            permit: Permit, attestation: WitnessAttestation) -> PublicationPlan:
        self._require_active()
        self._require_actor(actor, self.publisher, "publisher")
        self._validate_candidate(candidate)
        self._validate_permit(permit)
        permit_digest = permit.digest()
        if permit_digest in self._consumed_permits:
            self.safe_stop("permit_replay")
            raise SafeStop("permit_replay")
        if permit.candidate_digest != candidate.digest() or (
            permit.repository, permit.branch, permit.paths
        ) != (candidate.repository, candidate.branch, candidate.paths):
            self.safe_stop("permit_scope_mismatch")
            raise SafeStop("permit_scope_mismatch")
        if (attestation.permit_digest != permit_digest
                or attestation.witness_id != self.witness.principal_id
                or self._witnessed_permits.get(permit_digest) != self.witness.principal_id):
            self.safe_stop("witness_mismatch")
            raise SafeStop("witness_mismatch")
        plan = PublicationPlan(candidate.digest(), permit_digest, candidate.repository,
                               candidate.branch, candidate.paths)
        plan_digest = _digest(_plan_payload(plan))
        if self._durable_store is not None:
            try:
                self._durable_store.consume_permit_and_record(
                    permit_digest, plan_digest=plan_digest,
                    publisher_id=actor.principal_id, state=plan.state,
                )
            except self._durable_store.PermitAlreadyConsumed:
                self.safe_stop("permit_replay")
                raise SafeStop("permit_replay") from None
            except Exception:
                self.safe_stop("durability_failure")
                raise SafeStop("durability_failure") from None
        else:
            self._consumed_permits.add(permit_digest)
            self.journal.append("PERMIT_CONSUMED", permit_digest=permit_digest)
            self.journal.append("LOCAL_PLAN_PREPARED", plan_digest=plan_digest,
                                publisher_id=actor.principal_id, state=plan.state)
        return plan

    def audit_plan(self, actor: Principal, plan: PublicationPlan) -> bool:
        self._require_active()
        self._require_actor(actor, self.auditor, "auditor")
        if plan.state != "DRAFT_HOLD" or plan.repository != SANDBOX_REPOSITORY:
            self.safe_stop("audit_scope_mismatch")
            raise SafeStop("audit_scope_mismatch")
        try:
            journal_valid = self.journal.verify()
        except Exception:
            journal_valid = False
        if not journal_valid:
            self.safe_stop("journal_integrity_failure")
            raise SafeStop("journal_integrity_failure")
        plan_digest = _digest(_plan_payload(plan))
        if not any(entry.event == "LOCAL_PLAN_PREPARED" and
                   dict(entry.payload).get("plan_digest") == plan_digest
                   for entry in self.journal.entries):
            self.safe_stop("plan_not_journaled")
            raise SafeStop("plan_not_journaled")
        self._append_event("PLAN_AUDITED", plan_digest=plan_digest, auditor_id=actor.principal_id)
        return True

    def safe_stop(self, reason: str) -> None:
        if self.state != "SAFE_STOPPED":
            self.state = "SAFE_STOPPED"
            self.stop_reason = reason
            if self._durable_store is not None:
                try:
                    self._durable_store.safe_stop(reason)
                except Exception:
                    # Keep this process stopped even when the durable device fails.
                    pass
            else:
                self.journal.append("SAFE_STOP", reason=reason)

    def _append_event(self, event: str, **payload: str) -> None:
        try:
            self.journal.append(event, **payload)
        except Exception:
            self.safe_stop("durability_failure")
            raise SafeStop("durability_failure") from None

    def _validate_candidate(self, candidate: Candidate) -> None:
        if (candidate.repository != SANDBOX_REPOSITORY
                or not isinstance(candidate.branch, str)
                or not candidate.branch.startswith("feature/")
                or ".." in candidate.branch or "\\" in candidate.branch):
            raise BoundaryError("candidate is outside the public sandbox scope")
        if (not candidate.paths or len(set(candidate.paths)) != len(candidate.paths)
                or any(path not in self.allowed_paths for path in candidate.paths)):
            raise BoundaryError("candidate paths exceed the approved local allowlist")

    def _validate_permit(self, permit: Permit) -> None:
        if permit.repository != SANDBOX_REPOSITORY or permit.issuer_id != self.permit_authority.principal_id:
            raise BoundaryError("permit issuer or repository is outside the sandbox scope")
        if not permit.paths or any(path not in self.allowed_paths for path in permit.paths):
            raise BoundaryError("permit paths exceed the approved local allowlist")

    def _require_actor(self, actor: Principal, expected: Principal, label: str) -> None:
        if actor != expected:
            raise BoundaryError(f"actor is not the configured {label}")

    def _require_active(self) -> None:
        if self._durable_store is not None:
            try:
                if self._durable_store.state != "DRAFT_HOLD":
                    self.state = "SAFE_STOPPED"
                    self.stop_reason = self._durable_store.stop_reason or "durable_state_stopped"
            except Exception:
                self.state = "SAFE_STOPPED"
                self.stop_reason = "durable_state_unavailable"
        if self.state != "DRAFT_HOLD":
            raise SafeStop(self.stop_reason or "runtime is not active")


def _safe_path(path: str) -> bool:
    return (isinstance(path, str) and path.startswith("ops/command-tower/")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _plan_payload(plan: PublicationPlan) -> dict[str, Any]:
    return {"candidate_digest": plan.candidate_digest, "permit_digest": plan.permit_digest,
            "repository": plan.repository, "branch": plan.branch, "paths": list(plan.paths),
            "state": plan.state}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
