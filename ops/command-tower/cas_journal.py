"""Conditional external CAS journal for cross-job Permit continuity.

The HTTP adapter uses ETag compare-and-swap. It has no built-in endpoint or
credential; callers must supply an approved HTTPS service and an in-memory
token. No request or error includes authorization material in diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class CasHold(RuntimeError):
    """CAS state is unavailable, inconsistent, or raced."""


class CasConflict(CasHold):
    """The compare-and-swap version changed; caller must fail closed."""


@dataclass(frozen=True)
class CasValue:
    body: bytes
    version: str


class CasBackend(Protocol):
    def read(self, key: str) -> CasValue | None: ...
    def compare_and_swap(self, key: str, version: str | None, body: bytes) -> str: ...


class HttpsCasBackend:
    """Minimal JSON-object CAS adapter using GET/conditional PUT and ETags."""

    def __init__(self, *, endpoint: str, bearer_token: str, timeout: float = 5.0) -> None:
        if not endpoint.startswith("https://") or not bearer_token or timeout <= 0:
            raise ValueError("approved HTTPS CAS endpoint and credential are required")
        self._endpoint = endpoint.rstrip("/")
        self._token = bearer_token
        self._timeout = timeout

    def read(self, key: str) -> CasValue | None:
        request = Request(self._url(key), headers={
            "Authorization": f"Bearer {self._token}", "Accept": "application/json",
        })
        try:
            with urlopen(request, timeout=self._timeout) as response:
                version = response.headers.get("ETag")
                body = response.read()
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise CasHold("cas_read_rejected") from None
        except (OSError, URLError, TimeoutError):
            raise CasHold("cas_read_unavailable") from None
        if not version:
            raise CasHold("cas_version_missing")
        return CasValue(body, version)

    def compare_and_swap(self, key: str, version: str | None, body: bytes) -> str:
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        headers["If-Match" if version is not None else "If-None-Match"] = version or "*"
        request = Request(self._url(key), data=body, method="PUT", headers=headers)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                next_version = response.headers.get("ETag")
        except HTTPError as exc:
            if exc.code in {409, 412}:
                raise CasConflict("cas_version_conflict") from None
            raise CasHold("cas_write_rejected") from None
        except (OSError, URLError, TimeoutError):
            raise CasHold("cas_write_unavailable") from None
        if not next_version:
            raise CasHold("cas_version_missing")
        return next_version

    def _url(self, key: str) -> str:
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError("invalid CAS object key")
        return self._endpoint + "/" + quote(key, safe="/")


@dataclass(frozen=True)
class CasSnapshot:
    repository_id: int
    sequence: int
    head_sha256: str
    version: str | None
    events: tuple[dict[str, object], ...]


class PermitCasJournal:
    """Append-only repository journal and cross-run Permit-ID registry."""

    TEST_REPOSITORY_ID = 1458303357
    TEST_ID_PREFIX = "TEST:"

    def __init__(self, backend: CasBackend, *, repository_id: int,
                 mode: str = "formal") -> None:
        if isinstance(repository_id, bool) or repository_id <= 0:
            raise ValueError("repository ID must be positive")
        if mode not in {"formal", "test"}:
            raise ValueError("CAS journal mode must be formal or test")
        if mode == "test" and repository_id != self.TEST_REPOSITORY_ID:
            raise ValueError("TEST CAS is fixed to the public sandbox repository")
        self._backend = backend
        self.repository_id = repository_id
        self.mode = mode
        suffix = (
            "b09-permit-journal-test-v1.json"
            if mode == "test" else "b09-permit-journal-v1.json"
        )
        self._key = f"repositories/{repository_id}/{suffix}"

    def snapshot(self) -> CasSnapshot:
        stored = self._backend.read(self._key)
        if stored is None:
            return CasSnapshot(self.repository_id, 0, "0" * 64, None, ())
        try:
            document = json.loads(stored.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CasHold("cas_document_invalid") from None
        if (not isinstance(document, dict) or set(document) != {
                "schema", "repository_id", "sequence", "head_sha256", "events"}
                or document["schema"] != 1 or document["repository_id"] != self.repository_id
                or not isinstance(document["events"], list)):
            raise CasHold("cas_document_scope_invalid")
        events = document["events"]
        previous = "0" * 64
        for sequence, event in enumerate(events, 1):
            if not isinstance(event, dict) or set(event) != {
                    "sequence", "previous_sha256", "payload", "event_sha256"}:
                raise CasHold("cas_journal_event_invalid")
            body = {k: event[k] for k in ("sequence", "previous_sha256", "payload")}
            digest = _sha256(_canonical(body))
            if (event["sequence"] != sequence or event["previous_sha256"] != previous
                    or event["event_sha256"] != digest or not isinstance(event["payload"], dict)):
                raise CasHold("cas_journal_chain_invalid")
            payload = event["payload"]
            self._validate_mode_ids(payload.get("permit_id"), payload.get("worker_run_id"))
            previous = digest
        if document["sequence"] != len(events) or document["head_sha256"] != previous:
            raise CasHold("cas_journal_head_invalid")
        return CasSnapshot(self.repository_id, len(events), previous, stored.version,
                           tuple(events))

    def record_issuance(self, *, permit_id: str, candidate_digest: str,
                        permit_digest: str, worker_run_id: str) -> CasSnapshot:
        if (not permit_id or not worker_run_id or not _sha(candidate_digest)
                or not _sha(permit_digest)):
            raise CasHold("permit_issuance_scope_invalid")
        self._validate_mode_ids(permit_id, worker_run_id)
        current = self.snapshot()
        if self._permit_events(current, permit_id):
            raise CasHold("permit_id_reused_across_runs")
        payload = {
            "event": "PERMIT_ISSUED", "permit_id": permit_id,
            "candidate_digest": candidate_digest, "permit_digest": permit_digest,
            "worker_run_id": worker_run_id,
        }
        return self._append(current, payload)

    def record_consumption(self, *, permit_id: str, candidate_digest: str,
                           permit_digest: str, witness_digest: str,
                           worker_run_id: str, expected_parent: str) -> CasSnapshot:
        if (not permit_id or not worker_run_id or not _sha(candidate_digest)
                or not _sha(permit_digest) or not _sha(witness_digest)
                or not _sha(expected_parent)):
            raise CasHold("permit_consumption_scope_invalid")
        self._validate_mode_ids(permit_id, worker_run_id)
        current = self.snapshot()
        if current.head_sha256 != expected_parent:
            raise CasConflict("witness_journal_parent_mismatch")
        previous_events = self._permit_events(current, permit_id)
        if any(event.get("event") == "PERMIT_CONSUMED" for event in previous_events):
            raise CasHold("permit_id_already_consumed_across_runs")
        issuance = [event for event in previous_events if event.get("event") == "PERMIT_ISSUED"]
        if len(issuance) != 1 or any(issuance[0].get(key) != value for key, value in {
                "candidate_digest": candidate_digest, "permit_digest": permit_digest,
                "worker_run_id": worker_run_id,
        }.items()):
            raise CasHold("permit_issuance_not_found_or_scope_mismatch")
        payload = {
            "event": "PERMIT_CONSUMED", "permit_id": permit_id,
            "candidate_digest": candidate_digest, "permit_digest": permit_digest,
            "witness_digest": witness_digest, "worker_run_id": worker_run_id,
        }
        return self._append(current, payload)

    def _append(self, current: CasSnapshot, payload: dict[str, object]) -> CasSnapshot:
        body = {"sequence": current.sequence + 1, "previous_sha256": current.head_sha256,
                "payload": payload}
        event = {**body, "event_sha256": _sha256(_canonical(body))}
        events = [*current.events, event]
        head = event["event_sha256"]
        document = {"schema": 1, "repository_id": self.repository_id,
                    "sequence": len(events), "head_sha256": head, "events": events}
        version = self._backend.compare_and_swap(self._key, current.version, _canonical(document))
        return CasSnapshot(self.repository_id, len(events), head, version, tuple(events))

    @staticmethod
    def _permit_events(snapshot: CasSnapshot, permit_id: str) -> list[dict[str, object]]:
        result = []
        for event in snapshot.events:
            payload = event.get("payload")
            if isinstance(payload, dict) and payload.get("permit_id") == permit_id:
                result.append(payload)
        return result

    def _validate_mode_ids(self, permit_id: object, worker_run_id: object) -> None:
        if not isinstance(permit_id, str) or not isinstance(worker_run_id, str):
            raise CasHold("cas_journal_mode_scope_invalid")
        test_scoped = (permit_id.startswith(self.TEST_ID_PREFIX)
                       and worker_run_id.startswith(self.TEST_ID_PREFIX))
        formal_scoped = (not permit_id.startswith(self.TEST_ID_PREFIX)
                         and not worker_run_id.startswith(self.TEST_ID_PREFIX))
        if ((self.mode == "test" and not test_scoped)
                or (self.mode == "formal" and not formal_scoped)):
            raise CasHold("cas_journal_mode_scope_invalid")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)
