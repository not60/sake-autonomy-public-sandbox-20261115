"""DRAFT_HOLD contract for independently signed delegation revocation state.

This is a local adapter contract only. The CAS key must be separately
authorized by the deployed service before this module can be used remotely.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Mapping

from attestations import canonical_json
from f4_go_gate import _verify_ed25519
from trusted_key_registry import TrustedVerificationKey

REPOSITORY_ID = 1458303357
CAS_KEY = "repositories/1458303357/b09-delegation-status-v1.json"
TEST_CAS_KEY = "repositories/1458303357/b09-delegation-status-test-v1.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


class DelegationStatusHold(RuntimeError):
    pass


def _fail(code: str):
    raise DelegationStatusHold(code)


def _instant(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("delegation_status_time_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("delegation_status_time_invalid")


def verify_status(envelope: object, *, trusted_owner_keys: Mapping[str, TrustedVerificationKey],
                  now: datetime | None = None, fresh: bool = True) -> dict:
    keys = {"schema", "kind", "delegation_id", "contract_sha256", "repository_id",
            "execution_revision", "environment", "sequence", "status", "issued_at", "expires_at"}
    if not isinstance(envelope, Mapping) or set(envelope) != {"payload", "approvals"}:
        _fail("delegation_status_envelope_invalid")
    payload, approvals = envelope["payload"], envelope["approvals"]
    if not isinstance(payload, Mapping) or set(payload) != keys:
        _fail("delegation_status_payload_invalid")
    if (payload["schema"] != 1 or payload["kind"] != "DELEGATION_REVOCATION_STATUS"
            or not isinstance(payload["delegation_id"], str) or not payload["delegation_id"]
            or not isinstance(payload["contract_sha256"], str) or not _HEX64.fullmatch(payload["contract_sha256"])
            or payload["environment"] not in {"formal", "test"}
            or payload["repository_id"] != REPOSITORY_ID
            or not isinstance(payload["execution_revision"], str) or not _SHA40.fullmatch(payload["execution_revision"])
            or isinstance(payload["sequence"], bool) or not isinstance(payload["sequence"], int) or payload["sequence"] < 1
            or payload["status"] not in {"ACTIVE", "REVOKED"}):
        _fail("delegation_status_scope_invalid")
    start, end = _instant(payload["issued_at"]), _instant(payload["expires_at"])
    instant = now or datetime.now(timezone.utc)
    if end <= start or (fresh and (instant < start or instant >= end)):
        _fail("delegation_status_expired_or_not_yet_valid")
    if (not isinstance(approvals, Mapping) or not approvals
            or not set(approvals).issubset({"owner_a", "owner_b"})
            or (payload["status"] == "ACTIVE" and set(approvals) != {"owner_a", "owner_b"})):
        _fail("delegation_status_owner_signatures_missing")
    seen = []
    for role in approvals:
        approval = approvals[role]
        if not isinstance(approval, Mapping) or set(approval) != {"key_id", "signature"}:
            _fail("delegation_status_signature_invalid")
        key = trusted_owner_keys.get(approval["key_id"])
        if not isinstance(key, TrustedVerificationKey) or key.role != role or key.key_id != approval["key_id"] or len(key.public_key) != 32:
            _fail("delegation_status_trust_key_invalid")
        try:
            _verify_ed25519(key.public_key, base64.b64decode(approval["signature"], validate=True),
                            canonical_json(dict(payload)))
        except Exception:
            _fail("delegation_status_signature_invalid")
        seen.append(key.public_key)
    if len(seen) == 2 and seen[0] == seen[1]:
        _fail("delegation_status_owner_keys_not_independent")
    return dict(payload)


class DelegationStatusStore:
    """CAS-backed monotonic status; caller must enforce Owner-only write auth."""
    def __init__(self, backend, *, trusted_owner_keys, environment: str):
        if environment not in {"formal", "test"}:
            _fail("delegation_status_environment_invalid")
        self._backend, self._keys, self._environment = backend, trusted_owner_keys, environment
        self.key = CAS_KEY if environment == "formal" else TEST_CAS_KEY

    def _read_value(self):
        try:
            return self._backend.read(self.key)
        except Exception:
            _fail("delegation_status_read_unavailable")

    def read(self, *, now=None):
        value = self._read_value()
        if value is None:
            return None
        return self._decode(value, now=now)

    def _decode(self, value, *, now=None, fresh=True):
        try:
            import json
            from f4_signing_cli import _unique_object
            doc = json.loads(value.body, object_pairs_hook=_unique_object)
            if set(doc) != {"schema", "environment", "status", "head_sha256"} or doc["schema"] != 1 or doc["environment"] != self._environment:
                _fail("delegation_status_document_invalid")
            status = verify_status(doc["status"], trusted_owner_keys=self._keys, now=now, fresh=fresh)
            if status["environment"] != self._environment:
                _fail("delegation_status_environment_mismatch")
            digest = hashlib.sha256(canonical_json(doc["status"])).hexdigest()
            if doc["head_sha256"] != digest:
                _fail("delegation_status_digest_invalid")
            return status
        except DelegationStatusHold:
            raise
        except Exception:
            _fail("delegation_status_read_unavailable_or_invalid")

    def update(self, envelope, *, now=None):
        incoming = verify_status(envelope, trusted_owner_keys=self._keys, now=now)
        if incoming["environment"] != self._environment:
            _fail("delegation_status_environment_mismatch")
        current = self._read_value()
        if current is None:
            if incoming["sequence"] != 1 or incoming["status"] != "ACTIVE":
                _fail("delegation_status_initial_state_invalid")
            version = None
        else:
            prior = self._decode(current, now=now, fresh=False)
            if (incoming["delegation_id"] != prior["delegation_id"]
                    or incoming["contract_sha256"] != prior["contract_sha256"]
                    or incoming["repository_id"] != prior["repository_id"]
                    or incoming["execution_revision"] != prior["execution_revision"]
                    or incoming["sequence"] != prior["sequence"] + 1
                    or prior["status"] == "REVOKED"
                    or incoming["status"] != "REVOKED"):
                _fail("delegation_status_transition_invalid")
            version = current.version
        import json
        doc = {"schema": 1, "environment": self._environment, "status": envelope,
               "head_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest()}
        try:
            self._backend.compare_and_swap(self.key, version, canonical_json(doc))
        except Exception:
            _fail("delegation_status_cas_conflict_or_unavailable")
        result = self.read(now=now)
        if result != incoming:
            _fail("delegation_status_write_readback_mismatch")
        return result


def authenticated_delegation_reader(store: DelegationStatusStore, *, expected_delegation_id: str,
                                    expected_contract_sha256: str, expected_revision: str):
    """Fresh read callback compatible with the existing delegation verifier."""
    def read(_delegation_payload):
        status = store.read()
        if status is None or status["status"] != "ACTIVE":
            _fail("delegation_status_not_active")
        if (status["delegation_id"] != expected_delegation_id
                or status["contract_sha256"] != expected_contract_sha256
                or status["execution_revision"] != expected_revision):
            _fail("delegation_status_scope_mismatch")
        if (not isinstance(_delegation_payload, Mapping)
                or _delegation_payload.get("delegation_id") != expected_delegation_id
                or _delegation_payload.get("repository_id") != REPOSITORY_ID
                or _delegation_payload.get("execution_revision") != expected_revision
                or hashlib.sha256(canonical_json(dict(_delegation_payload))).hexdigest() != expected_contract_sha256
                or _delegation_payload.get("revocation", {}).get("sequence") != status["sequence"]):
            _fail("delegation_contract_binding_mismatch")
        return {key: status[key] for key in ("delegation_id", "sequence", "status")}
    return read
