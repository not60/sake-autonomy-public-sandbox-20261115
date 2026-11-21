"""Independent Ed25519 Permit Authority and Witness signing operations.

Private key material is provided by the caller and is never read from files,
printed, or persisted. Tests must use ephemeral test-only keys. Production key
provisioning and Owner approval remain outside this DRAFT_HOLD candidate.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cas_journal import PermitCasJournal
from durable_store import DurableStore


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sign_envelope(*, key_id: str, private_key: Any, payload: dict[str, object]) -> dict[str, object]:
    if not key_id or not isinstance(payload, dict):
        raise ValueError("key ID and payload are required")
    try:
        signature = private_key.sign(canonical_json(payload))
    except Exception:
        raise ValueError("Ed25519 signing operation failed") from None
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("signer did not return an Ed25519 signature")
    return {"key_id": key_id, "signature": base64.b64encode(signature).decode("ascii"),
            "payload": payload}


def issue_permit(*, permit_id: str, issuer_id: str, private_key: Any,
                 repository_id: int, base_sha: str, candidate_digest: str,
                 changed_paths: tuple[str, ...], worker_run_id: str,
                 journal: PermitCasJournal, local_store: DurableStore | None = None
                 ) -> dict[str, object]:
    if not permit_id or not issuer_id or not worker_run_id or not changed_paths:
        raise ValueError("Permit scope is incomplete")
    payload: dict[str, object] = {
        "schema": 2, "permit_id": permit_id, "issuer_id": issuer_id,
        "repository_id": repository_id, "base_sha": base_sha,
        "candidate_digest": candidate_digest, "changed_paths": list(sorted(changed_paths)),
        "issuer_role": "permit_authority", "worker_run_id": worker_run_id,
    }
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    # The external conditional write reserves IDs across independent runner jobs.
    journal.record_issuance(permit_id=permit_id, candidate_digest=candidate_digest,
                            permit_digest=digest, worker_run_id=worker_run_id)
    if local_store is not None:
        local_store.record_permit_issuance(permit_id, candidate_digest, digest, issuer_id)
    return sign_envelope(key_id=issuer_id, private_key=private_key, payload=payload)


def issue_witness(*, witness_id: str, private_key: Any,
                  permit: dict[str, object], journal: PermitCasJournal
                  ) -> dict[str, object]:
    if not witness_id or not isinstance(permit, dict) or not isinstance(permit.get("payload"), dict):
        raise ValueError("Witness scope is incomplete")
    permit_payload = permit["payload"]
    snapshot = journal.snapshot()
    payload: dict[str, object] = {
        "schema": 2,
        "witness_id": witness_id,
        "permit_digest": hashlib.sha256(canonical_json(permit_payload)).hexdigest(),
        "repository_id": permit_payload["repository_id"],
        "base_sha": permit_payload["base_sha"],
        "candidate_digest": permit_payload["candidate_digest"],
        "changed_paths": permit_payload["changed_paths"],
        "issuer_role": "witness",
        "worker_run_id": permit_payload["worker_run_id"],
        "journal_parent_sha256": snapshot.head_sha256,
    }
    return sign_envelope(key_id=witness_id, private_key=private_key, payload=payload)
