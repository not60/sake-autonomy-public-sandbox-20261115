"""Positive and negative Ed25519 tests with ephemeral test-only keys."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_store import DurableStore
from publisher_gate import PublisherGate, PublisherGateHold, TrustedVerificationKey


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
CONTENT = b"test-only signed candidate\n"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signed_envelope(key_id: str, private_key: Ed25519PrivateKey,
                    payload: dict[str, object]) -> dict[str, object]:
    signature = private_key.sign(canonical(payload))
    return {"key_id": key_id, "signature": base64.b64encode(signature).decode("ascii"),
            "payload": payload}


class PublisherGateCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "artifact"
        self.source = self.root / PATH
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(CONTENT)
        self.authority_private = Ed25519PrivateKey.generate()
        self.witness_private = Ed25519PrivateKey.generate()
        self.other_private = Ed25519PrivateKey.generate()
        self.authority_key = TrustedVerificationKey(
            "authority-key", "permit_authority", public_bytes(self.authority_private),
        )
        self.witness_key = TrustedVerificationKey(
            "witness-key", "witness", public_bytes(self.witness_private),
        )
        files = {PATH: hashlib.sha256(CONTENT).hexdigest()}
        material: dict[str, object] = {
            "schema": 1,
            "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA,
            "changed_paths": [PATH],
            "files": files,
        }
        self.manifest = {
            **material,
            "candidate_digest": hashlib.sha256(canonical(material)).hexdigest(),
        }
        permit_payload: dict[str, object] = {
            "schema": 1,
            "permit_id": "test-permit-1",
            "issuer_id": "authority-key",
            "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA,
            "candidate_digest": self.manifest["candidate_digest"],
            "changed_paths": [PATH],
            "issuer_role": "permit_authority",
        }
        self.permit = signed_envelope("authority-key", self.authority_private, permit_payload)
        permit_digest = hashlib.sha256(canonical(permit_payload)).hexdigest()
        witness_payload: dict[str, object] = {
            "schema": 1,
            "witness_id": "witness-key",
            "permit_digest": permit_digest,
            "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA,
            "candidate_digest": self.manifest["candidate_digest"],
            "changed_paths": [PATH],
            "issuer_role": "witness",
        }
        self.witness = signed_envelope("witness-key", self.witness_private, witness_payload)
        self.store = self._new_store("publisher.sqlite3")
        self.gate = self._new_gate(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _new_store(self, filename: str) -> DurableStore:
        return DurableStore(Path(self.temporary.name) / filename)

    def _new_gate(self, store: DurableStore,
                  keys: dict[str, TrustedVerificationKey] | None = None) -> PublisherGate:
        return PublisherGate(
            repository_id=REPOSITORY_ID,
            base_sha=BASE_SHA,
            allowed_paths=(PATH,),
            trusted_keys=keys or {
                "authority-key": self.authority_key,
                "witness-key": self.witness_key,
            },
            durable_store=store,
        )

    def test_valid_test_only_permit_and_witness_verify_without_authorizing_write(self) -> None:
        result = self.gate.verify_bundle(
            artifact_root=self.root, manifest=self.manifest,
            permit=self.permit, witness=self.witness,
        )
        self.assertEqual(result.permit_id, "test-permit-1")
        self.assertFalse(result.publication_authorized)
        self.assertEqual(self.store.state, "DRAFT_HOLD")
        self.assertTrue(self.store.journal.verify())

    def test_invalid_permit_signature_is_rejected(self) -> None:
        invalid = dict(self.permit)
        invalid["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=self.manifest,
                                    permit=invalid, witness=self.witness)
        self.assertEqual(held.exception.reason, "signature_invalid")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_untrusted_public_key_is_rejected(self) -> None:
        wrong_authority = TrustedVerificationKey(
            "authority-key", "permit_authority", public_bytes(self.other_private),
        )
        gate = self._new_gate(self.store, {
            "authority-key": wrong_authority,
            "witness-key": self.witness_key,
        })
        with self.assertRaises(PublisherGateHold) as held:
            gate.verify_bundle(artifact_root=self.root, manifest=self.manifest,
                               permit=self.permit, witness=self.witness)
        self.assertEqual(held.exception.reason, "signature_invalid")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_tampered_signed_artifact_is_rejected(self) -> None:
        self.source.write_bytes(b"modified after signing\n")
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=self.manifest,
                                    permit=self.permit, witness=self.witness)
        self.assertEqual(held.exception.reason, "artifact_digest_mismatch")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_valid_bundle_replay_is_rejected_durably(self) -> None:
        self.gate.verify_bundle(artifact_root=self.root, manifest=self.manifest,
                                permit=self.permit, witness=self.witness)
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=self.manifest,
                                    permit=self.permit, witness=self.witness)
        self.assertEqual(held.exception.reason, "permit_replay_or_id_reuse")
        self.assertEqual(self.store.state, "SAFE_STOPPED")


if __name__ == "__main__":
    unittest.main()
