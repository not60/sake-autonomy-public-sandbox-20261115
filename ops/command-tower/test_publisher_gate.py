"""Offline fail-closed tests for Publisher artifact verification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from durable_store import DurableStore
from publisher_gate import PublisherGate, PublisherGateHold


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
ALLOWED_PATHS = (PATH,)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def manifest_for(content: bytes, *, repository_id: int = REPOSITORY_ID,
                 base_sha: str = BASE_SHA) -> dict[str, object]:
    files = {PATH: hashlib.sha256(content).hexdigest()}
    material: dict[str, object] = {
        "schema": 1,
        "repository_id": repository_id,
        "base_sha": base_sha,
        "changed_paths": [PATH],
        "files": files,
    }
    return {**material, "candidate_digest": hashlib.sha256(canonical(material)).hexdigest()}


def signed_shape(manifest: dict[str, object], *, witness_present: bool = True):
    permit_payload = {
        "schema": 1,
        "permit_id": "permit-test-1",
        "issuer_id": "authority-key",
        "repository_id": manifest["repository_id"],
        "base_sha": manifest["base_sha"],
        "candidate_digest": manifest["candidate_digest"],
        "changed_paths": [PATH],
        "issuer_role": "permit_authority",
    }
    permit = {"key_id": "authority-key", "signature": "AA==", "payload": permit_payload}
    if not witness_present:
        return permit, None
    permit_digest = hashlib.sha256(canonical(permit_payload)).hexdigest()
    witness_payload = {
        "schema": 1,
        "witness_id": "witness-key",
        "permit_digest": permit_digest,
        "repository_id": manifest["repository_id"],
        "base_sha": manifest["base_sha"],
        "candidate_digest": manifest["candidate_digest"],
        "changed_paths": [PATH],
        "issuer_role": "witness",
    }
    witness = {"key_id": "witness-key", "signature": "AA==", "payload": witness_payload}
    return permit, witness


class PublisherGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "artifact"
        self.file = self.root / PATH
        self.file.parent.mkdir(parents=True)
        self.content = b"safe fixture\n"
        self.file.write_bytes(self.content)
        self.store = DurableStore(Path(self.temporary.name) / "publisher.sqlite3")
        self.gate = PublisherGate(
            repository_id=REPOSITORY_ID,
            base_sha=BASE_SHA,
            allowed_paths=ALLOWED_PATHS,
            trusted_keys={},
            durable_store=self.store,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_tampered_artifact_fails_closed_before_signature_check(self) -> None:
        manifest = manifest_for(self.content)
        self.file.write_bytes(b"tampered fixture\n")
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=manifest,
                                    permit=None, witness=None)
        self.assertEqual(held.exception.reason, "artifact_digest_mismatch")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_unsigned_witness_is_a_hold(self) -> None:
        manifest = manifest_for(self.content)
        permit, witness = signed_shape(manifest, witness_present=False)
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=manifest,
                                    permit=permit, witness=witness)
        self.assertEqual(held.exception.reason, "signed_permit_and_witness_required")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_signature_without_configured_trusted_keys_is_a_hold(self) -> None:
        manifest = manifest_for(self.content)
        permit, witness = signed_shape(manifest)
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=manifest,
                                    permit=permit, witness=witness)
        self.assertEqual(held.exception.reason, "trusted_signing_key_missing_or_wrong_role")
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_repository_and_base_mismatch_fail_closed(self) -> None:
        for invalid_manifest, reason in (
            (manifest_for(self.content, repository_id=1), "repository_id_mismatch"),
            (manifest_for(self.content, base_sha="b" * 40), "base_sha_mismatch"),
        ):
            with self.subTest(reason=reason):
                store = DurableStore(Path(self.temporary.name) / f"{reason}.sqlite3")
                gate = PublisherGate(
                    repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                    allowed_paths=ALLOWED_PATHS, trusted_keys={}, durable_store=store,
                )
                with self.assertRaises(PublisherGateHold) as held:
                    gate.verify_bundle(artifact_root=self.root, manifest=invalid_manifest,
                                       permit=None, witness=None)
                self.assertEqual(held.exception.reason, reason)
                self.assertEqual(store.state, "SAFE_STOPPED")
                store.close()

    def test_extra_file_is_rejected(self) -> None:
        manifest = manifest_for(self.content)
        (self.root / "unlisted.txt").write_text("not in manifest", encoding="utf-8")
        with self.assertRaises(PublisherGateHold) as held:
            self.gate.verify_bundle(artifact_root=self.root, manifest=manifest,
                                    permit=None, witness=None)
        self.assertEqual(held.exception.reason, "unmanifested_artifact_file")


if __name__ == "__main__":
    unittest.main()
