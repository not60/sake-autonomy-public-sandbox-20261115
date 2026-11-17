"""End-to-end Ed25519 tests using ephemeral test-only role keys."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from attestations import canonical_json, issue_permit, issue_witness, sign_envelope
from cas_journal import PermitCasJournal
from durable_store import DurableStore
from publisher_gate import (
    PublisherGate, PublisherGateHold, TrustedVerificationKey,
    is_gate_approved_draft_pr_plan, prepare_draft_pr_plan,
)
from test_cas_journal import MemoryCasBackend


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
CONTENT = b"test-only signed candidate\n"
CODEX_OUTPUT = b"test-only Codex result\n"
WORKER_RUN_ID = "test-run-42"


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )


class PublisherGateCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "artifact"
        self.source = self.root / PATH
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(CONTENT)
        self.output = Path(self.temporary.name) / "codex-output.bin"
        self.output.write_bytes(CODEX_OUTPUT)
        self.keys = {
            role: Ed25519PrivateKey.generate()
            for role in ("permit_authority", "witness", "owner_a", "owner_b", "untrusted")
        }
        self.trusted_keys = {
            role + "-key": TrustedVerificationKey(role + "-key", role, public_bytes(private))
            for role, private in self.keys.items() if role != "untrusted"
        }
        self.backend = MemoryCasBackend()
        self.journal = PermitCasJournal(self.backend, repository_id=REPOSITORY_ID)
        self.store = DurableStore(Path(self.temporary.name) / "publisher.sqlite3")
        material = {
            "schema": 2, "repository_id": REPOSITORY_ID, "base_sha": BASE_SHA,
            "worker_run_id": WORKER_RUN_ID,
            "codex_output_sha256": hashlib.sha256(CODEX_OUTPUT).hexdigest(),
            "changed_paths": [PATH],
            "files": {PATH: hashlib.sha256(CONTENT).hexdigest()},
        }
        self.manifest = {**material,
                         "candidate_digest": hashlib.sha256(canonical_json(material)).hexdigest()}
        self.permit = issue_permit(
            permit_id="test-permit-1", issuer_id="permit_authority-key",
            private_key=self.keys["permit_authority"], repository_id=REPOSITORY_ID,
            base_sha=BASE_SHA, candidate_digest=self.manifest["candidate_digest"],
            changed_paths=(PATH,), worker_run_id=WORKER_RUN_ID,
            journal=self.journal, local_store=self.store,
        )
        self.witness = issue_witness(
            witness_id="witness-key", private_key=self.keys["witness"],
            permit=self.permit, journal=self.journal,
        )
        permit_digest = hashlib.sha256(canonical_json(self.permit["payload"])).hexdigest()
        witness_digest = hashlib.sha256(canonical_json(self.witness)).hexdigest()
        approval_payload = {
            "schema": 1, "decision": "DRAFT_PR_ONLY", "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA, "candidate_digest": self.manifest["candidate_digest"],
            "changed_paths": [PATH], "permit_digest": permit_digest,
            "witness_digest": witness_digest, "worker_run_id": WORKER_RUN_ID,
        }
        self.approvals = {
            role: sign_envelope(key_id=role + "-key", private_key=self.keys[role],
                                payload=approval_payload)
            for role in ("owner_a", "owner_b")
        }
        self.gate = self._gate(self.store, self.trusted_keys, self.journal)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _gate(self, store, keys=None, journal=None):
        return PublisherGate(
            repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
            allowed_paths=(PATH,), trusted_keys=keys or self.trusted_keys,
            durable_store=store, cas_journal=journal or self.journal,
        )

    def verify(self, gate=None, approvals=None, permit=None, witness=None):
        return (gate or self.gate).verify_bundle(
            artifact_root=self.root, manifest=self.manifest,
            permit=self.permit if permit is None else permit,
            witness=self.witness if witness is None else witness,
            codex_output_file=self.output,
            owner_approvals=self.approvals if approvals is None else approvals,
        )

    def test_four_independent_role_signatures_and_cas_prepare_plan_without_write(self) -> None:
        result = self.verify()
        self.assertTrue(result.draft_pr_ready)
        self.assertFalse(result.publication_authorized)
        plan = prepare_draft_pr_plan(result)
        self.assertTrue(is_gate_approved_draft_pr_plan(plan))
        self.assertTrue(plan.draft_pr_ready)
        self.assertFalse(result.publication_authorized)
        self.assertEqual(plan.changed_paths, (PATH,))
        self.assertEqual(self.journal.snapshot().sequence, 2)
        self.assertEqual(self.store.state, "DRAFT_HOLD")
        self.assertTrue(self.store.journal.verify())

    def test_independent_auditor_checks_consumption_without_mutating_cas(self) -> None:
        self.verify()
        before = self.journal.snapshot()
        auditor_store = self._new_store("auditor.sqlite3")
        auditor = self._gate(auditor_store)
        audited = auditor.audit_bundle(
            artifact_root=self.root, manifest=self.manifest,
            permit=self.permit, witness=self.witness,
            codex_output_file=self.output, owner_approvals=self.approvals,
        )
        after = self.journal.snapshot()
        self.assertFalse(audited.draft_pr_ready)
        self.assertEqual(before.head_sha256, after.head_sha256)
        self.assertEqual(before.sequence, after.sequence)
        auditor_store.close()

    def test_missing_owner_approval_stops_before_permit_consumption(self) -> None:
        with self.assertRaisesRegex(PublisherGateHold, "both_owner_draft_approvals_required"):
            self.verify(approvals={})
        self.assertEqual(self.journal.snapshot().sequence, 1)

    def test_invalid_permit_signature_is_rejected(self) -> None:
        invalid = {**self.permit, "signature": "eHh4"}
        with self.assertRaisesRegex(PublisherGateHold, "signature_invalid"):
            self.verify(gate=self._gate(self._new_store("bad-permit.sqlite3"), journal=self.journal),
                        permit=invalid)

    def test_untrusted_authority_key_is_rejected(self) -> None:
        keys = dict(self.trusted_keys)
        keys["permit_authority-key"] = TrustedVerificationKey(
            "permit_authority-key", "permit_authority", public_bytes(self.keys["untrusted"]),
        )
        with self.assertRaisesRegex(PublisherGateHold, "signature_invalid"):
            self.verify(gate=self._gate(self._new_store("untrusted.sqlite3"), keys, self.journal))

    def test_tampered_artifact_and_codex_output_are_rejected(self) -> None:
        self.source.write_bytes(b"modified after signing\n")
        with self.assertRaisesRegex(PublisherGateHold, "artifact_digest_mismatch"):
            self.verify(gate=self._gate(self._new_store("tampered-file.sqlite3")))
        self.source.write_bytes(CONTENT)
        self.output.write_bytes(b"tampered Codex result")
        with self.assertRaisesRegex(PublisherGateHold, "codex_output_digest_mismatch"):
            self.verify(gate=self._gate(self._new_store("tampered-output.sqlite3")))

    def test_stale_journal_witness_is_rejected(self) -> None:
        self.journal.record_issuance(
            permit_id="intervening",
            candidate_digest=hashlib.sha256(b"intervening candidate").hexdigest(),
            permit_digest=hashlib.sha256(b"intervening permit").hexdigest(),
            worker_run_id="other-run",
        )
        with self.assertRaisesRegex(PublisherGateHold, "witness_journal_parent_mismatch"):
            self.verify(gate=self._gate(self._new_store("stale.sqlite3")))

    def _new_store(self, filename: str) -> DurableStore:
        return DurableStore(Path(self.temporary.name) / filename)


if __name__ == "__main__":
    unittest.main()
