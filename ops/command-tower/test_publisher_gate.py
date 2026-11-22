"""Focused fail-closed tests for the Publisher boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cas_journal import PermitCasJournal
from durable_store import DurableStore
from publisher_gate import (
    OfflineVerificationResult, PublisherGate, PublisherGateHold, _cycle_audit_evidence,
    prepare_draft_pr_plan,
)
from test_cas_journal import MemoryCasBackend


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
CONTENT = b"safe fixture\n"
CODEX_OUTPUT = b"Worker completed local candidate\n"
WORKER_RUN_ID = "run-42-attempt-1"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def manifest_for(content: bytes = CONTENT, output: bytes = CODEX_OUTPUT, *,
                 repository_id: int = REPOSITORY_ID, base_sha: str = BASE_SHA):
    material = {
        "schema": 2, "repository_id": repository_id, "base_sha": base_sha,
        "worker_run_id": WORKER_RUN_ID,
        "codex_output_sha256": hashlib.sha256(output).hexdigest(),
        "changed_paths": [PATH],
        "files": {PATH: hashlib.sha256(content).hexdigest()},
    }
    return {**material, "candidate_digest": hashlib.sha256(canonical(material)).hexdigest()}


def signed_shape(manifest: dict[str, object], journal_parent: str = "0" * 64,
                 *, witness_present: bool = True):
    permit_payload = {
        "schema": 2, "permit_id": "permit-test-1", "issuer_id": "authority-key",
        "repository_id": manifest["repository_id"], "base_sha": manifest["base_sha"],
        "candidate_digest": manifest["candidate_digest"], "changed_paths": [PATH],
        "issuer_role": "permit_authority", "worker_run_id": WORKER_RUN_ID,
    }
    permit = {"key_id": "authority-key", "signature": "AA==", "payload": permit_payload}
    if not witness_present:
        return permit, None
    permit_digest = hashlib.sha256(canonical(permit_payload)).hexdigest()
    witness_payload = {
        "schema": 2, "witness_id": "witness-key", "permit_digest": permit_digest,
        "repository_id": manifest["repository_id"], "base_sha": manifest["base_sha"],
        "candidate_digest": manifest["candidate_digest"], "changed_paths": [PATH],
        "issuer_role": "witness", "worker_run_id": WORKER_RUN_ID,
        "journal_parent_sha256": journal_parent,
    }
    witness = {"key_id": "witness-key", "signature": "AA==", "payload": witness_payload}
    return permit, witness


class PublisherGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "artifact"
        self.file = self.root / PATH
        self.file.parent.mkdir(parents=True)
        self.file.write_bytes(CONTENT)
        self.output = Path(self.temporary.name) / "codex-output.bin"
        self.output.write_bytes(CODEX_OUTPUT)
        self.store = DurableStore(Path(self.temporary.name) / "publisher.sqlite3")
        self.backend = MemoryCasBackend()
        self.journal = PermitCasJournal(self.backend, repository_id=REPOSITORY_ID)
        self.gate = PublisherGate(
            repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
            allowed_paths=(PATH,), trusted_keys={}, durable_store=self.store,
            cas_journal=self.journal,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def verify(self, manifest, permit=None, witness=None, approvals=None, gate=None):
        return (gate or self.gate).verify_bundle(
            artifact_root=self.root, manifest=manifest, permit=permit, witness=witness,
            codex_output_file=self.output, owner_approvals=approvals,
        )

    def test_tampered_artifact_fails_closed_before_signature_check(self) -> None:
        manifest = manifest_for()
        self.file.write_bytes(b"tampered fixture\n")
        with self.assertRaisesRegex(PublisherGateHold, "artifact_digest_mismatch"):
            self.verify(manifest)
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_tampered_codex_output_fails_closed(self) -> None:
        manifest = manifest_for()
        self.output.write_bytes(b"different Worker output")
        with self.assertRaisesRegex(PublisherGateHold, "codex_output_digest_mismatch"):
            self.verify(manifest)

    def test_unsigned_witness_is_a_hold(self) -> None:
        manifest = manifest_for()
        permit, witness = signed_shape(manifest, witness_present=False)
        with self.assertRaisesRegex(PublisherGateHold, "signed_permit_and_witness_required"):
            self.verify(manifest, permit, witness)
        self.assertEqual(self.store.state, "SAFE_STOPPED")

    def test_missing_trusted_key_holds_before_cas_consumption(self) -> None:
        manifest = manifest_for()
        permit, witness = signed_shape(manifest)
        with self.assertRaisesRegex(PublisherGateHold, "trusted_signing_key_missing_or_wrong_role"):
            self.verify(manifest, permit, witness)
        self.assertEqual(self.journal.snapshot().sequence, 0)

    def test_repository_and_base_mismatch_fail_closed(self) -> None:
        for invalid, reason in (
            (manifest_for(repository_id=1), "repository_id_mismatch"),
            (manifest_for(base_sha="b" * 40), "base_sha_mismatch"),
        ):
            store = DurableStore(Path(self.temporary.name) / f"{reason}.sqlite3")
            gate = PublisherGate(repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                                 allowed_paths=(PATH,), trusted_keys={}, durable_store=store,
                                 cas_journal=self.journal)
            with self.subTest(reason=reason), self.assertRaisesRegex(PublisherGateHold, reason):
                self.verify(invalid, gate=gate)
            self.assertEqual(store.state, "SAFE_STOPPED")
            store.close()

    def test_missing_cas_blocks_even_signed_bundle(self) -> None:
        store = DurableStore(Path(self.temporary.name) / "no-cas.sqlite3")
        gate = PublisherGate(repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                             allowed_paths=(PATH,), trusted_keys={}, durable_store=store,
                             cas_journal=None)
        with self.assertRaisesRegex(PublisherGateHold, "external_cas_not_configured"):
            self.verify(manifest_for(), gate=gate)
        store.close()

    def test_extra_file_is_rejected(self) -> None:
        manifest = manifest_for()
        (self.root / "unlisted.txt").write_text("not in manifest", encoding="utf-8")
        with self.assertRaisesRegex(PublisherGateHold, "unmanifested_artifact_file"):
            self.verify(manifest)

    def test_auditor_requires_matching_issuance_and_consumption_events(self) -> None:
        events = (
            {"previous_sha256": "0" * 64, "payload": {
                "event": "PERMIT_ISSUED", "permit_id": "permit-1",
                "candidate_digest": "c" * 64, "permit_digest": "d" * 64,
                "worker_run_id": WORKER_RUN_ID,
            }},
            {"previous_sha256": "e" * 64, "payload": {
                "event": "PERMIT_CONSUMED", "permit_id": "permit-1",
                "candidate_digest": "c" * 64, "permit_digest": "d" * 64,
                "witness_digest": "f" * 64, "worker_run_id": WORKER_RUN_ID,
            }},
        )
        PublisherGate._verify_consumed_cas_event(
            events, permit_id="permit-1", candidate_digest="c" * 64,
            permit_digest="d" * 64, witness_digest="f" * 64,
            worker_run_id=WORKER_RUN_ID, journal_parent="e" * 64,
        )
        with self.assertRaisesRegex(PublisherGateHold, "auditor_cas_consumption_scope_mismatch"):
            PublisherGate._verify_consumed_cas_event(
                events, permit_id="permit-1", candidate_digest="c" * 64,
                permit_digest="d" * 64, witness_digest="0" * 64,
                worker_run_id=WORKER_RUN_ID, journal_parent="e" * 64,
            )

    def test_draft_pr_plan_is_not_authorized_without_gate_result(self) -> None:
        result = OfflineVerificationResult(
            repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
            candidate_digest="a" * 64, permit_id="p", permit_digest="d" * 64,
            changed_paths=(PATH,), file_sha256=((PATH, "c" * 64),),
            worker_run_id=WORKER_RUN_ID, codex_output_sha256="e" * 64,
            witness_digest="f" * 64, draft_pr_ready=False,
        )
        with self.assertRaisesRegex(PublisherGateHold, "draft_pr_approval_or_verification_missing"):
            prepare_draft_pr_plan(result)

    def test_f4_publication_evidence_keeps_cycle_specific_permit_digest(self) -> None:
        base = {"worker_run_id": "101-1-cycle-1", "permit_sha256": "a" * 64}
        cycle1 = _cycle_audit_evidence(
            base, cycle=1, repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
        )
        self.assertNotIn("permit_sha256", cycle1)
        cycle2 = _cycle_audit_evidence(
            {**base, "worker_run_id": "102-1-cycle-2"}, cycle=2,
            repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
        )
        self.assertEqual(cycle2["permit_sha256"], "a" * 64)
        with self.assertRaisesRegex(PublisherGateHold, "cycle2_permit_digest_missing"):
            _cycle_audit_evidence(
                {"worker_run_id": "102-1-cycle-2"}, cycle=2,
                repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
            )


if __name__ == "__main__":
    unittest.main()
