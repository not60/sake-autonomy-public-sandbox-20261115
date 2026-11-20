"""End-to-end Ed25519 tests using ephemeral test-only role keys."""
from __future__ import annotations

import hashlib
import base64
from datetime import datetime, timezone
import io
import json
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
from f4_limited_delegation import (
    DelegationHold, build_delegation_payload,
    issue_candidate_authorization_for_role, combine_candidate_authorization_fragments,
    verify_delegation_contract,
)
from f4_auditor_artifact import verify_limited_delegation as verify_auditor_delegation
from f4_signing_cli import (
    SigningCliHold, SigningContext, issue_from_cli_request, main as signing_cli_main,
)
from test_cas_journal import MemoryCasBackend


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
CONTENT = b"test-only signed candidate\n"
CODEX_OUTPUT = b"test-only Codex result\n"
WORKER_RUN_ID = "test-run-42"
F4_NOW = datetime(2026, 11, 19, 3, 0, tzinfo=timezone.utc)


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

    def test_owner_and_delegate_ed25519_signatures_are_reverified_by_publisher_and_auditor(self) -> None:
        case = self._delegation_case()
        kwargs = self._delegation_verifier_kwargs(case)
        publisher_digest = PublisherGate.verify_limited_delegation(**kwargs)
        auditor_digest = verify_auditor_delegation(**kwargs)
        self.assertEqual(publisher_digest, auditor_digest)
        self.assertEqual(len(publisher_digest), 64)

    def test_delegation_rejects_missing_owner_signature_tamper_revocation_and_protected_path(self) -> None:
        case = self._delegation_case()
        contract, _status, _evidence, authorization, _candidate_verifier = case
        kwargs = self._delegation_verifier_kwargs(case)

        missing_owner = {**contract, "approvals": {"owner_a": contract["approvals"]["owner_a"]}}
        with self.assertRaisesRegex(DelegationHold, "both_owner_signatures_required"):
            PublisherGate.verify_limited_delegation(**{**kwargs, "delegation_envelope": missing_owner})

        tampered = {**authorization, "signatures": dict(authorization["signatures"])}
        tampered["signatures"]["owner_b_delegate"] = {
            **tampered["signatures"]["owner_b_delegate"],
            "signature": base64.b64encode(b"x" * 64).decode("ascii"),
        }
        with self.assertRaisesRegex(DelegationHold, "signature_invalid"):
            verify_auditor_delegation(**{**kwargs, "authorization": tampered})

        with self.assertRaisesRegex(DelegationHold, "revocation_not_authenticated"):
            PublisherGate.verify_limited_delegation(
                **{**kwargs, "verify_revocation_status": lambda _status, _payload: False},
            )

        with self.assertRaisesRegex(ValueError, "unsafe_or_noncanonical"):
            build_delegation_payload(
                delegation_id="fixture-delegation-protected",
                execution_revision=BASE_SHA,
                cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
                allowed_paths=("ops/command-tower/f4_go_gate.py",),
                not_before="2026-11-19T02:00:00Z", expires_at="2026-11-19T04:00:00Z",
                revocation_sequence=1, delegates={},
            )

    def test_signing_cli_issues_permit_and_witness_with_role_bound_signers(self) -> None:
        journal = PermitCasJournal(MemoryCasBackend(), repository_id=REPOSITORY_ID)
        request = {
            "permit_id": "cli-fixture-permit",
            "issuer_id": "permit_authority-key",
            "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA,
            "candidate_digest": self.manifest["candidate_digest"],
            "changed_paths": [PATH],
            "worker_run_id": WORKER_RUN_ID,
        }
        permit_context = SigningContext(
            role="permit_authority", signer=self.keys["permit_authority"],
            trusted_keys=self.trusted_keys, journal=journal,
            verify_candidate_scope=lambda observed: observed == request,
        )
        permit_output, permit_errors = io.StringIO(), io.StringIO()
        self.assertEqual(signing_cli_main(
            ["--role", "permit_authority"], context=permit_context,
            stdin=io.StringIO(json.dumps(request)), stdout=permit_output,
            stderr=permit_errors,
        ), 0)
        self.assertEqual(permit_errors.getvalue(), "")
        permit = json.loads(permit_output.getvalue())
        self.assertEqual(permit["payload"]["issuer_role"], "permit_authority")
        self.assertEqual(journal.snapshot().sequence, 1)

        witness_request = {"witness_id": "witness-key", "permit": permit}
        witness_context = SigningContext(
            role="witness", signer=self.keys["witness"],
            trusted_keys=self.trusted_keys, journal=journal,
            verify_candidate_scope=lambda observed: (
                observed["repository_id"] == REPOSITORY_ID
                and observed["candidate_digest"] == request["candidate_digest"]
                and observed["permit"] == permit
            ),
        )
        witness_output, witness_errors = io.StringIO(), io.StringIO()
        self.assertEqual(signing_cli_main(
            ["--role", "witness"], context=witness_context,
            stdin=io.StringIO(json.dumps(witness_request)), stdout=witness_output,
            stderr=witness_errors,
        ), 0)
        witness = json.loads(witness_output.getvalue())
        self.assertEqual(witness_errors.getvalue(), "")
        self.assertEqual(witness["payload"]["issuer_role"], "witness")
        self.assertNotEqual(permit["key_id"], witness["key_id"])
        self.assertNotEqual(
            self.trusted_keys[permit["key_id"]].public_key,
            self.trusted_keys[witness["key_id"]].public_key,
        )

    def test_signing_cli_delegate_a_and_b_are_separate_and_consumable(self) -> None:
        from f4_limited_delegation import (
            build_delegation_payload, combine_candidate_authorization_fragments,
            verify_delegation_contract, verify_publisher_candidate_authorization,
        )

        evidence = self._delegation_case()[2]
        delegate_keys = {
            "owner_a_delegate": Ed25519PrivateKey.generate(),
            "owner_b_delegate": Ed25519PrivateKey.generate(),
        }
        delegate_entries = {
            role: {"key_id": role + "-cli-fixture",
                   "public_key": base64.b64encode(public_bytes(key)).decode("ascii")}
            for role, key in delegate_keys.items()
        }
        payload = build_delegation_payload(
            delegation_id="cli-limited-delegation",
            execution_revision=BASE_SHA,
            cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
            allowed_paths=(PATH,), not_before="2026-11-19T02:00:00Z",
            expires_at="2026-11-19T04:00:00Z", revocation_sequence=1,
            delegates=delegate_entries,
        )
        contract = {
            "schema": 1, "state": "SIGNED_DELEGATION", "payload": payload,
            "approvals": {
                role: sign_envelope(key_id=role + "-key", private_key=self.keys[role], payload=payload)
                for role in ("owner_a", "owner_b")
            },
        }
        status = {"delegation_id": "cli-limited-delegation", "sequence": 1, "status": "ACTIVE"}
        verify_revocation = lambda observed, scope: (
            observed == status and scope["delegation_id"] == status["delegation_id"]
        )
        verified = verify_delegation_contract(
            envelope=contract, trusted_owner_keys=self.trusted_keys,
            expected_execution_revision=BASE_SHA,
            expected_cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
            revocation_status=status, verify_revocation_status=verify_revocation,
            now=F4_NOW,
        )

        def verify_evidence(observed, scope):
            return observed == evidence and scope.digest == verified.digest

        request = {
            "delegation_envelope": contract,
            "revocation_status": status,
            "evidence": evidence,
        }
        fragments = []
        for role in ("owner_a_delegate", "owner_b_delegate"):
            context = SigningContext(
                role=role, signer=delegate_keys[role],
                trusted_owner_keys=self.trusted_keys,
                expected_execution_revision=BASE_SHA,
                expected_cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
                verify_revocation_status=verify_revocation,
                verify_candidate_evidence=verify_evidence, now=F4_NOW,
            )
            fragments.append(issue_from_cli_request(role, request, context=context))
        authorization = combine_candidate_authorization_fragments(
            delegation=verified, fragments=fragments,
        )
        self.assertEqual(set(authorization["signatures"]), set(delegate_keys))
        self.assertTrue(verify_publisher_candidate_authorization(
            delegation_envelope=contract, trusted_owner_keys=self.trusted_keys,
            expected_execution_revision=BASE_SHA,
            expected_cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
            revocation_status=status, verify_revocation_status=verify_revocation,
            authorization=authorization, evidence=evidence,
            verify_candidate_evidence=verify_evidence, now=F4_NOW,
        ))

        tampered = {**request, "evidence": {**evidence, "candidate_digest": "0" * 64}}
        with self.assertRaisesRegex(SigningCliHold, "delegate_fragment_issue_failed"):
            issue_from_cli_request("owner_a_delegate", tampered, context=SigningContext(
                role="owner_a_delegate", signer=delegate_keys["owner_a_delegate"],
                trusted_owner_keys=self.trusted_keys,
                expected_execution_revision=BASE_SHA,
                expected_cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
                verify_revocation_status=verify_revocation,
                verify_candidate_evidence=verify_evidence, now=F4_NOW,
            ))

    def test_signing_cli_fails_closed_without_role_provider_or_scope(self) -> None:
        output, errors = io.StringIO(), io.StringIO()
        self.assertEqual(signing_cli_main(
            ["--role", "permit_authority"], context=None,
            stdin=io.StringIO("{}"), stdout=output, stderr=errors,
        ), 78)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "HOLD:trusted_role_signer_provider_not_configured\n")

        journal = PermitCasJournal(MemoryCasBackend(), repository_id=REPOSITORY_ID)
        request = {
            "permit_id": "cli-missing-scope",
            "issuer_id": "permit_authority-key", "repository_id": REPOSITORY_ID,
            "base_sha": BASE_SHA, "candidate_digest": self.manifest["candidate_digest"],
            "changed_paths": [PATH], "worker_run_id": WORKER_RUN_ID,
        }
        context = SigningContext(
            role="permit_authority", signer=self.keys["permit_authority"],
            trusted_keys=self.trusted_keys, journal=journal,
        )
        with self.assertRaisesRegex(SigningCliHold, "signer_role_context_mismatch"):
            issue_from_cli_request(
                "permit_authority", request,
                context=SigningContext(
                    role="witness", signer=self.keys["permit_authority"],
                    trusted_keys=self.trusted_keys, journal=journal,
                    verify_candidate_scope=lambda _observed: True,
                ),
            )
        with self.assertRaisesRegex(SigningCliHold, "candidate_scope_verifier_missing"):
            issue_from_cli_request("permit_authority", request, context=context)
        self.assertEqual(journal.snapshot().sequence, 0)

    def _delegation_case(self):
        """Build an ephemeral, real-Ed25519 test delegation and candidate."""
        verified_bundle = self.verify()
        delegate_keys = {
            "owner_a_delegate": Ed25519PrivateKey.generate(),
            "owner_b_delegate": Ed25519PrivateKey.generate(),
        }
        delegates = {
            role: {"key_id": role + "-fixture",
                   "public_key": base64.b64encode(public_bytes(key)).decode("ascii")}
            for role, key in delegate_keys.items()
        }
        payload = build_delegation_payload(
            delegation_id="fixture-limited-delegation-1", execution_revision=BASE_SHA,
            cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"), allowed_paths=(PATH,),
            not_before="2026-11-19T02:00:00Z", expires_at="2026-11-19T04:00:00Z",
            revocation_sequence=1, delegates=delegates,
        )
        contract = {
            "schema": 1, "state": "SIGNED_DELEGATION", "payload": payload,
            "approvals": {
                role: sign_envelope(key_id=role + "-key", private_key=self.keys[role], payload=payload)
                for role in ("owner_a", "owner_b")
            },
        }
        status = {"delegation_id": "fixture-limited-delegation-1", "sequence": 1, "status": "ACTIVE"}
        verify_revocation = lambda observed, scope: (
            observed == status and scope["delegation_id"] == status["delegation_id"]
        )
        verified_delegation = verify_delegation_contract(
            envelope=contract, trusted_owner_keys=self.trusted_keys,
            expected_execution_revision=BASE_SHA,
            expected_cycle_tasks=("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
            revocation_status=status, verify_revocation_status=verify_revocation,
            now=F4_NOW,
        )
        snapshot = self.journal.snapshot()
        provenance_digest = hashlib.sha256(b"fixture worker provenance receipt").hexdigest()
        evidence = {
            "repository_id": REPOSITORY_ID, "execution_revision": BASE_SHA,
            "task_id": "fixture-f4-task-cycle1", "cycle_number": 1,
            "run_id": WORKER_RUN_ID, "changed_paths": [PATH],
            "file_sha256": dict(verified_bundle.file_sha256),
            "candidate_digest": verified_bundle.candidate_digest,
            "permit_digest": verified_bundle.permit_digest,
            "witness_digest": verified_bundle.witness_digest,
            "cas_revision": snapshot.sequence, "cas_head_sha256": snapshot.head_sha256,
            "worker_provenance_digest": provenance_digest, "cycle1_audit_digest": None,
            "issued_at": "2026-11-19T02:30:00Z", "expires_at": "2026-11-19T03:30:00Z",
        }

        def verify_candidate(observed, _delegation):
            current = self.journal.snapshot()
            return (observed == evidence
                    and verified_bundle.candidate_digest == self.manifest["candidate_digest"]
                    and current.sequence == snapshot.sequence
                    and current.head_sha256 == snapshot.head_sha256
                    and provenance_digest == observed["worker_provenance_digest"])

        fragments = [
            issue_candidate_authorization_for_role(
                delegation=verified_delegation, role=role, evidence=evidence,
                verify_candidate_evidence=verify_candidate, signer=key, now=F4_NOW,
            )
            for role, key in delegate_keys.items()
        ]
        authorization = combine_candidate_authorization_fragments(
            delegation=verified_delegation, fragments=fragments,
        )
        return contract, status, evidence, authorization, verify_candidate

    def _delegation_verifier_kwargs(self, case):
        contract, status, evidence, authorization, evidence_verifier = case
        verify_revocation = lambda observed, scope: (
            observed == status and scope["delegation_id"] == status["delegation_id"]
        )
        return {
            "delegation_envelope": contract, "trusted_owner_keys": self.trusted_keys,
            "expected_execution_revision": BASE_SHA,
            "expected_cycle_tasks": ("fixture-f4-task-cycle1", "fixture-f4-task-cycle2"),
            "revocation_status": status, "verify_revocation_status": verify_revocation,
            "authorization": authorization, "evidence": evidence,
            "verify_candidate_evidence": evidence_verifier, "now": F4_NOW,
        }

    def _new_store(self, filename: str) -> DurableStore:
        return DurableStore(Path(self.temporary.name) / filename)


if __name__ == "__main__":
    unittest.main()
