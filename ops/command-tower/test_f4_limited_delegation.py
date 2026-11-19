"""Focused contract tests; Ed25519 primitive is mocked, external adapters are fixtures."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import unittest
from unittest.mock import patch

from attestations import canonical_json
import f4_limited_delegation as delegation
from publisher_gate import PublisherGate
from f4_auditor_artifact import verify_limited_delegation as auditor_verify_limited_delegation
from trusted_key_registry import TrustedVerificationKey


NOW = datetime(2026, 11, 19, 3, 0, tzinfo=timezone.utc)
REVISION = "a" * 40
TASK = "fixture-task-17"
TASK_2 = "fixture-task-18"
TASKS = (TASK, TASK_2)


def signature(public_key: bytes, message: bytes) -> bytes:
    return hashlib.sha512(public_key + message).digest()


def verify_signature(public_key: bytes, signed: bytes, message: bytes) -> None:
    if signature(public_key, message) != signed:
        raise ValueError("fixture signature mismatch")


class FixtureSigner:
    def __init__(self, public_key: bytes) -> None:
        self.public_key = public_key

    def sign(self, message: bytes) -> bytes:
        return signature(self.public_key, message)


class LimitedDelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.patch = patch.object(delegation, "_verify_ed25519", verify_signature)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        roles = ("permit_authority", "witness", "owner_a", "owner_b")
        self.trusted = {
            role + "-root": TrustedVerificationKey(role + "-root", role, bytes([i]) * 32)
            for i, role in enumerate(roles, 1)
        }
        self.delegate_public = {
            "owner_a_delegate": bytes([11]) * 32,
            "owner_b_delegate": bytes([12]) * 32,
        }
        delegate_docs = {
            role: {"key_id": role + "-key", "public_key": base64.b64encode(key).decode("ascii")}
            for role, key in self.delegate_public.items()
        }
        self.payload = delegation.build_delegation_payload(
            delegation_id="fixture-delegation-1", execution_revision=REVISION,
            cycle_tasks=TASKS, allowed_paths=("ops/command-tower/example.py",),
            not_before="2026-11-19T02:00:00Z", expires_at="2026-11-19T04:00:00Z",
            revocation_sequence=3, delegates=delegate_docs,
        )
        self.contract = {
            "schema": 1, "state": "SIGNED_DELEGATION", "payload": self.payload,
            "approvals": {
                role: {"key_id": role + "-root",
                       "signature": base64.b64encode(signature(self.trusted[role + "-root"].public_key,
                                                                 canonical_json(self.payload))).decode("ascii"),
                       "payload": self.payload}
                for role in ("owner_a", "owner_b")
            },
        }
        self.status = {"delegation_id": "fixture-delegation-1", "sequence": 3, "status": "ACTIVE"}
        self.verified = self._verify_contract()
        self.evidence = {
            "repository_id": delegation.REPOSITORY_ID,
            "execution_revision": REVISION, "task_id": TASK,
            "cycle_number": 1, "run_id": "fixture-run-1",
            "changed_paths": ["ops/command-tower/example.py"],
            "file_sha256": {"ops/command-tower/example.py": "1" * 64},
            "candidate_digest": "2" * 64, "permit_digest": "3" * 64,
            "witness_digest": "4" * 64, "cas_revision": 9,
            "cas_head_sha256": "5" * 64, "worker_provenance_digest": "6" * 64,
            "cycle1_audit_digest": None,
            "issued_at": "2026-11-19T02:30:00Z", "expires_at": "2026-11-19T03:30:00Z",
        }

    def _verify_contract(self, envelope=None, status=None):
        return delegation.verify_delegation_contract(
            envelope=self.contract if envelope is None else envelope,
            trusted_owner_keys=self.trusted, expected_execution_revision=REVISION,
            expected_cycle_tasks=TASKS,
            revocation_status=self.status if status is None else status,
            verify_revocation_status=lambda observed, payload: (
                observed == self.status and payload["delegation_id"] == observed["delegation_id"]
            ), now=NOW,
        )

    def _issue(self, evidence=None, evidence_verifier=lambda _e, _d: True):
        observed = self.evidence if evidence is None else evidence
        fragments = [
            delegation.issue_candidate_authorization_for_role(
                delegation=self.verified, role=role, evidence=observed,
                verify_candidate_evidence=evidence_verifier,
                signer=FixtureSigner(self.delegate_public[role]), now=NOW,
            )
            for role in self.delegate_public
        ]
        return delegation.combine_candidate_authorization_fragments(
            delegation=self.verified, fragments=fragments,
        )

    def _entry_args(self, auth, evidence=None, evidence_verifier=lambda _e, _d: True):
        return {
            "delegation_envelope": self.contract, "trusted_owner_keys": self.trusted,
            "expected_execution_revision": REVISION, "expected_cycle_tasks": TASKS,
            "revocation_status": self.status,
            "verify_revocation_status": lambda observed, payload: (
                observed == self.status and payload["delegation_id"] == self.status["delegation_id"]
            ),
            "authorization": auth, "evidence": self.evidence if evidence is None else evidence,
            "verify_candidate_evidence": evidence_verifier, "now": NOW,
        }

    def test_owner_dual_signature_and_candidate_auth_verify_for_publisher_and_auditor(self):
        auth = self._issue()
        verifier = lambda _evidence, verified: verified.digest == self.verified.digest
        publisher_digest = PublisherGate.verify_limited_delegation(
            **self._entry_args(auth, evidence_verifier=verifier),
        )
        auditor_digest = auditor_verify_limited_delegation(
            **self._entry_args(auth, evidence_verifier=verifier),
        )
        self.assertEqual(publisher_digest, auditor_digest)

    def test_single_role_signers_combine_and_both_consumers_verify(self):
        fragments = []
        for role, key in self.delegate_public.items():
            fragments.append(delegation.issue_candidate_authorization_for_role(
                delegation=self.verified, role=role, evidence=self.evidence,
                verify_candidate_evidence=lambda _e, _d: True,
                signer=FixtureSigner(key), now=NOW,
            ))
        authorization = delegation.combine_candidate_authorization_fragments(
            delegation=self.verified, fragments=fragments,
        )
        verifier = lambda _evidence, verified: verified.digest == self.verified.digest
        self.assertEqual(
            PublisherGate.verify_limited_delegation(
                **self._entry_args(authorization, evidence_verifier=verifier),
            ),
            auditor_verify_limited_delegation(
                **self._entry_args(authorization, evidence_verifier=verifier),
            ),
        )
        with self.assertRaisesRegex(delegation.DelegationHold, "signer_role_invalid"):
            delegation.issue_candidate_authorization_for_role(
                delegation=self.verified, role="publisher", evidence=self.evidence,
                verify_candidate_evidence=lambda _e, _d: True,
                signer=FixtureSigner(self.delegate_public["owner_a_delegate"]), now=NOW,
            )
        with self.assertRaisesRegex(delegation.DelegationHold, "payload_mismatch"):
            different_evidence = {**self.evidence, "run_id": "other"}
            other = delegation.issue_candidate_authorization_for_role(
                delegation=self.verified, role="owner_b_delegate", evidence=different_evidence,
                verify_candidate_evidence=lambda _e, _d: True,
                signer=FixtureSigner(self.delegate_public["owner_b_delegate"]), now=NOW,
            )
            delegation.combine_candidate_authorization_fragments(
                delegation=self.verified, fragments=(fragments[0], other),
            )

    def test_missing_owner_or_delegate_signature_and_tampering_fail_closed(self):
        missing_owner = {**self.contract, "approvals": {"owner_a": self.contract["approvals"]["owner_a"]}}
        with self.assertRaisesRegex(delegation.DelegationHold, "both_owner_signatures"):
            self._verify_contract(envelope=missing_owner)
        auth = self._issue()
        tampered = {**auth, "signatures": {**auth["signatures"]}}
        tampered["signatures"]["owner_b_delegate"] = {
            **tampered["signatures"]["owner_b_delegate"],
            "signature": base64.b64encode(b"x" * 64).decode("ascii"),
        }
        with self.assertRaisesRegex(delegation.DelegationHold, "signature_invalid"):
            delegation.verify_publisher_candidate_authorization(
                **self._entry_args(tampered),
            )
        with self.assertRaisesRegex(delegation.DelegationHold, "candidate_paths_invalid"):
            self._issue({**self.evidence, "changed_paths": ["ops/command-tower/f4_go_gate.py"],
                         "file_sha256": {"ops/command-tower/f4_go_gate.py": "1" * 64}})

    def test_expired_or_revoked_delegation_and_unverified_evidence_are_rejected(self):
        with self.assertRaisesRegex(delegation.DelegationHold, "revocation_not_authenticated"):
            delegation.verify_delegation_contract(
                envelope=self.contract, trusted_owner_keys=self.trusted,
                expected_execution_revision=REVISION, expected_cycle_tasks=TASKS,
                revocation_status={**self.status, "status": "REVOKED"},
                verify_revocation_status=lambda _status, _payload: False, now=NOW,
            )
        with self.assertRaisesRegex(delegation.DelegationHold, "not_verified"):
            self._issue(evidence_verifier=lambda _e, _d: False)
        with self.assertRaisesRegex(delegation.DelegationHold, "expired"):
            self._issue(evidence={**self.evidence, "expires_at": "2026-11-19T02:59:00Z"})
        with self.assertRaisesRegex(delegation.DelegationHold, "cycle2_requires_cycle1_audit_digest"):
            self._issue(evidence={**self.evidence, "task_id": TASK_2, "cycle_number": 2})

    def test_two_cycle_task_binding_is_exact_and_distinct(self):
        cycle2 = {**self.evidence, "task_id": TASK_2, "cycle_number": 2,
                  "cycle1_audit_digest": "7" * 64}
        auth = self._issue(evidence=cycle2)
        verifier = lambda observed, verified: (
            observed == cycle2 and verified.cycle_tasks == TASKS
        )
        self.assertTrue(delegation.verify_publisher_candidate_authorization(
            **self._entry_args(auth, evidence=cycle2, evidence_verifier=verifier),
        ))
        with self.assertRaisesRegex(ValueError, "two_distinct_cycle_tasks_required"):
            delegation.build_delegation_payload(
                delegation_id="fixture-duplicate-tasks", execution_revision=REVISION,
                cycle_tasks=(TASK, TASK), allowed_paths=("ops/command-tower/example.py",),
                not_before="2026-11-19T02:00:00Z", expires_at="2026-11-19T04:00:00Z",
                revocation_sequence=4, delegates={
                    role: {"key_id": role + "-key",
                           "public_key": base64.b64encode(key).decode("ascii")}
                    for role, key in self.delegate_public.items()
                },
            )
        with self.assertRaisesRegex(delegation.DelegationHold, "candidate_scope_mismatch"):
            self._issue(evidence={**self.evidence, "task_id": TASK_2})
        with self.assertRaisesRegex(delegation.DelegationHold, "cycle_task_scope_mismatch"):
            delegation.verify_delegation_contract(
                envelope=self.contract, trusted_owner_keys=self.trusted,
                expected_execution_revision=REVISION,
                expected_cycle_tasks=(TASK_2, TASK),
                revocation_status=self.status,
                verify_revocation_status=lambda observed, payload: (
                    observed == self.status and payload["delegation_id"] == self.status["delegation_id"]
                ), now=NOW,
            )

    def test_finite_two_cycle_sequence_stops_on_missing_cycle1_audit(self):
        calls = []
        stops = []
        result = delegation.execute_finite_two_cycles(
            check_revocation=lambda cycle: calls.append(("revoke", cycle)) or True,
            atomic_claim=lambda cycle: calls.append(("claim", cycle)) or True,
            execute_stage=lambda cycle, stage: calls.append((cycle, stage)) or (cycle, stage),
            verify_cycle1_audit=lambda receipt: receipt == (1, "publish-audit"),
            safe_stop=lambda: stops.append("stop") or True,
        )
        self.assertEqual(result.cycles_completed, 2)
        self.assertEqual(len(result.stage_receipts), 4)
        self.assertEqual(stops, ["stop"])
        self.assertEqual([item for item in calls if isinstance(item[0], int)],
                         [(1, "worker"), (1, "publish-audit"), (2, "worker"), (2, "publish-audit")])

        calls.clear()
        with self.assertRaisesRegex(delegation.DelegationHold, "cycle1_independent_audit_not_passed"):
            delegation.execute_finite_two_cycles(
                check_revocation=lambda _cycle: True,
                atomic_claim=lambda _cycle: True,
                execute_stage=lambda cycle, stage: calls.append((cycle, stage)) or (cycle, stage),
                verify_cycle1_audit=lambda _receipt: False,
                safe_stop=lambda: True,
            )
        self.assertNotIn((2, "worker"), calls)

        stopped = []
        with self.assertRaisesRegex(delegation.DelegationHold, "safe_stop_failed_after_cycle2"):
            delegation.execute_finite_two_cycles(
                check_revocation=lambda _cycle: True,
                atomic_claim=lambda _cycle: True,
                execute_stage=lambda cycle, stage: (cycle, stage),
                verify_cycle1_audit=lambda _receipt: True,
                safe_stop=lambda: stopped.append(True) or False,
            )
        self.assertEqual(stopped, [True])


if __name__ == "__main__":
    unittest.main()
