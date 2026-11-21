"""Local-only tests for the DRAFT_HOLD isolation reference model."""
from __future__ import annotations

import unittest

from isolated_runtime import (
    BoundaryError,
    HashJournal,
    IsolatedRuntime,
    Principal,
    Role,
    SafeStop,
)


PATHS = ("ops/command-tower/isolated_runtime.py", "ops/command-tower/test_isolated_runtime.py")


def runtime() -> IsolatedRuntime:
    return IsolatedRuntime(
        worker=Principal("worker-1", Role.WORKER),
        publisher=Principal("publisher-1", Role.PUBLISHER),
        auditor=Principal("auditor-1", Role.AUDITOR),
        witness=Principal("witness-1", Role.WITNESS),
        permit_authority=Principal("authority-1", Role.PERMIT_AUTHORITY),
        allowed_paths=PATHS,
    )


def prepared_flow(rt: IsolatedRuntime):
    candidate = rt.create_candidate(rt.worker, branch="feature/local-proof", paths=PATHS,
                                    content_digest="fixture-content-sha256")
    permit = rt.issue_permit(rt.permit_authority, candidate, permit_id="permit-001")
    witness = rt.witness_permit(rt.witness, permit)
    plan = rt.prepare_publication(rt.publisher, candidate, permit, witness)
    return candidate, permit, witness, plan


class IsolatedRuntimeTests(unittest.TestCase):
    def test_roles_must_be_distinct(self) -> None:
        with self.assertRaises(BoundaryError):
            IsolatedRuntime(worker=Principal("same", Role.WORKER),
                            publisher=Principal("same", Role.PUBLISHER),
                            auditor=Principal("audit", Role.AUDITOR),
                            witness=Principal("witness", Role.WITNESS),
                            permit_authority=Principal("authority", Role.PERMIT_AUTHORITY),
                            allowed_paths=PATHS)

    def test_unauthorized_actor_cannot_create_candidate(self) -> None:
        rt = runtime()
        with self.assertRaises(BoundaryError):
            rt.create_candidate(rt.publisher, branch="feature/x", paths=PATHS,
                                content_digest="fixture")

    def test_candidate_rejects_unapproved_path(self) -> None:
        rt = runtime()
        with self.assertRaises(BoundaryError):
            rt.create_candidate(rt.worker, branch="feature/x",
                                paths=(".github/workflows/deploy.yml",), content_digest="fixture")

    def test_permit_witness_and_publisher_produce_only_local_hold_plan(self) -> None:
        rt = runtime()
        _, _, _, plan = prepared_flow(rt)
        self.assertEqual(plan.state, "DRAFT_HOLD")
        self.assertEqual(plan.repository, "not60/sake-autonomy-public-sandbox-20261115")
        self.assertEqual(rt.state, "DRAFT_HOLD")
        self.assertTrue(rt.journal.verify())
        self.assertEqual(rt.journal.entries[-1].event, "LOCAL_PLAN_PREPARED")

    def test_permit_replay_enters_safe_stop(self) -> None:
        rt = runtime()
        candidate, permit, witness, _ = prepared_flow(rt)
        with self.assertRaises(SafeStop):
            rt.prepare_publication(rt.publisher, candidate, permit, witness)
        self.assertEqual(rt.state, "SAFE_STOPPED")
        self.assertEqual(rt.stop_reason, "permit_replay")
        self.assertEqual(rt.journal.entries[-1].event, "SAFE_STOP")

    def test_mismatched_witness_enters_safe_stop(self) -> None:
        rt = runtime()
        candidate = rt.create_candidate(rt.worker, branch="feature/local-proof", paths=PATHS,
                                        content_digest="fixture-content-sha256")
        permit = rt.issue_permit(rt.permit_authority, candidate, permit_id="permit-002")
        with self.assertRaises(SafeStop):
            rt.prepare_publication(rt.publisher, candidate, permit,
                                   type("Forged", (), {"permit_digest": "bad", "witness_id": "wrong"})())
        self.assertEqual(rt.stop_reason, "witness_mismatch")

    def test_fabricated_attestation_is_rejected(self) -> None:
        rt = runtime()
        candidate = rt.create_candidate(rt.worker, branch="feature/local-proof", paths=PATHS,
                                        content_digest="fixture-content-sha256")
        permit = rt.issue_permit(rt.permit_authority, candidate, permit_id="permit-fabricated")
        fabricated = type("Forged", (), {"permit_digest": permit.digest(),
                                          "witness_id": rt.witness.principal_id})()
        with self.assertRaises(SafeStop):
            rt.prepare_publication(rt.publisher, candidate, permit, fabricated)
        self.assertEqual(rt.stop_reason, "witness_mismatch")

    def test_permit_ids_cannot_be_reissued(self) -> None:
        rt = runtime()
        candidate = rt.create_candidate(rt.worker, branch="feature/local-proof", paths=PATHS,
                                        content_digest="fixture-content-sha256")
        rt.issue_permit(rt.permit_authority, candidate, permit_id="permit-unique")
        with self.assertRaises(BoundaryError):
            rt.issue_permit(rt.permit_authority, candidate, permit_id="permit-unique")

    def test_distinct_auditor_verifies_journaled_plan(self) -> None:
        rt = runtime()
        _, _, _, plan = prepared_flow(rt)
        self.assertTrue(rt.audit_plan(rt.auditor, plan))
        self.assertEqual(rt.journal.entries[-1].event, "PLAN_AUDITED")
        self.assertTrue(rt.journal.verify())

    def test_journal_detects_tampering(self) -> None:
        journal = HashJournal()
        journal.append("FIRST", item="one")
        journal.append("SECOND", item="two")
        self.assertTrue(journal.verify())
        tampered = list(journal.entries)
        tampered[0] = type(tampered[0])(tampered[0].sequence, "ALTERED", tampered[0].payload,
                                        tampered[0].previous_hash, tampered[0].entry_hash)
        journal._entries = tampered
        self.assertFalse(journal.verify())

    def test_explicit_safe_stop_blocks_followup_work(self) -> None:
        rt = runtime()
        rt.safe_stop("owner_hold")
        with self.assertRaises(SafeStop):
            rt.create_candidate(rt.worker, branch="feature/x", paths=PATHS, content_digest="fixture")


if __name__ == "__main__":
    unittest.main()
