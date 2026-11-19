"""Local-only F4 CAS control and cross-run Auditor artifact integration tests."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import f4_cycle_control
from attestations import canonical_json
from cas_journal import CasConflict, CasValue
from f4_cycle_control import (
    AUDIT_ARTIFACT_NAME,
    AUDIT_WORKFLOW_PATH,
    CONTROL_KEY,
    CycleControlHold,
    F4CycleControlJournal,
    GitHubArtifactProvenanceReader,
    build_cycle1_auditor_artifact,
)
from f4_go_gate import F4_SOURCE_PATHS, build_f4_go_candidate, verify_f4_go_candidate
from test_f4_go_gate import EphemeralEd25519, NOW
from trusted_key_registry import TrustedVerificationKey


BASE_SHA = "a" * 40
VALID_FROM = "2026-11-18T02:00:00Z"
EXPIRES_AT = "2026-11-18T04:00:00Z"
APPROVAL_ID = "fixture-f4-cycle-control"


class MemoryCasBackend:
    """Test-only atomic ETag fixture; it is not evidence of external CAS."""

    def __init__(self) -> None:
        self.value = None
        self.revision = 0

    def read(self, key: str):
        if key != CONTROL_KEY:
            raise AssertionError("unexpected CAS key")
        return None if self.value is None else CasValue(self.value.body, self.value.version)

    def compare_and_swap(self, key: str, version: str | None, body: bytes) -> str:
        if key != CONTROL_KEY:
            raise AssertionError("unexpected CAS key")
        if (self.value is None) != (version is None):
            raise CasConflict("fixture CAS conflict")
        if self.value is not None and self.value.version != version:
            raise CasConflict("fixture CAS conflict")
        self.revision += 1
        next_version = str(self.revision)
        self.value = CasValue(body, next_version)
        return next_version


class F4CycleControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="b12-f4-cycle-control-")
        self.root = Path(self.temp.name)
        for relative in F4_SOURCE_PATHS:
            target = self.root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("test-only source " + relative + "\n").encode())
        self.keys = EphemeralEd25519(self.root)
        auditor_root = self.root / "auditor-test-keys"
        auditor_root.mkdir()
        self.auditor_test_keys = EphemeralEd25519(auditor_root)
        self.owner_keys = {
            role + "-test-key": TrustedVerificationKey(
                role + "-test-key", role, self.keys.public_keys[role],
            )
            for role in ("permit_authority", "witness", "owner_a", "owner_b")
        }
        self.auditor_key = TrustedVerificationKey(
            "auditor-test-key", "auditor", self.auditor_test_keys.public_keys["witness"],
        )
        self.candidate = self._go_candidate()
        self.revocation = self._revocation(sequence=1, status="ACTIVE")
        self.initial_f4_status = {
            "approval_id": APPROVAL_ID, "sequence": 1, "status": "ACTIVE",
        }
        self.verify_patch = patch("f4_go_gate._verify_ed25519", self.keys.verify)
        self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)
        self.control_verify_patch = patch("f4_cycle_control._verify_ed25519", self.keys.verify)
        self.control_verify_patch.start()
        self.addCleanup(self.control_verify_patch.stop)
        self.go = verify_f4_go_candidate(
            candidate=self.candidate, workspace=self.root,
            expected_repository_id=1458303357, expected_base_sha=BASE_SHA,
            trusted_keys=self.owner_keys, revocation_status=self.initial_f4_status,
            verify_revocation_status=lambda value: value == self.initial_f4_status, now=NOW,
        )
        self.backend = MemoryCasBackend()
        self.control = F4CycleControlJournal(
            self.backend,
            trusted_signing_keys=self.owner_keys,
            trusted_auditor_key=self.auditor_key,
        )
        self.control.initialize(
            candidate=self.candidate, go=self.go,
            revocation_status=self.revocation, now=NOW,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _go_candidate(self):
        draft = build_f4_go_candidate(
            workspace=self.root, base_sha=BASE_SHA, approval_id=APPROVAL_ID,
            not_before=VALID_FROM, expires_at=EXPIRES_AT, revocation_sequence=1,
        )
        payload = draft["payload"]
        approvals = {}
        for role in ("owner_a", "owner_b"):
            approvals[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(
                    self.keys.sign(role, canonical_json(payload)),
                ).decode("ascii"),
                "payload": payload,
            }
        return {**draft, "state": "SIGNED_GO", "approvals": approvals}

    def _revocation(self, *, sequence: int, status: str):
        payload = {
            "schema": 1, "kind": "F4_REVOCATION_STATUS",
            "repository_id": 1458303357, "approval_id": APPROVAL_ID,
            "go_sha256": hashlib.sha256(canonical_json(self.candidate)).hexdigest()
            if hasattr(self, "candidate") else "0" * 64,
            "sequence": sequence, "status": status,
            "valid_from": "2026-11-18T02:00:00Z",
            "valid_until": "2026-11-18T03:59:00Z",
        }
        approvals = {}
        for role in ("owner_a", "owner_b"):
            approvals[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(
                    self.keys.sign(role, canonical_json(payload)),
                ).decode("ascii"),
                "payload": payload,
            }
        return {"payload": payload, "approvals": approvals}

    def _artifact(self):
        payload = {
            "schema": 1, "kind": "F4_CYCLE_AUDIT",
            "repository_id": 1458303357, "approval_id": APPROVAL_ID,
            "go_sha256": hashlib.sha256(canonical_json(self.candidate)).hexdigest(),
            "cycle_number": 1, "worker_run_id": "run-101:1:worker",
            "auditor_run_id": "run-101:1:auditor", "workflow_run_id": "101",
            "run_attempt": 1, "workflow_path": AUDIT_WORKFLOW_PATH,
            "source_commit_sha": "b" * 40, "base_sha": BASE_SHA,
            "pr_number": 1, "pr_state": "open", "pr_is_draft": True,
            "pr_merged": False, "pr_head_sha": "b" * 40, "pr_base_sha": BASE_SHA,
            "readonly_ci_run_id": "ci-101", "readonly_ci_conclusion": "success",
            "permit_id": "permit-cycle1", "candidate_digest": "c" * 64,
            "witness_digest": "d" * 64, "journal_revision": 2,
            "journal_head_sha256": "e" * 64, "result": "PASS",
            "issued_at": "2026-11-18T03:00:00Z", "expires_at": "2026-11-18T03:30:00Z",
        }
        return build_cycle1_auditor_artifact(
            payload=payload, key_id=self.auditor_key.key_id,
            private_key=type("EphemeralSigner", (), {
                "sign": lambda _self, message: self.auditor_test_keys.sign("witness", message),
            })(),
        )

    @staticmethod
    def _provenance(payload):
        return {
            "repository_id": payload["repository_id"],
            "workflow_run_id": payload["workflow_run_id"],
            "run_attempt": payload["run_attempt"],
            "workflow_path": payload["workflow_path"],
            "source_commit_sha": payload["source_commit_sha"],
            "artifact_name": AUDIT_ARTIFACT_NAME,
            "artifact_id": 9001,
            "archive_digest": "sha256:" + "f" * 64,
            "expired": False,
        }

    def test_cycle1_auditor_artifact_pass_enables_cycle2_once(self) -> None:
        state = self.control.claim_cycle(
            candidate=self.candidate, go=self.go, cycle_number=1,
            run_id="run-101:1:worker", source_commit_sha="b" * 40, now=NOW,
        )
        self.assertEqual(state.sequence, 2)
        artifact = self._artifact()
        with self.assertRaisesRegex(CycleControlHold, "cycle1_auditor_artifact_required"):
            self.control.claim_cycle(
                candidate=self.candidate, go=self.go, cycle_number=2,
                run_id="run-102:1:worker", source_commit_sha="c" * 40, now=NOW,
            )
        audited = self.control.record_cycle1_auditor_pass(
            candidate=self.candidate, go=self.go, artifact=artifact,
            verify_github_artifact=self._provenance, now=NOW,
        )
        self.assertEqual(audited.sequence, 3)
        cycle2 = self.control.claim_cycle(
            candidate=self.candidate, go=self.go, cycle_number=2,
            run_id="run-102:1:worker", source_commit_sha="c" * 40,
            cycle1_auditor_artifact=artifact,
            verify_github_artifact=self._provenance, now=NOW,
        )
        self.assertEqual(cycle2.sequence, 4)
        with self.assertRaisesRegex(CycleControlHold, "cycle_duplicate_or_out_of_order"):
            self.control.claim_cycle(
                candidate=self.candidate, go=self.go, cycle_number=2,
                run_id="run-103:1:worker", source_commit_sha="c" * 40,
                cycle1_auditor_artifact=artifact,
                verify_github_artifact=self._provenance, now=NOW,
            )

    def test_tampered_artifact_and_missing_github_provenance_fail_closed(self) -> None:
        self.control.claim_cycle(
            candidate=self.candidate, go=self.go, cycle_number=1,
            run_id="run-101:1:worker", source_commit_sha="b" * 40, now=NOW,
        )
        artifact = self._artifact()
        changed = {**artifact, "payload": {**artifact["payload"], "result": "FAIL"}}
        with self.assertRaisesRegex(CycleControlHold, "payload_scope_invalid"):
            self.control.record_cycle1_auditor_pass(
                candidate=self.candidate, go=self.go, artifact=changed,
                verify_github_artifact=self._provenance, now=NOW,
            )
        with self.assertRaisesRegex(CycleControlHold, "github_artifact_provenance_verifier_missing"):
            self.control.record_cycle1_auditor_pass(
                candidate=self.candidate, go=self.go, artifact=artifact,
                verify_github_artifact=None, now=NOW,
            )
        self.assertEqual(self.control.read().sequence, 2)

    def test_mutated_verified_go_candidate_cannot_claim_cycle(self) -> None:
        changed = {**self.candidate, "payload": dict(self.candidate["payload"])}
        changed["payload"]["scope"] = {
            **changed["payload"]["scope"], "max_worker_cycles": 3,
        }
        with self.assertRaisesRegex(CycleControlHold, "candidate_binding_mismatch"):
            self.control.claim_cycle(
                candidate=changed, go=self.go, cycle_number=1,
                run_id="run-101:1:worker", source_commit_sha="b" * 40, now=NOW,
            )
        self.assertEqual(self.control.read().sequence, 1)

    def test_signed_revocation_blocks_cycle_and_status_replay(self) -> None:
        stopped = self._revocation(sequence=2, status="REVOKED")
        state = self.control.set_revocation(
            candidate=self.candidate, go=self.go,
            revocation_status=stopped, now=NOW,
        )
        self.assertEqual(state.sequence, 2)
        with self.assertRaisesRegex(CycleControlHold, "f4_go_revoked_or_stopped"):
            self.control.claim_cycle(
                candidate=self.candidate, go=self.go, cycle_number=1,
                run_id="run-101:1:worker", source_commit_sha="b" * 40, now=NOW,
            )
        with self.assertRaisesRegex(CycleControlHold, "revocation_transition_invalid"):
            self.control.set_revocation(
                candidate=self.candidate, go=self.go,
                revocation_status=stopped, now=NOW,
            )

    def test_cas_ambiguity_is_not_retried(self) -> None:
        class AmbiguousBackend(MemoryCasBackend):
            def __init__(self):
                super().__init__()
                self.fail = False
                self.calls = 0

            def compare_and_swap(self, key, version, body):
                self.calls += 1
                if self.fail:
                    raise CasConflict("fixture stale ETag")
                return super().compare_and_swap(key, version, body)

        backend = AmbiguousBackend()
        control = F4CycleControlJournal(
            backend,
            trusted_signing_keys=self.owner_keys,
            trusted_auditor_key=self.auditor_key,
        )
        control.initialize(candidate=self.candidate, go=self.go,
                            revocation_status=self.revocation, now=NOW)
        backend.fail = True
        with self.assertRaisesRegex(CycleControlHold, "cas_conflict_no_retry"):
            control.claim_cycle(candidate=self.candidate, go=self.go, cycle_number=1,
                                run_id="run-101:1:worker", source_commit_sha="b" * 40,
                                now=NOW)
        self.assertEqual(backend.calls, 2)
        self.assertEqual(control.read().sequence, 1)

    def test_github_artifact_reader_binds_run_path_sha_and_archive_digest(self) -> None:
        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                import json
                return json.dumps(self.body).encode("utf-8")

        responses = [
            Response({
                "id": 101, "run_attempt": 1, "path": AUDIT_WORKFLOW_PATH,
                "head_sha": "b" * 40, "status": "completed", "conclusion": "success",
                "repository": {"id": 1458303357},
            }),
            Response({"artifacts": [{
                "id": 9001, "name": AUDIT_ARTIFACT_NAME, "expired": False,
                "digest": "sha256:" + "f" * 64, "workflow_run": {"id": 101},
            }]}),
        ]
        requests = []

        def opener(request, timeout):
            requests.append(request)
            self.assertEqual(timeout, 4)
            return responses.pop(0)

        reader = GitHubArtifactProvenanceReader(
            bearer_token="test-only-unprinted-token", timeout=4, opener=opener,
        )
        payload = {
            "workflow_run_id": "101", "run_attempt": 1,
            "source_commit_sha": "b" * 40,
        }
        provenance = reader(payload)
        self.assertEqual(provenance["artifact_id"], 9001)
        self.assertEqual(provenance["archive_digest"], "sha256:" + "f" * 64)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(request.get_method() == "GET" for request in requests))

    def test_github_artifact_reader_rejects_wrong_source_revision(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                import json
                return json.dumps({
                    "id": 101, "run_attempt": 1, "path": AUDIT_WORKFLOW_PATH,
                    "head_sha": "c" * 40, "status": "completed", "conclusion": "success",
                    "repository": {"id": 1458303357},
                }).encode("utf-8")

        reader = GitHubArtifactProvenanceReader(
            bearer_token="test-only", opener=lambda *_args, **_kwargs: Response(),
        )
        with self.assertRaisesRegex(CycleControlHold, "workflow_run_mismatch"):
            reader({
                "workflow_run_id": "101", "run_attempt": 1,
                "source_commit_sha": "b" * 40,
            })


if __name__ == "__main__":
    unittest.main()
