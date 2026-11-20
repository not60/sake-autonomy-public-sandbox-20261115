"""New F4 request, runtime adapter and Auditor handoff tests with test-only keys."""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops/command-tower"))

import f4_auditor_artifact
import f4_cycle_control
import f4_cycle_runtime
import f4_go_gate
from attestations import canonical_json
from f4_auditor_artifact import build_payload, create_artifact
from f4_go_gate import F4_SOURCE_PATHS, build_f4_go_candidate
from f4_go_request import create_request
from test_f4_go_gate import EphemeralEd25519
from trusted_key_registry import TrustedVerificationKey

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
BASE = "b" * 40


class F4RuntimeConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="b12-f4-runtime-connection-")
        self.root = Path(self.temp.name)
        (self.root / "owners").mkdir()
        (self.root / "auditor").mkdir()
        self.owner_signer = EphemeralEd25519(self.root / "owners")
        self.auditor_signer = EphemeralEd25519(self.root / "auditor")
        self.owner_keys = {
            role + "-test-key": TrustedVerificationKey(
                role + "-test-key", role, self.owner_signer.public_keys[role],
            ) for role in ("permit_authority", "witness", "owner_a", "owner_b")
        }
        self.key_document = {"keys": [
            {"key_id": key.key_id, "role": key.role,
             "public_key": base64.b64encode(key.public_key).decode("ascii")}
            for key in self.owner_keys.values()
        ]}
        self.auditor_public = self.auditor_signer.public_keys["witness"]
        self.auditor_document = {
            "key_id": "auditor-fixture", "role": "auditor",
            "public_key": base64.b64encode(self.auditor_public).decode("ascii"),
        }
        self.verify_f4_patch = patch("f4_go_gate._verify_ed25519", self.owner_signer.verify)
        self.verify_cycle_patch = patch("f4_cycle_control._verify_ed25519", self.owner_signer.verify)
        self.verify_f4_patch.start(); self.verify_cycle_patch.start()
        self.addCleanup(self.verify_f4_patch.stop); self.addCleanup(self.verify_cycle_patch.stop)
        self.candidate, self.revocation = self._signed_go()

    def tearDown(self):
        self.temp.cleanup()

    def _signed_go(self):
        draft = build_f4_go_candidate(
            workspace=ROOT, base_sha=BASE, approval_id="fixture-f4-runtime",
            not_before="2026-11-19T00:00:00Z", expires_at="2026-11-19T23:59:00Z",
            revocation_sequence=1,
        )
        payload = draft["payload"]
        approvals = {}
        for role in ("owner_a", "owner_b"):
            approvals[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(self.owner_signer.sign(role, canonical_json(payload))).decode("ascii"),
                "payload": payload,
            }
        candidate = {**draft, "state": "SIGNED_GO", "approvals": approvals}
        go_sha = hashlib.sha256(canonical_json(candidate)).hexdigest()
        rev_payload = {
            "schema": 1, "kind": "F4_REVOCATION_STATUS", "repository_id": 1458303357,
            "approval_id": "fixture-f4-runtime", "go_sha256": go_sha,
            "sequence": 1, "status": "ACTIVE", "valid_from": "2026-11-19T00:00:00Z",
            "valid_until": "2026-11-19T23:00:00Z",
        }
        signatures = {}
        for role in ("owner_a", "owner_b"):
            signatures[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(self.owner_signer.sign(role, canonical_json(rev_payload))).decode("ascii"),
                "payload": rev_payload,
            }
        return candidate, {"payload": rev_payload, "approvals": signatures}

    def test_unsigned_go_request_contains_final_source_hashes_and_never_overwrites(self):
        with tempfile.TemporaryDirectory(prefix="f4-request-out-") as output_dir:
            target = Path(output_dir) / "f4-go-request.json"
            candidate = create_request(
                workspace=ROOT, base_sha=BASE, approval_id="request-only",
                not_before="2026-11-19T00:00:00Z", expires_at="2026-11-19T23:59:00Z",
                revocation_sequence=1, output=target,
            )
            self.assertEqual(candidate["state"], "DRAFT_HOLD")
            self.assertEqual(candidate["approvals"], {})
            self.assertEqual(set(candidate["payload"]["source_sha256s"]), set(F4_SOURCE_PATHS))
            self.assertEqual(json.loads(target.read_text())["state"], "DRAFT_HOLD")
            with self.assertRaises(FileExistsError):
                create_request(
                    workspace=ROOT, base_sha=BASE, approval_id="request-only",
                    not_before="2026-11-19T00:00:00Z", expires_at="2026-11-19T23:59:00Z",
                    revocation_sequence=1, output=target,
                )

    def test_auditor_payload_binds_run_and_pr_head_separately_and_signs_only_auditor(self):
        go_sha = hashlib.sha256(canonical_json(self.candidate)).hexdigest()
        evidence = {
            "schema": 1, "repository_id": 1458303357, "base_sha": BASE,
            "worker_run_id": "77-1", "candidate_digest": "a" * 64,
            "permit_id": "permit-1", "witness_digest": "c" * 64,
            "journal_revision": 2, "journal_head_sha256": "d" * 64,
            "pr_number": 1, "pr_state": "open", "pr_is_draft": True,
            "pr_merged": False, "pr_head_sha": "e" * 40, "pr_base_sha": BASE,
            "readonly_ci_run_id": "88", "readonly_ci_conclusion": "success",
        }
        payload, observed_go_sha = build_payload(
            evidence=evidence, candidate=self.candidate, workspace=ROOT,
            expected_base_sha=BASE, trusted_keys=self.key_document,
            auditor_key_document=self.auditor_document, revocation_envelope=self.revocation,
            workflow_run_id="99", run_attempt=1, source_commit_sha="f" * 40, now=NOW,
        )
        self.assertEqual(observed_go_sha, go_sha)
        self.assertEqual(payload["source_commit_sha"], "f" * 40)
        self.assertEqual(payload["pr_head_sha"], "e" * 40)
        self.assertNotEqual(payload["source_commit_sha"], payload["pr_head_sha"])
        self.assertEqual(payload["auditor_run_id"], "99:1:auditor")

        class TestSigner:
            def sign(_self, message):
                return self.auditor_signer.sign("witness", message)

        with tempfile.TemporaryDirectory(prefix="f4-envelope-out-") as output_dir:
            target = Path(output_dir) / "auditor-envelope.json"
            with patch.object(f4_auditor_artifact, "_SignerProxy", return_value=TestSigner()):
                create_artifact(
                    evidence=evidence, candidate=self.candidate, workspace=ROOT,
                    expected_base_sha=BASE, trusted_keys=self.key_document,
                    auditor_key_document=self.auditor_document, revocation_envelope=self.revocation,
                    workflow_run_id="99", run_attempt=1, source_commit_sha="f" * 40,
                    output=target, now=NOW,
                )
            envelope = json.loads(target.read_text())
            self.assertEqual(envelope["key_id"], "auditor-fixture")
            self.assertEqual(envelope["payload"], payload)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            verified_go = f4_go_gate.verify_f4_go_candidate(
                candidate=self.candidate, workspace=ROOT,
                expected_repository_id=1458303357, expected_base_sha=BASE,
                trusted_keys=self.owner_keys,
                revocation_status={key: self.revocation["payload"][key]
                                   for key in ("approval_id", "sequence", "status")},
                verify_revocation_status=lambda value: True, now=NOW,
            )
            provenance = lambda _: {
                "repository_id": 1458303357, "workflow_run_id": "99", "run_attempt": 1,
                "workflow_path": f4_cycle_control.AUDIT_WORKFLOW_PATH,
                "source_commit_sha": "f" * 40,
                "artifact_name": f4_cycle_control.AUDIT_ARTIFACT_NAME,
                "artifact_id": 901, "archive_digest": "sha256:" + "a" * 64,
                "expired": False,
            }
            verified = f4_cycle_control._verify_auditor_artifact(
                envelope, go=verified_go, go_sha256=go_sha,
                trusted_key=TrustedVerificationKey("auditor-fixture", "auditor", self.auditor_public),
                verify_github_artifact=provenance, now=NOW,
            )
            self.assertEqual(verified.payload["workflow_run_id"], "99")
            tampered = {**envelope, "payload": {**envelope["payload"], "result": "FAIL"}}
            with self.assertRaises(f4_cycle_control.CycleControlHold):
                f4_cycle_control._verify_auditor_artifact(
                    tampered, go=verified_go, go_sha256=go_sha,
                    trusted_key=TrustedVerificationKey("auditor-fixture", "auditor", self.auditor_public),
                    verify_github_artifact=provenance, now=NOW,
                )
            with self.assertRaises(FileExistsError):
                create_artifact(
                    evidence=evidence, candidate=self.candidate, workspace=ROOT,
                    expected_base_sha=BASE, trusted_keys=self.key_document,
                    auditor_key_document=self.auditor_document, revocation_envelope=self.revocation,
                    workflow_run_id="99", run_attempt=1, source_commit_sha="f" * 40,
                    output=target, now=NOW,
                )

    def test_runtime_role_cas_binding_cycle2_and_fail_closed_inputs(self):
        with tempfile.TemporaryDirectory(prefix="f4-runtime-inputs-") as input_dir:
            folder = Path(input_dir)
            values = {
                "candidate.json": self.candidate,
                "revocation.json": self.revocation,
                "trusted.json": self.key_document,
                "auditor.json": self.auditor_document,
                "auditor-envelope.json": {
                    "key_id": "auditor-fixture", "signature": "test",
                    "payload": {"workflow_run_id": "99"},
                },
            }
            for name, value in values.items():
                (folder / name).write_text(json.dumps(value))
            env = {
                "B09_CAS_ENDPOINT": f4_cycle_runtime.CAS_ENDPOINT,
                "B09_F4_CONTROL_V2_WORKER_BEARER": "w" * 40,
                "GITHUB_TOKEN": "g" * 40,
            }
            fake_state = type("State", (), {"sequence": 4, "go_sha256": "a" * 64, "head_sha256": "b" * 64, "version": "4"})()
            with patch("f4_cycle_runtime.verify_f4_go_candidate", return_value=object()), \
                 patch("f4_cycle_runtime.HttpsCasBackend") as backend, \
                 patch("f4_cycle_runtime.F4CycleControlJournal") as journal_class:
                journal = journal_class.return_value
                journal.claim_cycle.return_value = fake_state
                reader = object()
                out = io.StringIO()
                with redirect_stdout(out):
                    result = f4_cycle_runtime.execute(
                        operation="claim-cycle2", workspace=ROOT, expected_base_sha=BASE,
                        candidate_path=folder / "candidate.json", revocation_path=folder / "revocation.json",
                        trusted_keys_path=folder / "trusted.json", auditor_key_path=folder / "auditor.json",
                        env=env, cycle=2, run_id="100-1-cycle-2", source_commit_sha="b" * 40,
                        auditor_artifact_path=folder / "auditor-envelope.json",
                        cycle1_auditor_run_id="99", provenance_reader=reader,
                        claim_receipt_path=folder / "receipt.json",
                    )
                self.assertEqual(result, 0)
                backend.assert_called_once_with(endpoint=f4_cycle_runtime.CAS_ENDPOINT, bearer_token="w" * 40)
                journal.claim_cycle.assert_called_once()
                self.assertIs(journal.claim_cycle.call_args.kwargs["verify_github_artifact"], reader)
                self.assertIn("F4_CYCLE_CONTROL_OK:claim-cycle2:4", out.getvalue())

                self.assertEqual(json.loads((folder / "receipt.json").read_text()), {
                    "repository_id": 1458303357, "cycle": 2, "run_id": "100-1-cycle-2",
                    "source_commit_sha": "b" * 40, "go_sha256": "a" * 64,
                    "journal_sequence": 4, "journal_head_sha256": "b" * 64, "journal_version": "4",
                })
                journal.claim_cycle.reset_mock()
                with self.assertRaisesRegex(f4_cycle_runtime.F4RuntimeHold, "cycle1_auditor_run_id_mismatch"):
                    f4_cycle_runtime.execute(
                        operation="claim-cycle2", workspace=ROOT, expected_base_sha=BASE,
                        candidate_path=folder / "candidate.json", revocation_path=folder / "revocation.json",
                        trusted_keys_path=folder / "trusted.json", auditor_key_path=folder / "auditor.json",
                        env=env, cycle=2, run_id="101-1-cycle-2", source_commit_sha="c" * 40,
                        auditor_artifact_path=folder / "auditor-envelope.json",
                        cycle1_auditor_run_id="100", provenance_reader=reader,
                        claim_receipt_path=folder / "unused-receipt.json",
                    )
                journal.claim_cycle.assert_not_called()

            with self.assertRaises(f4_cycle_runtime.F4RuntimeHold):
                f4_cycle_runtime.execute(
                    operation="claim-cycle1", workspace=ROOT, expected_base_sha=BASE,
                    candidate_path=folder / "candidate.json", revocation_path=folder / "revocation.json",
                    trusted_keys_path=folder / "trusted.json", auditor_key_path=folder / "auditor.json",
                    env={"B09_CAS_ENDPOINT": f4_cycle_runtime.CAS_ENDPOINT},
                    cycle=1, run_id="100-1-cycle-2", source_commit_sha="b" * 40,
                )

    def test_workflow_trust_roots_are_external_and_all_execution_stays_disabled(self):
        workflow = (ROOT / ".github/workflows/public-runner-draft.yml").read_text(encoding="utf-8")
        self.assertIn("B09_F4_TRUSTED_KEYS_JSON: ${{ vars.B09_F4_TRUSTED_KEYS_JSON }}", workflow)
        self.assertIn("B09_F4_AUDITOR_KEY_JSON: ${{ vars.B09_F4_AUDITOR_KEY_JSON }}", workflow)
        self.assertIn("name: b09-public-runner-signed-attestations", workflow)
        self.assertIn('"$RUNNER_TEMP/b09-signed-attestations/permit.json"', workflow)
        self.assertNotIn('{"keys":[]}', workflow)
        self.assertIn("root = Path(os.environ[\"RUNNER_TEMP\"]) / \"b09-f4-trust\"", workflow)
        self.assertIn("required=(candidate.json revocation-envelope.json)", workflow)
        self.assertNotIn("required=(candidate.json revocation-envelope.json trusted-keys.json auditor-key.json)", workflow)
        self.assertGreaterEqual(workflow.count("if: ${{ false &&"), 3)
        self.assertIn("if: ${{ false }}\n        uses: openai/codex-action@", workflow)
        self.assertIn('F4_BASE_SHA: ${{ inputs.f4_base_sha }}', workflow)
        self.assertNotIn('"${{ inputs.f4_base_sha }}"', workflow)

    def test_expired_go_and_shared_auditor_key_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "f4_go_not_yet_valid_or_expired"):
            build_payload(
                evidence={}, candidate=self.candidate, workspace=ROOT,
                expected_base_sha=BASE, trusted_keys=self.key_document,
                auditor_key_document=self.auditor_document,
                revocation_envelope=self.revocation,
                workflow_run_id="99", run_attempt=1, source_commit_sha="f" * 40,
                now=datetime(2026, 11, 20, tzinfo=timezone.utc),
            )
        shared_key = {**self.auditor_document,
                      "public_key": base64.b64encode(self.owner_keys["owner_a-test-key"].public_key).decode("ascii")}
        with self.assertRaises(f4_cycle_runtime.F4RuntimeHold):
            f4_cycle_runtime._load_auditor_key(shared_key, self.owner_keys)


if __name__ == "__main__":
    unittest.main()
