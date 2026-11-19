"""Focused tests for cross-run Worker artifact provenance checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops/command-tower"))

from github_worker_provenance import (  # noqa: E402
    ARTIFACT_NAME, REPOSITORY_ID, WORKFLOW_PATH, WorkerProvenanceHold,
    verify_worker_artifact_provenance,
)


BASE = "a" * 40


def response(value: object):
    instance = Mock()
    instance.status = 200
    instance.read.return_value = json.dumps(value).encode("utf-8")
    instance.__enter__ = Mock(return_value=instance)
    instance.__exit__ = Mock(return_value=False)
    return instance


class WorkerArtifactProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "schema": 2, "repository_id": REPOSITORY_ID, "base_sha": BASE,
            "worker_run_id": "12345-2", "codex_output_sha256": hashlib.sha256(b"out").hexdigest(),
            "changed_paths": ["ops/command-tower/example.py"],
            "files": {"ops/command-tower/example.py": hashlib.sha256(b"file").hexdigest()},
            "candidate_digest": hashlib.sha256(b"candidate").hexdigest(),
        }
        self.run = {
            "id": 12345, "run_attempt": 2, "path": WORKFLOW_PATH,
            "event": "workflow_dispatch", "head_branch": "main", "head_sha": BASE,
            "status": "completed", "conclusion": "success",
            "repository": {"id": REPOSITORY_ID},
        }
        self.artifacts = {"artifacts": [{
            "id": 67890, "name": ARTIFACT_NAME, "expired": False,
            "digest": "sha256:" + "b" * 64,
            "workflow_run": {
                "id": 12345, "repository_id": REPOSITORY_ID,
                "head_branch": "main", "head_sha": BASE,
            },
        }]}

    def test_exact_completed_run_and_artifact_are_accepted(self):
        opener = Mock(side_effect=[response(self.run), response(self.artifacts)])
        result = verify_worker_artifact_provenance(
            self.manifest, expected_run_id="12345", expected_base_sha=BASE,
            bearer_token="test-only", opener=opener,
        )
        self.assertEqual(result["run_attempt"], 2)
        self.assertEqual(result["artifact_id"], 67890)
        self.assertEqual(result["archive_digest"], "sha256:" + "b" * 64)
        self.assertEqual(opener.call_count, 2)

    def test_in_progress_or_failed_run_is_rejected(self):
        in_progress = {**self.run, "status": "in_progress", "conclusion": None}
        opener = Mock(side_effect=[response(in_progress), response(self.artifacts)])
        with self.assertRaisesRegex(WorkerProvenanceHold, "not_completed_successfully"):
            verify_worker_artifact_provenance(
                self.manifest, expected_run_id="12345", expected_base_sha=BASE,
                bearer_token="test-only", opener=opener,
            )

    def test_wrong_attempt_commit_repo_or_artifact_is_rejected(self):
        for changed_run in (
            {**self.run, "run_attempt": 1},
            {**self.run, "head_sha": "c" * 40},
            {**self.run, "repository": {"id": REPOSITORY_ID + 1}},
        ):
            with self.subTest(changed_run=changed_run):
                opener = Mock(side_effect=[response(changed_run), response(self.artifacts)])
                with self.assertRaises(WorkerProvenanceHold):
                    verify_worker_artifact_provenance(
                        self.manifest, expected_run_id="12345", expected_base_sha=BASE,
                        bearer_token="test-only", opener=opener,
                    )

        wrong_artifact = {"artifacts": [{**self.artifacts["artifacts"][0], "expired": True}]}
        opener = Mock(side_effect=[response(self.run), response(wrong_artifact)])
        with self.assertRaisesRegex(WorkerProvenanceHold, "artifact_metadata_invalid"):
            verify_worker_artifact_provenance(
                self.manifest, expected_run_id="12345", expected_base_sha=BASE,
                bearer_token="test-only", opener=opener,
            )

    def test_run_id_manifest_and_missing_artifact_fail_closed(self):
        with self.assertRaisesRegex(WorkerProvenanceHold, "worker_run_id_mismatch"):
            verify_worker_artifact_provenance(
                self.manifest, expected_run_id="99999", expected_base_sha=BASE,
                bearer_token="test-only", opener=Mock(),
            )
        no_artifact = {"artifacts": []}
        opener = Mock(side_effect=[response(self.run), response(no_artifact)])
        with self.assertRaisesRegex(WorkerProvenanceHold, "artifact_missing_or_duplicated"):
            verify_worker_artifact_provenance(
                self.manifest, expected_run_id="12345", expected_base_sha=BASE,
                bearer_token="test-only", opener=opener,
            )


if __name__ == "__main__":
    unittest.main()
