"""Focused tests for exact-byte runner artifact packaging."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from durable_store import DurableStore
from publisher_gate import PublisherGate, PublisherGateHold
from runner_artifact import ArtifactBuildHold, build_artifact


REPOSITORY_ID = 1458303357
BASE_SHA = "a" * 40
PATH = "ops/command-tower/candidate.py"
CONTENT = b"byte exact candidate\n"


class RunnerArtifactTests(unittest.TestCase):
    def test_manifest_matches_copied_bytes_and_missing_attestations_hold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worktree"
            source = root / PATH
            source.parent.mkdir(parents=True)
            source.write_bytes(CONTENT)
            output = Path(directory) / "bundle"
            manifest = build_artifact(
                worktree_root=root, output_root=output,
                repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                changed_paths=(PATH,), allowed_paths=(PATH,),
            )
            self.assertEqual(manifest["files"][PATH], hashlib.sha256(CONTENT).hexdigest())
            self.assertEqual((output / "files" / PATH).read_bytes(), CONTENT)
            self.assertEqual(json.loads((output / "permit.json").read_text()), {"state": "NOT_ISSUED"})
            self.assertEqual(json.loads((output / "witness.json").read_text()), {"state": "NOT_ISSUED"})

            store = DurableStore(Path(directory) / "publisher.sqlite3")
            gate = PublisherGate(
                repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                allowed_paths=(PATH,), trusted_keys={}, durable_store=store,
            )
            with self.assertRaises(PublisherGateHold) as held:
                gate.verify_bundle(
                    artifact_root=output / "files", manifest=manifest,
                    permit=json.loads((output / "permit.json").read_text()),
                    witness=json.loads((output / "witness.json").read_text()),
                )
            self.assertEqual(held.exception.reason, "signed_permit_and_witness_required")
            self.assertEqual(store.state, "SAFE_STOPPED")
            store.close()

    def test_outside_allowlist_is_rejected_without_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worktree"
            source = root / PATH
            source.parent.mkdir(parents=True)
            source.write_bytes(CONTENT)
            output = Path(directory) / "bundle"
            with self.assertRaisesRegex(ArtifactBuildHold, "path_outside_allowlist"):
                build_artifact(
                    worktree_root=root, output_root=output,
                    repository_id=REPOSITORY_ID, base_sha=BASE_SHA,
                    changed_paths=("ops/command-tower/../outside.py",),
                    allowed_paths=(PATH,),
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
