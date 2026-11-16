"""Tests for actual Worker delta capture and manifest binding."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from runner_artifact import ArtifactBuildHold, build_artifact


REPOSITORY_ID = 1458303357
PATH_A = "ops/command-tower/a.py"
PATH_B = "ops/command-tower/b.py"


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


class RunnerArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "worktree"
        (self.root / "ops/command-tower").mkdir(parents=True)
        (self.root / PATH_A).write_bytes(b"old a\n")
        (self.root / PATH_B).write_bytes(b"unchanged b\n")
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "add", PATH_A, PATH_B)
        git(self.root, "commit", "-qm", "base")
        self.base_sha = git(self.root, "rev-parse", "HEAD")
        self.output_file = Path(self.temporary.name) / "codex-output.bin"
        self.output_file.write_bytes(b"Codex final result for run 42\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, output: Path, *, allowed: tuple[str, ...] = (PATH_A, PATH_B),
              base_sha: str | None = None, changed_paths: tuple[str, ...] | None = None):
        return build_artifact(
            worktree_root=self.root, output_root=output,
            repository_id=REPOSITORY_ID, base_sha=base_sha or self.base_sha,
            worker_run_id="run-42-attempt-1", codex_output_file=self.output_file,
            allowed_paths=allowed, changed_paths=changed_paths,
        )

    def test_only_actual_modified_file_is_packaged_and_bound_to_output(self) -> None:
        (self.root / PATH_A).write_bytes(b"new a\n")
        output = Path(self.temporary.name) / "bundle"
        manifest = self.build(output)
        self.assertEqual(manifest["changed_paths"], [PATH_A])
        self.assertEqual(set(manifest["files"]), {PATH_A})
        self.assertEqual(manifest["worker_run_id"], "run-42-attempt-1")
        self.assertEqual(manifest["base_sha"], self.base_sha)
        self.assertEqual(manifest["codex_output_sha256"],
                         hashlib.sha256(self.output_file.read_bytes()).hexdigest())
        self.assertEqual((output / "files" / PATH_A).read_bytes(), b"new a\n")
        self.assertFalse((output / "files" / PATH_B).exists())
        self.assertEqual((output / "evidence/codex-output.bin").read_bytes(),
                         self.output_file.read_bytes())
        self.assertEqual(json.loads((output / "permit.json").read_text())["state"], "NOT_ISSUED")

    def test_disallowed_untracked_change_holds(self) -> None:
        outside = "ops/command-tower/unapproved.py"
        (self.root / outside).write_text("unapproved\n", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactBuildHold, "path_outside_allowlist"):
            self.build(Path(self.temporary.name) / "bundle")

    def test_deleted_file_holds(self) -> None:
        (self.root / PATH_A).unlink()
        with self.assertRaisesRegex(ArtifactBuildHold, "unsupported_change_type"):
            self.build(Path(self.temporary.name) / "bundle")

    def test_codex_output_is_required_and_base_must_be_head(self) -> None:
        with self.assertRaisesRegex(ArtifactBuildHold, "no_worker_changes"):
            self.build(Path(self.temporary.name) / "empty-bundle")
        with self.assertRaisesRegex(ArtifactBuildHold, "worktree_head_does_not_match_base_sha"):
            self.build(Path(self.temporary.name) / "wrong-base", base_sha="a" * 40)

    def test_supplied_static_file_list_cannot_replace_actual_delta(self) -> None:
        (self.root / PATH_A).write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactBuildHold, "supplied_paths_do_not_match_worker_delta"):
            self.build(Path(self.temporary.name) / "bundle", changed_paths=(PATH_A, PATH_B))


if __name__ == "__main__":
    unittest.main()
