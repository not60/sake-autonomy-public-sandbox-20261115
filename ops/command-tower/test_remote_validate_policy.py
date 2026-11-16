#!/usr/bin/env python3
"""Read-only baseline regression tests for the isolated sandbox fixture."""
from __future__ import annotations

import copy
import unittest

from remote_validate import SANDBOX_REPO, ValidationError, validate_draft


def safe_fixture() -> dict:
    return {
        "schema": 1,
        "state": "DRAFT_HOLD",
        "repository": SANDBOX_REPO,
        "write_enabled": False,
        "feature_branch": "feature/sandbox-fixture-01",
        "allowed_changed_paths": [
            "ops/command-tower/remote_validate.py",
            "ops/command-tower/test_remote_validate_policy.py",
        ],
    }


class BaselineSandboxTests(unittest.TestCase):
    def test_safe_fixture_is_read_only(self) -> None:
        branch, paths = validate_draft(safe_fixture())
        self.assertEqual(branch, "feature/sandbox-fixture-01")
        self.assertEqual(len(paths), 2)

    def test_reject_enabled_write(self) -> None:
        fixture = safe_fixture()
        fixture["write_enabled"] = True
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_reject_non_sandbox_repository(self) -> None:
        fixture = safe_fixture()
        fixture["repository"] = "example/non-sandbox-repo"
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_reject_active_state(self) -> None:
        fixture = safe_fixture()
        fixture["state"] = "GO"
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_reject_unsafe_or_out_of_scope_paths(self) -> None:
        for unsafe in (
            "../escape.py",
            "ops/command-tower/../escape.py",
            "ops/command-tower/",
            ".github/workflows/deploy.yml",
            "ops/command-tower\\unexpected.py",
        ):
            with self.subTest(unsafe=unsafe):
                fixture = safe_fixture()
                fixture["allowed_changed_paths"] = [unsafe]
                with self.assertRaises(ValidationError):
                    validate_draft(fixture)

    def test_reject_malformed_branch(self) -> None:
        fixture = safe_fixture()
        fixture["feature_branch"] = "../main"
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_reject_missing_paths(self) -> None:
        fixture = copy.deepcopy(safe_fixture())
        fixture["allowed_changed_paths"] = []
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_reject_duplicate_paths(self) -> None:
        fixture = safe_fixture()
        fixture["allowed_changed_paths"].append(fixture["allowed_changed_paths"][0])
        with self.assertRaises(ValidationError):
            validate_draft(fixture)

    def test_accept_distinct_paths(self) -> None:
        fixture = safe_fixture()
        _, paths = validate_draft(fixture)
        self.assertEqual(paths, tuple(fixture["allowed_changed_paths"]))

    def test_reject_unsafe_feature_branches(self) -> None:
        for branch in (
            "main", "refs/heads/main", "bootstrap/test", "review/test",
            "feature/", "feature//x", "feature/../main", "feature/./x",
            "feature/.hidden", "feature/x/", "feature/x.", "feature/x.lock",
            "feature/x.lock/y", "feature/a..b", "feature/x y", "feature/x@{y",
            "feature/x\\y", "feature/x\n", None, 123, "feature/" + "x" * 94,
        ):
            with self.subTest(branch=branch):
                fixture = safe_fixture()
                fixture["feature_branch"] = branch
                with self.assertRaises(ValidationError):
                    validate_draft(fixture)

    def test_accept_safe_feature_branches(self) -> None:
        for branch in (
            "feature/x", "feature/sandbox-fixture-01", "feature/team/task_01.v2",
            "feature/" + "x" * 93,
        ):
            with self.subTest(branch=branch):
                fixture = safe_fixture()
                fixture["feature_branch"] = branch
                self.assertEqual(validate_draft(fixture)[0], branch)

    def test_reject_missing_schema(self) -> None:
        fixture = safe_fixture()
        del fixture["schema"]
        with self.assertRaises(ValidationError):
            validate_draft(fixture)


if __name__ == "__main__":
    unittest.main()
