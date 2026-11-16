"""Offline tests for commit-before-Draft-PR Publisher boundary."""
from __future__ import annotations

import hashlib
import base64
from pathlib import Path
import tempfile
import unittest

from draft_pr_writer import (
    BranchSnapshot,
    ClientOutcomeUnknown,
    DraftPrCreated,
    DraftPrRequest,
    DraftPrWriter,
    PermissionSnapshot,
    RepositorySnapshot,
    WriterHold,
)
from publisher_gate import (
    PUBLIC_BASE_BRANCH,
    PUBLIC_HEAD_BRANCH,
    PUBLIC_REPOSITORY,
    PUBLIC_REPOSITORY_ID,
    DraftPrPlan,
)


BASE_SHA = "a" * 40
OLD_HEAD = "d" * 40
NEW_HEAD = "e" * 40
RELATIVE = "ops/command-tower/publisher_gate.py"
CONTENTS = b"verified worker candidate\n"


def make_plan(path: str = RELATIVE, content: bytes = CONTENTS) -> DraftPrPlan:
    return DraftPrPlan(
        repository_id=PUBLIC_REPOSITORY_ID,
        base_sha=BASE_SHA,
        base_branch=PUBLIC_BASE_BRANCH,
        head_branch=PUBLIC_HEAD_BRANCH,
        worker_run_id="offline-commit-run",
        candidate_digest="c" * 64,
        changed_paths=(path,),
        file_sha256=((path, hashlib.sha256(content).hexdigest()),),
        title="Draft: offline commit test",
        body="DRAFT_HOLD test request",
    )


class FakeApi:
    def __init__(self) -> None:
        self.contents_permission = "write"
        self.head_sha = OLD_HEAD
        self.file_sha256: dict[str, str] = {}
        self.graphql_calls: list[tuple[str, dict[str, object]]] = []
        self.pr_calls: list[DraftPrRequest] = []
        self.unknown_commit = False
        self.concurrent_head_change = False
        self.api_rejects_commit = False

    def get_repository(self, repository_id: int) -> RepositorySnapshot:
        return RepositorySnapshot(repository_id, PUBLIC_REPOSITORY, False)

    def get_permissions(self, repository_id: int) -> PermissionSnapshot:
        return PermissionSnapshot(repository_id, "publisher", {
            "contents": self.contents_permission,
            "pull_requests": "write",
            "actions": "none",
        })

    def get_branch(self, repository_id: int, branch: str) -> BranchSnapshot:
        if branch == PUBLIC_BASE_BRANCH:
            return BranchSnapshot(branch, BASE_SHA, BASE_SHA, {})
        return BranchSnapshot(branch, self.head_sha, BASE_SHA, dict(self.file_sha256))

    def find_open_pull_request(self, repository_id: int, head: str, base: str) -> bool:
        return False

    def execute_graphql(self, query: str,
                        variables: dict[str, object]) -> dict[str, object]:
        self.graphql_calls.append((query, variables))
        input_value = variables["input"]
        branch = input_value["branch"]
        expected_head_oid = input_value["expectedHeadOid"]
        if self.concurrent_head_change:
            self.head_sha = "f" * 40
            return {"errors": [{"message": "expectedHeadOid conflict"}]}
        if self.api_rejects_commit:
            return {"errors": [{"message": "API rejected mutation"}]}
        if self.unknown_commit:
            raise ClientOutcomeUnknown("offline simulated lost response")
        if (branch["repositoryNameWithOwner"] != PUBLIC_REPOSITORY
                or branch["branchName"] != PUBLIC_HEAD_BRANCH
                or expected_head_oid != self.head_sha):
            return {"errors": [{"message": "scope or expected head mismatch"}]}
        additions = input_value["fileChanges"]["additions"]
        files = {item["path"]: base64.b64decode(item["contents"])
                 for item in additions}
        self.file_sha256 = {path: hashlib.sha256(data).hexdigest()
                            for path, data in files.items()}
        self.head_sha = NEW_HEAD
        return {"data": {"createCommitOnBranch": {"commit": {
            "oid": NEW_HEAD,
            "parents": {"nodes": [{"oid": expected_head_oid}]},
        }}}}

    def create_draft_pull_request(self, request: DraftPrRequest) -> DraftPrCreated:
        self.pr_calls.append(request)
        return DraftPrCreated(
            PUBLIC_REPOSITORY_ID, 19, "https://github.com/not60/example/pull/19",
            PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH, True,
        )


class PublisherBranchCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.artifact_root = Path(self.temporary.name)
        target = self.artifact_root / "files" / RELATIVE
        target.parent.mkdir(parents=True)
        target.write_bytes(CONTENTS)
        self.api = FakeApi()
        self.writer = DraftPrWriter(self.api, authorization_check=lambda _plan: True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_candidate(self, candidate: DraftPrPlan | None = None,
                      expected_head: str = OLD_HEAD):
        return self.writer.commit_verified_artifact_and_create_draft(
            candidate or make_plan(), artifact_root=self.artifact_root,
            expected_head_sha=expected_head,
        )

    def test_commits_exact_bytes_nonforce_then_requests_scoped_draft_pr(self) -> None:
        result = self.run_candidate()
        self.assertEqual(len(self.api.graphql_calls), 1)
        query, variables = self.api.graphql_calls[0]
        self.assertIn("createCommitOnBranch", query)
        self.assertIn("CreateCommitOnBranchInput", query)
        input_value = variables["input"]
        self.assertEqual(input_value["branch"], {
            "repositoryNameWithOwner": PUBLIC_REPOSITORY,
            "branchName": PUBLIC_HEAD_BRANCH,
        })
        self.assertEqual(input_value["expectedHeadOid"], OLD_HEAD)
        self.assertEqual(input_value["fileChanges"]["additions"], [{
            "path": RELATIVE,
            "contents": base64.b64encode(CONTENTS).decode("ascii"),
        }])
        self.assertNotIn("force", input_value)
        self.assertEqual(len(self.api.pr_calls), 1)
        request = self.api.pr_calls[0]
        self.assertEqual(request.repository_id, PUBLIC_REPOSITORY_ID)
        self.assertEqual(request.head, PUBLIC_HEAD_BRANCH)
        self.assertEqual(request.base, PUBLIC_BASE_BRANCH)
        self.assertIs(request.draft, True)
        self.assertEqual(result.number, 19)

    def test_head_conflict_holds_before_commit(self) -> None:
        with self.assertRaisesRegex(WriterHold, "expected_head_mismatch"):
            self.run_candidate(expected_head="f" * 40)
        self.assertEqual(self.api.graphql_calls, [])
        self.assertEqual(self.api.pr_calls, [])

    def test_out_of_allowlist_path_holds_before_commit(self) -> None:
        illegal = "README.md"
        plan = make_plan(illegal)
        with self.assertRaisesRegex(WriterHold, "paths_or_file_sha"):
            self.run_candidate(plan)
        self.assertEqual(self.api.graphql_calls, [])

    def test_contents_write_permission_is_required(self) -> None:
        self.api.contents_permission = "read"
        with self.assertRaisesRegex(WriterHold, "permission_scope_mismatch"):
            self.run_candidate()
        self.assertEqual(self.api.graphql_calls, [])

    def test_gate_hold_prevents_commit_and_pr(self) -> None:
        writer = DraftPrWriter(self.api, authorization_check=lambda _plan: False)
        with self.assertRaisesRegex(WriterHold, "gate_receipt_missing"):
            writer.commit_verified_artifact_and_create_draft(
                make_plan(), artifact_root=self.artifact_root,
                expected_head_sha=OLD_HEAD,
            )
        self.assertEqual(self.api.graphql_calls, [])
        self.assertEqual(self.api.pr_calls, [])

    def test_ambiguous_commit_is_not_retried_and_does_not_create_pr(self) -> None:
        self.api.unknown_commit = True
        with self.assertRaisesRegex(WriterHold, "commit_outcome_unknown_no_retry"):
            self.run_candidate()
        self.assertEqual(len(self.api.graphql_calls), 1)
        self.assertEqual(self.api.pr_calls, [])
        with self.assertRaisesRegex(WriterHold, "commit_attempt_already_used"):
            self.run_candidate()
        self.assertEqual(len(self.api.graphql_calls), 1)

    def test_graphql_expected_head_race_is_rejected_without_retry_or_pr(self) -> None:
        self.api.concurrent_head_change = True
        with self.assertRaisesRegex(WriterHold, "branch_commit_rejected"):
            self.run_candidate()
        self.assertEqual(len(self.api.graphql_calls), 1)
        self.assertEqual(self.api.pr_calls, [])

    def test_graphql_api_error_is_rejected_without_retry_or_pr(self) -> None:
        self.api.api_rejects_commit = True
        with self.assertRaisesRegex(WriterHold, "branch_commit_rejected"):
            self.run_candidate()
        self.assertEqual(len(self.api.graphql_calls), 1)
        self.assertEqual(self.api.pr_calls, [])

    def test_artifact_bytes_must_match_gate_digest(self) -> None:
        (self.artifact_root / "files" / RELATIVE).write_bytes(b"tampered\n")
        with self.assertRaisesRegex(WriterHold, "artifact_sha256_mismatch"):
            self.run_candidate()
        self.assertEqual(self.api.graphql_calls, [])


if __name__ == "__main__":
    unittest.main()
