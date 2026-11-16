"""Dependency-injected tests for the offline Draft PR writer boundary."""
from __future__ import annotations

import unittest

from publisher_gate import (
    PUBLIC_BASE_BRANCH,
    PUBLIC_HEAD_BRANCH,
    PUBLIC_REPOSITORY,
    PUBLIC_REPOSITORY_ID,
    DraftPrPlan,
)
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


BASE_SHA = "a" * 40
PATH = "ops/command-tower/publisher_gate.py"
FILE_SHA = "b" * 64


def plan() -> DraftPrPlan:
    # The injected authorization callback below stands in for the existing
    # cryptographic/CAS gate. It is test-only and never represents a real permit.
    return DraftPrPlan(
        repository_id=PUBLIC_REPOSITORY_ID,
        base_sha=BASE_SHA,
        base_branch=PUBLIC_BASE_BRANCH,
        head_branch=PUBLIC_HEAD_BRANCH,
        worker_run_id="offline-test-run",
        candidate_digest="c" * 64,
        changed_paths=(PATH,),
        file_sha256=((PATH, FILE_SHA),),
        title="Draft: offline test",
        body="DRAFT_HOLD test request",
    )


class FakeApi:
    def __init__(self) -> None:
        self.permission_values = {
            "contents": "write", "pull_requests": "write", "actions": "none",
        }
        self.request: DraftPrRequest | None = None
        self.write_calls = 0
        self.unknown_result = False

    def get_repository(self, repository_id: int) -> RepositorySnapshot:
        return RepositorySnapshot(repository_id, PUBLIC_REPOSITORY, False)

    def get_permissions(self, repository_id: int) -> PermissionSnapshot:
        return PermissionSnapshot(repository_id, "publisher", self.permission_values)

    def get_branch(self, repository_id: int, branch: str) -> BranchSnapshot:
        if branch == PUBLIC_BASE_BRANCH:
            return BranchSnapshot(branch, BASE_SHA, BASE_SHA, {})
        return BranchSnapshot(branch, "d" * 40, BASE_SHA, {PATH: FILE_SHA})

    def find_open_pull_request(self, repository_id: int, head: str, base: str) -> bool:
        return False

    def create_draft_pull_request(self, request: DraftPrRequest) -> DraftPrCreated:
        self.write_calls += 1
        self.request = request
        if self.unknown_result:
            raise ClientOutcomeUnknown("offline simulated ambiguous response")
        return DraftPrCreated(
            PUBLIC_REPOSITORY_ID, 17, "https://github.com/not60/example/pull/17",
            PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH, True,
        )


class DraftPrWriterTests(unittest.TestCase):
    def writer(self, api: FakeApi, approved=True) -> DraftPrWriter:
        return DraftPrWriter(api, authorization_check=lambda _plan: approved)

    def test_generates_only_scoped_draft_request_via_injected_client(self) -> None:
        api = FakeApi()
        result = self.writer(api).create_draft(plan(), expected_head_sha="d" * 40)
        self.assertEqual(api.write_calls, 1)
        self.assertIsNotNone(api.request)
        self.assertEqual(api.request.repository_id, PUBLIC_REPOSITORY_ID)
        self.assertEqual(api.request.repository_full_name, PUBLIC_REPOSITORY)
        self.assertEqual(api.request.head, PUBLIC_HEAD_BRANCH)
        self.assertEqual(api.request.base, PUBLIC_BASE_BRANCH)
        self.assertIs(api.request.draft, True)
        self.assertEqual(result.number, 17)

    def test_rejects_bad_signature_cas_conflict_and_permit_replay_before_write(self) -> None:
        # These gate outcomes represent a bad signature, failed CAS consume,
        # and replayed permit respectively; none can mint an approved receipt.
        for reason in ("signature_invalid", "cas_conflict", "permit_replay"):
            with self.subTest(reason=reason):
                api = FakeApi()
                writer = DraftPrWriter(
                    api,
                    authorization_check=lambda _plan, _reason=reason: False,
                )
                with self.assertRaises(WriterHold):
                    writer.create_draft(plan(), expected_head_sha="d" * 40)
                self.assertEqual(api.write_calls, 0)

    def test_rejects_publisher_permission_mismatch_before_write(self) -> None:
        api = FakeApi()
        api.permission_values["contents"] = "read"
        with self.assertRaisesRegex(WriterHold, "permission_scope_mismatch"):
            self.writer(api).create_draft(plan(), expected_head_sha="d" * 40)
        self.assertEqual(api.write_calls, 0)

    def test_ambiguous_create_response_is_not_retried(self) -> None:
        api = FakeApi()
        api.unknown_result = True
        with self.assertRaisesRegex(WriterHold, "outcome_unknown_no_retry"):
            self.writer(api).create_draft(plan(), expected_head_sha="d" * 40)
        self.assertEqual(api.write_calls, 1)

    def test_rejects_private_or_main_write_scope(self) -> None:
        api = FakeApi()
        unapproved_scope = plan()
        object.__setattr__(unapproved_scope, "head_branch", "main")
        with self.assertRaisesRegex(WriterHold, "plan_scope_mismatch"):
            self.writer(api).create_draft(unapproved_scope, expected_head_sha="d" * 40)
        self.assertEqual(api.write_calls, 0)


if __name__ == "__main__":
    unittest.main()
