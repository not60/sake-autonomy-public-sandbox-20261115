"""No-network contract tests for the fixed-scope GitHub Publisher adapter."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import unittest

from draft_pr_writer import (
    GitHubApiHold,
    GitHubDraftPrApi,
    GitHubPermissionScopeUnverifiable,
    DraftPrWriter,
    PUBLIC_BASE_BRANCH,
    PUBLIC_HEAD_BRANCH,
    PUBLIC_REPOSITORY,
    PUBLIC_REPOSITORY_ID,
    ALLOWED_CHANGED_PATHS,
)


BASE = "a" * 40
HEAD = "b" * 40
PATH = "ops/command-tower/publisher_gate.py"
BODY = b"fixture bytes\n"


class FakeTransport:
    def __init__(self, responses=(), error=None):
        self.responses = list(responses)
        self.error = error
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        if self.error is not None:
            raise self.error
        status, response_headers, value = self.responses.pop(0)
        return status, response_headers, json.dumps(value).encode("utf-8")


def reply(value, status=200):
    return status, {}, value


class GitHubDraftPrApiTests(unittest.TestCase):
    def api(self, transport):
        return GitHubDraftPrApi("dummy-test-token-never-sent-to-network", transport=transport)

    def test_reads_target_repository_and_rejects_wrong_id_before_io(self):
        transport = FakeTransport([reply({
            "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY, "archived": False,
        })])
        api = self.api(transport)
        snapshot = api.get_repository(PUBLIC_REPOSITORY_ID)
        self.assertEqual(snapshot.repository_id, PUBLIC_REPOSITORY_ID)
        self.assertEqual(snapshot.full_name, PUBLIC_REPOSITORY)
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("/repositories/1458303357", transport.calls[0][1])
        with self.assertRaisesRegex(GitHubApiHold, "not_allowlisted"):
            api.get_repository(12)
        self.assertEqual(len(transport.calls), 1)

    def test_repository_role_readback_does_not_masquerade_as_token_scope(self):
        transport = FakeTransport([reply({
            "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY,
            "permissions": {"admin": True, "push": True, "pull": True},
        })])
        with self.assertRaisesRegex(GitHubPermissionScopeUnverifiable, "not_exposed"):
            self.api(transport).get_permissions(PUBLIC_REPOSITORY_ID)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0][0], "GET")

    def test_missing_github_credential_is_rejected_without_io(self):
        transport = FakeTransport()
        with self.assertRaisesRegex(ValueError, "credential is required"):
            GitHubDraftPrApi("", transport=transport)
        self.assertEqual(transport.calls, [])

    def test_reads_head_and_changed_file_bytes_for_allowlisted_review_branch(self):
        encoded = base64.b64encode(BODY).decode("ascii")
        transport = FakeTransport([
            reply({"commit": {"sha": HEAD}}),
            reply({"base_commit": {"sha": BASE}, "head_commit": {"sha": HEAD},
                   "files": [{"filename": PATH, "status": "modified"}]}),
            reply({"type": "file", "encoding": "base64", "content": encoded}),
        ])
        snapshot = self.api(transport).get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH)
        self.assertEqual(snapshot.sha, HEAD)
        self.assertEqual(snapshot.base_sha, BASE)
        self.assertEqual(snapshot.file_sha256[PATH], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(len(transport.calls), 3)
        self.assertTrue(all(call[0] == "GET" for call in transport.calls))

    def test_finds_the_existing_draft_pr_without_creating_another(self):
        transport = FakeTransport([reply([{
            "number": 1, "state": "open", "draft": True,
            "head": {"ref": PUBLIC_HEAD_BRANCH, "repo": {"full_name": PUBLIC_REPOSITORY}},
            "base": {"ref": PUBLIC_BASE_BRANCH},
        }])])
        found = self.api(transport).find_open_pull_request(
            PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
        )
        self.assertTrue(found)
        self.assertEqual(transport.calls[0][0], "GET")
        self.assertIn("/pulls?", transport.calls[0][1])

    def test_reads_existing_pr_identity_as_reusable_draft(self):
        transport = FakeTransport([reply([{
            "number": 1, "state": "open", "draft": True,
            "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/1",
            "head": {"ref": PUBLIC_HEAD_BRANCH, "sha": HEAD,
                     "repo": {"full_name": PUBLIC_REPOSITORY}},
            "base": {"ref": PUBLIC_BASE_BRANCH, "sha": BASE,
                     "repo": {"id": PUBLIC_REPOSITORY_ID}},
        }])])
        pr = self.api(transport).get_open_draft_pull_request(
            PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
        )
        self.assertEqual(pr.number, 1)
        self.assertEqual(pr.head_sha, HEAD)
        self.assertEqual(pr.base_sha, BASE)
        self.assertIs(pr.draft, True)

    def test_ci_readback_binds_one_pr_run_to_exact_head_and_base(self):
        pr_value = {
            "number": 1, "state": "open", "draft": True,
            "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/1",
            "head": {"ref": PUBLIC_HEAD_BRANCH, "sha": HEAD,
                     "repo": {"full_name": PUBLIC_REPOSITORY}},
            "base": {"ref": PUBLIC_BASE_BRANCH, "sha": BASE,
                     "repo": {"id": PUBLIC_REPOSITORY_ID}},
        }
        transport = FakeTransport([
            reply([pr_value]),
            reply({"workflow_runs": [{
                "id": 44010738955,
                "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/actions/runs/44010738955",
                "head_sha": HEAD, "event": "pull_request", "status": "completed",
                "conclusion": "success",
            }]}),
        ])
        result = self.api(transport).read_readonly_ci_run(1, HEAD, BASE)
        self.assertEqual(result.head_sha, HEAD)
        self.assertEqual(result.base_sha, BASE)
        self.assertEqual(result.conclusion, "success")
        self.assertEqual(len(transport.calls), 2)
        self.assertIn("head_sha=" + HEAD, transport.calls[1][1])

    def test_ci_readback_holds_if_pr_base_sha_differs(self):
        pr_value = {
            "number": 1, "state": "open", "draft": True,
            "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/1",
            "head": {"ref": PUBLIC_HEAD_BRANCH, "sha": HEAD,
                     "repo": {"full_name": PUBLIC_REPOSITORY}},
            "base": {"ref": PUBLIC_BASE_BRANCH, "sha": "c" * 40,
                     "repo": {"id": PUBLIC_REPOSITORY_ID}},
        }
        transport = FakeTransport([reply([pr_value])])
        with self.assertRaisesRegex(GitHubApiHold, "pr_sha_mismatch"):
            self.api(transport).read_readonly_ci_run(1, HEAD, BASE)
        self.assertEqual(len(transport.calls), 1)

    def test_ci_wait_is_bounded_and_returns_only_after_exact_run_completes(self):
        pr_value = {
            "number": 1, "state": "open", "draft": True,
            "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/1",
            "head": {"ref": PUBLIC_HEAD_BRANCH, "sha": HEAD,
                     "repo": {"full_name": PUBLIC_REPOSITORY}},
            "base": {"ref": PUBLIC_BASE_BRANCH, "sha": BASE,
                     "repo": {"id": PUBLIC_REPOSITORY_ID}},
        }
        run = {
            "id": 44010738955,
            "html_url": "https://github.com/not60/sake-autonomy-public-sandbox-20261115/actions/runs/44010738955",
            "head_sha": HEAD, "event": "pull_request",
        }
        transport = FakeTransport([
            reply([pr_value]), reply({"workflow_runs": [{**run, "status": "in_progress", "conclusion": None}]}),
            reply([pr_value]), reply({"workflow_runs": [{**run, "status": "completed", "conclusion": "success"}]}),
        ])
        now = [0.0]
        api = GitHubDraftPrApi(
            "dummy-test-token-never-sent-to-network", transport=transport,
            sleep_fn=lambda seconds: now.__setitem__(0, now[0] + seconds),
            monotonic_fn=lambda: now[0],
        )
        result = api.wait_for_readonly_ci_run(
            1, HEAD, BASE, timeout_seconds=5, poll_interval_seconds=1,
        )
        self.assertEqual(result.conclusion, "success")
        self.assertEqual(len(transport.calls), 4)

    def test_graphql_boundary_accepts_only_expected_head_and_allowlisted_bytes(self):
        query, variables = DraftPrWriter._build_graphql_commit(
            expected_head_oid=HEAD, files={PATH: BODY}, worker_run_id="local-fixture",
        )
        GitHubDraftPrApi._validate_graphql_commit(query, variables)
        self.assertEqual(variables["input"]["expectedHeadOid"], HEAD)
        self.assertNotIn("force", variables["input"])
        bad = json.loads(json.dumps(variables))
        bad["input"]["branch"]["branchName"] = "main"
        with self.assertRaisesRegex(GitHubApiHold, "not_allowlisted"):
            GitHubDraftPrApi._validate_graphql_commit(query, bad)
        bad_path = json.loads(json.dumps(variables))
        bad_path["input"]["fileChanges"]["additions"][0]["path"] = "README.md"
        self.assertIn(PATH, ALLOWED_CHANGED_PATHS)
        with self.assertRaisesRegex(GitHubApiHold, "outside_allowlist"):
            GitHubDraftPrApi._validate_graphql_commit(query, bad_path)

    def test_mutations_are_blocked_without_writer_authorization(self):
        transport = FakeTransport()
        api = self.api(transport)
        query, variables = DraftPrWriter._build_graphql_commit(
            expected_head_oid=HEAD, files={PATH: BODY}, worker_run_id="local-fixture",
        )
        with self.assertRaisesRegex(GitHubApiHold, "authorization_missing"):
            api.execute_graphql(query, variables)
        self.assertEqual(transport.calls, [])

    def test_publisher_cli_connects_gate_plan_to_writer_without_default_write(self):
        source = Path(__file__).with_name("publisher_gate.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--draft-pr-write", action="store_true"', source)
        self.assertIn('os.environ.get("B09_PUBLISHER_GITHUB_TOKEN", "")', source)
        self.assertIn("DraftPrWriter(api).commit_verified_artifact_and_create_draft(", source)
        self.assertIn('sys.modules.setdefault("publisher_gate", sys.modules[__name__])', source)
        self.assertIn("DRAFT_PR_PLAN_READY_NO_GITHUB_WRITE", source)
        self.assertIn('parser.add_argument("--expected-pr-head-sha", default=""', source)
        self.assertIn('parser.add_argument("--expected-pr-base-sha", default=""', source)
        self.assertIn("args.pull_request_number, args.expected_pr_head_sha, args.expected_pr_base_sha", source)
        self.assertIn(".wait_for_readonly_ci_run(", source)
        self.assertIn("draft_result.head_sha}:{draft_result.base_sha}", source)

    def test_ambiguous_mutation_transport_is_not_retried(self):
        transport = FakeTransport(error=TimeoutError("offline-only synthetic timeout"))
        api = self.api(transport)
        with self.assertRaisesRegex(TimeoutError, "outcome_unknown_no_retry"):
            api._request("POST", "/graphql", {"query": "test"}, mutation=True)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0][0], "POST")


if __name__ == "__main__":
    unittest.main()
