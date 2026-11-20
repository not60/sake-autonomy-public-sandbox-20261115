"""No-network contract tests for the fixed-scope GitHub Publisher adapter."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from draft_pr_writer import (
    GitHubApiHold,
    GitHubAppInstallationCredentialIssuer,
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
        with self.assertRaisesRegex(GitHubPermissionScopeUnverifiable, "evidence"):
            self.api(transport).get_permissions(PUBLIC_REPOSITORY_ID)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0][0], "GET")

    def _app_issuer_responses(self, *, permissions=None, repositories=None,
                              expiry="2027-01-15T08:30:00Z"):
        now = 1_800_000_000
        return now, [
            reply({"id": 184026537, "app_id": 5848436,
                   "permissions": {"contents": "write", "pull_requests": "write",
                                   "metadata": "read"}}),
            reply({"token": "ghs-test-issued-token", "expires_at": expiry,
                   "repository_selection": "selected",
                   "permissions": permissions or {
                       "contents": "write", "pull_requests": "write", "metadata": "read",
                   }} , status=201),
            reply({"total_count": 1 if repositories is None else len(repositories),
                   "repositories": repositories or [{
                       "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY,
                   }]}),
        ]

    def test_app_issuance_binds_exact_repo_permissions_expiry_and_same_token(self):
        now, responses = self._app_issuer_responses()
        transport = FakeTransport(responses)
        with patch("draft_pr_writer._github_app_jwt", return_value="dummy-app-jwt"):
            token, evidence = GitHubAppInstallationCredentialIssuer(
                app_id=5848436, installation_id=184026537,
                private_key_pem="test-only-private-key-fixture",
                transport=transport, wall_time_fn=lambda: now,
            ).issue()
        self.assertEqual(token, "ghs-test-issued-token")
        self.assertEqual(evidence.repository_ids, (PUBLIC_REPOSITORY_ID,))
        self.assertEqual(evidence.token_sha256, hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(evidence.permissions, tuple(sorted({
            "contents": "write", "pull_requests": "write", "metadata": "read",
        }.items())))
        self.assertEqual([call[0] for call in transport.calls], ["GET", "POST", "GET"])
        self.assertEqual(json.loads(transport.calls[1][3]), {
            "repository_ids": [PUBLIC_REPOSITORY_ID],
            "permissions": {"contents": "write", "pull_requests": "write"},
        })
        self.assertEqual(transport.calls[0][2]["Authorization"], "Bearer dummy-app-jwt")
        self.assertEqual(transport.calls[1][2]["Authorization"], "Bearer dummy-app-jwt")
        self.assertEqual(transport.calls[2][2]["Authorization"], f"Bearer {token}")
        self.assertNotIn("dummy-app-jwt", repr(evidence))

        api = GitHubDraftPrApi(
            token, transport=FakeTransport([reply({
                "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY,
            })]), permission_evidence=evidence, wall_time_fn=lambda: now,
        )
        snapshot = api.get_permissions(PUBLIC_REPOSITORY_ID)
        self.assertEqual(snapshot.permissions, {
            "contents": "write", "pull_requests": "write", "metadata": "read",
            "actions": "none",
        })
        self.assertEqual(snapshot.evidence, evidence)

    def test_app_issuance_rejects_extra_action_permission_and_wrong_repo_scope(self):
        cases = (
            {"permissions": {"contents": "write", "pull_requests": "write",
                             "metadata": "read", "actions": "read"}},
            {"permissions": {"contents": "read", "pull_requests": "write",
                             "metadata": "read"}},
            {"repositories": [{"id": 12, "full_name": "other/repo"}]},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                now, responses = self._app_issuer_responses(**kwargs)
                transport = FakeTransport(responses)
                with patch("draft_pr_writer._github_app_jwt", return_value="dummy-app-jwt"):
                    with self.assertRaises(GitHubApiHold):
                        GitHubAppInstallationCredentialIssuer(
                            app_id=5848436, installation_id=184026537,
                            private_key_pem="test-only-private-key-fixture",
                            transport=transport, wall_time_fn=lambda: now,
                        ).issue()

    def test_raw_token_or_changed_token_cannot_claim_permission_proof(self):
        transport = FakeTransport([reply({
            "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY,
        })])
        with self.assertRaisesRegex(GitHubPermissionScopeUnverifiable, "evidence"):
            self.api(transport).get_permissions(PUBLIC_REPOSITORY_ID)
        now, responses = self._app_issuer_responses()
        with patch("draft_pr_writer._github_app_jwt", return_value="dummy-app-jwt"):
            token, evidence = GitHubAppInstallationCredentialIssuer(
                app_id=5848436, installation_id=184026537,
                private_key_pem="test-only-private-key-fixture",
                transport=FakeTransport(responses), wall_time_fn=lambda: now,
            ).issue()
        changed = GitHubDraftPrApi(
            token + "-changed", transport=FakeTransport([reply({
                "id": PUBLIC_REPOSITORY_ID, "full_name": PUBLIC_REPOSITORY,
            })]), permission_evidence=evidence, wall_time_fn=lambda: now,
        )
        with self.assertRaisesRegex(GitHubPermissionScopeUnverifiable, "evidence"):
            changed.get_permissions(PUBLIC_REPOSITORY_ID)

    def test_app_environment_requires_private_key_and_has_no_legacy_token_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GitHubApiHold, "private_key_missing"):
                GitHubDraftPrApi.from_publisher_app_environment()

    @unittest.skipUnless(importlib.util.find_spec("cryptography"),
                         "cryptography is pinned for CI but unavailable in this local Python")
    def test_app_jwt_uses_rsa_signature_and_short_fixed_claims(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from draft_pr_writer import _github_app_jwt

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        now = 1_800_000_000
        encoded = _github_app_jwt(5848436, private_pem, now)
        header_part, payload_part, signature_part = encoded.split(".")
        unpad = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        header = json.loads(unpad(header_part))
        payload = json.loads(unpad(payload_part))
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(payload, {"iss": "5848436", "iat": now - 60, "exp": now + 540})
        private_key.public_key().verify(
            unpad(signature_part), f"{header_part}.{payload_part}".encode("ascii"),
            padding.PKCS1v15(), hashes.SHA256(),
        )

    def test_app_issuance_rejects_expired_token_without_retry(self):
        now, responses = self._app_issuer_responses(expiry="2027-01-15T08:00:00Z")
        transport = FakeTransport(responses)
        with patch("draft_pr_writer._github_app_jwt", return_value="dummy-app-jwt"):
            issuer = GitHubAppInstallationCredentialIssuer(
                app_id=5848436, installation_id=184026537,
                private_key_pem="test-only-private-key-fixture",
                transport=transport, wall_time_fn=lambda: now,
            )
            with self.assertRaisesRegex(GitHubApiHold, "expiry_out_of_bounds"):
                issuer.issue()
            with self.assertRaisesRegex(GitHubApiHold, "already_attempted"):
                issuer.issue()

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

    def test_publication_reader_uses_pinned_bytes_and_independent_audit(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from publisher_gate import PublisherGateHold, publication_reader

        oid = hashlib.sha1(f"blob {len(BODY)}\0".encode() + BODY).hexdigest()
        commit = {"sha": HEAD, "parents": [{"sha": BASE}], "files": [
            {"filename": PATH, "sha": oid, "status": "modified"},
        ]}
        pr = {"number": 1, "state": "open", "draft": True,
              "html_url": f"https://github.com/{PUBLIC_REPOSITORY}/pull/1",
              "head": {"ref": PUBLIC_HEAD_BRANCH, "sha": HEAD, "repo": {"full_name": PUBLIC_REPOSITORY}},
              "base": {"ref": PUBLIC_BASE_BRANCH, "sha": BASE, "repo": {"id": PUBLIC_REPOSITORY_ID}}}
        blob = {"type": "file", "sha": oid, "encoding": "base64",
                "content": base64.b64encode(BODY).decode()}
        run = {"workflow_runs": [{
            "id": 42, "html_url": f"https://github.com/{PUBLIC_REPOSITORY}/actions/runs/42",
            "head_sha": HEAD, "event": "pull_request", "status": "completed", "conclusion": "success",
        }]}
        gate = Mock()
        gate.audit_bundle.return_value = SimpleNamespace(
            repository_id=PUBLIC_REPOSITORY_ID, base_sha=BASE, worker_run_id="worker-fixture",
            file_sha256=((PATH, hashlib.sha256(BODY).hexdigest()),), candidate_digest="c" * 64,
            permit_id="permit-fixture", permit_digest="d" * 64, witness_digest="e" * 64,
            audit_journal_revision=2, audit_journal_head_sha256="f" * 64,
        )
        claim = SimpleNamespace(cycle=2, run_id="worker-fixture", go_sha256="a" * 64)
        transport = FakeTransport([reply([pr]), reply(commit), reply(blob), reply([pr]), reply(run)])
        reader = publication_reader(gate=gate, github_api=self.api(transport),
                                    expected_head_sha=HEAD, bundle={"permit": "trusted-input"})
        result = reader(claim, {"pr_head_sha": "0" * 40, "permit_id": "untrusted"})
        self.assertEqual((result["pr_head_sha"], result["permit_id"], result["readonly_ci_run_id"]),
                         (HEAD, "permit-fixture", "42"))
        gate.audit_bundle.assert_called_once_with(permit="trusted-input")
        self.assertIn("?ref=" + HEAD, transport.calls[2][1])
        self.assertTrue(all(call[0] == "GET" for call in transport.calls))

        gate.audit_bundle.return_value.file_sha256 = ((PATH, "0" * 64),)
        transport = FakeTransport([reply([pr]), reply(commit), reply(blob)])
        reader = publication_reader(gate=gate, github_api=self.api(transport),
                                    expected_head_sha=HEAD, bundle={})
        with self.assertRaisesRegex(PublisherGateHold, "publication_candidate_bytes_mismatch"):
            reader(claim, None)

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
        self.assertIn("GitHubDraftPrApi.from_publisher_app_environment()", source)
        self.assertNotIn('os.environ.get("B09_PUBLISHER_GITHUB_TOKEN", "")', source)
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
