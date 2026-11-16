"""Least-privilege Draft PR writer boundary; all GitHub I/O is injected."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Mapping, Protocol

from publisher_gate import (
    DraftPrPlan,
    PUBLIC_BASE_BRANCH,
    PUBLIC_HEAD_BRANCH,
    PUBLIC_REPOSITORY,
    PUBLIC_REPOSITORY_ID,
    is_gate_approved_draft_pr_plan,
)


ALLOWED_CHANGED_PATHS = frozenset({
    "ops/command-tower/policy-public-runner.draft.json",
    "ops/command-tower/runtime-public-runner.draft.json",
    "ops/command-tower/backlog-public-runner.draft.json",
    "ops/command-tower/test_public_runner_draft_contract.py",
    "ops/command-tower/isolated_runtime.py",
    "ops/command-tower/test_isolated_runtime.py",
    "ops/command-tower/durable_store.py",
    "ops/command-tower/test_durable_store.py",
    "ops/command-tower/test_process_crash_recovery.py",
    "ops/command-tower/publisher_gate.py",
    "ops/command-tower/runner_artifact.py",
    "ops/command-tower/cas_journal.py",
    "ops/command-tower/attestations.py",
    "ops/command-tower/requirements-publisher.txt",
    "ops/command-tower/test_cas_journal.py",
    "ops/command-tower/test_durable_permit_identity.py",
    "ops/command-tower/test_publisher_gate.py",
    "ops/command-tower/test_publisher_gate_crypto.py",
    "ops/command-tower/test_runner_artifact.py",
})
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CREATE_COMMIT_ON_BRANCH = """\
mutation CreateCommitOnBranch($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) {
    commit {
      oid
      parents(first: 1) { nodes { oid } }
    }
  }
}
"""


class WriterHold(RuntimeError):
    """A pre-write boundary rejected the Draft PR request."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ClientOutcomeUnknown(TimeoutError):
    """The remote create request may have reached GitHub, but no response arrived."""


class ClientRejected(RuntimeError):
    """The client received an explicit rejection before creating a PR."""


class CommitOutcomeUnknown(TimeoutError):
    """The branch ref update may have succeeded, but no response arrived."""


@dataclass(frozen=True)
class RepositorySnapshot:
    repository_id: int
    full_name: str
    archived: bool


@dataclass(frozen=True)
class PermissionSnapshot:
    repository_id: int
    credential_role: str
    permissions: Mapping[str, str]


@dataclass(frozen=True)
class BranchSnapshot:
    branch: str
    sha: str
    base_sha: str
    file_sha256: Mapping[str, str]


@dataclass(frozen=True)
class BranchCommitResult:
    repository_id: int
    branch: str
    expected_head_oid: str
    commit_sha: str


@dataclass(frozen=True)
class DraftPrRequest:
    repository_id: int
    repository_full_name: str
    head: str
    base: str
    title: str
    body: str
    draft: bool = True


@dataclass(frozen=True)
class DraftPrCreated:
    repository_id: int
    number: int
    url: str
    head: str
    base: str
    draft: bool


class DraftPrApi(Protocol):
    """Injected GitHub boundary; writes are limited to branch commit and Draft PR."""

    def get_repository(self, repository_id: int) -> RepositorySnapshot: ...
    def get_permissions(self, repository_id: int) -> PermissionSnapshot: ...
    def get_branch(self, repository_id: int, branch: str) -> BranchSnapshot: ...
    def find_open_pull_request(self, repository_id: int, head: str, base: str) -> bool: ...
    def execute_graphql(self, query: str,
                        variables: Mapping[str, object]) -> Mapping[str, object]: ...
    def create_draft_pull_request(self, request: DraftPrRequest) -> DraftPrCreated: ...


class DraftPrWriter:
    """Write a Draft PR only after Gate receipt, branch, bytes, and auth readback pass.

    This module contains no GitHub client implementation. A real client must be
    explicitly injected. Unit tests use an in-memory fake and never connect.
    """

    def __init__(self, api: DraftPrApi, *,
                 authorization_check=is_gate_approved_draft_pr_plan) -> None:
        self._api = api
        self._authorization_check = authorization_check
        self._commit_attempted: set[tuple[int, str, str, str]] = set()

    def commit_verified_artifact_and_create_draft(
            self, plan: DraftPrPlan, *, artifact_root: str | Path,
            expected_head_sha: str) -> DraftPrCreated:
        """Commit verified artifact bytes to the one allowed branch, then request a Draft PR."""
        try:
            authorized = self._authorization_check(plan)
        except Exception:
            raise WriterHold("publisher_gate_hold") from None
        if not authorized:
            raise WriterHold("publisher_gate_receipt_missing")
        self._check_plan_scope(plan)
        if not _GIT_SHA.fullmatch(expected_head_sha):
            raise WriterHold("expected_head_sha_invalid")

        try:
            repository = self._api.get_repository(PUBLIC_REPOSITORY_ID)
            permissions = self._api.get_permissions(PUBLIC_REPOSITORY_ID)
            base = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_BASE_BRANCH)
            head = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH)
        except Exception:
            raise WriterHold("github_readback_failed") from None

        if (repository.repository_id != PUBLIC_REPOSITORY_ID
                or repository.full_name != PUBLIC_REPOSITORY
                or repository.archived):
            raise WriterHold("repository_identity_mismatch")
        if (permissions.repository_id != PUBLIC_REPOSITORY_ID
                or permissions.credential_role != "publisher"
                or permissions.permissions != {
                    "contents": "write", "pull_requests": "write", "actions": "none",
                }):
            raise WriterHold("publisher_permission_scope_mismatch")
        if base.branch != PUBLIC_BASE_BRANCH or base.sha != plan.base_sha:
            raise WriterHold("main_base_sha_changed")
        if (head.branch != PUBLIC_HEAD_BRANCH or head.base_sha != plan.base_sha
                or head.sha != expected_head_sha):
            raise WriterHold("head_branch_or_expected_head_mismatch")

        files = self._read_verified_artifact(plan, artifact_root)
        query, variables = self._build_graphql_commit(
            expected_head_oid=expected_head_sha, files=files,
            worker_run_id=plan.worker_run_id,
        )
        attempt_key = (PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH,
                       expected_head_sha, plan.candidate_digest)
        if attempt_key in self._commit_attempted:
            raise WriterHold("commit_attempt_already_used_no_retry")
        self._commit_attempted.add(attempt_key)
        try:
            response = self._api.execute_graphql(query, variables)
        except CommitOutcomeUnknown:
            raise WriterHold("commit_outcome_unknown_no_retry") from None
        except Exception:
            raise WriterHold("commit_outcome_unknown_no_retry") from None
        committed = self._parse_graphql_commit(response, expected_head_sha)

        try:
            base_after = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_BASE_BRANCH)
            head_after = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH)
        except Exception:
            raise WriterHold("post_commit_readback_failed") from None
        if base_after.sha != plan.base_sha:
            raise WriterHold("main_changed_after_branch_commit")
        if (head_after.branch != PUBLIC_HEAD_BRANCH or head_after.sha != committed.commit_sha
                or head_after.base_sha != plan.base_sha
                or dict(head_after.file_sha256) != dict(plan.file_sha256)):
            raise WriterHold("branch_commit_readback_mismatch")
        return self.create_draft(plan, expected_head_sha=committed.commit_sha)

    @staticmethod
    def _build_graphql_commit(*, expected_head_oid: str,
                              files: Mapping[str, bytes],
                              worker_run_id: str) -> tuple[str, dict[str, object]]:
        """Build the actual createCommitOnBranch input; never includes a force field."""
        if not _GIT_SHA.fullmatch(expected_head_oid) or not files:
            raise WriterHold("graphql_commit_scope_invalid")
        additions = []
        for path, content in sorted(files.items()):
            if path not in ALLOWED_CHANGED_PATHS or not isinstance(content, bytes):
                raise WriterHold("graphql_commit_file_outside_allowlist")
            additions.append({
                "path": path,
                "contents": base64.b64encode(content).decode("ascii"),
            })
        return _CREATE_COMMIT_ON_BRANCH, {
            "input": {
                "branch": {
                    "repositoryNameWithOwner": PUBLIC_REPOSITORY,
                    "branchName": PUBLIC_HEAD_BRANCH,
                },
                "message": {"headline": f"Verified sandbox candidate {worker_run_id}"},
                "fileChanges": {"additions": additions},
                "expectedHeadOid": expected_head_oid,
            },
        }

    @staticmethod
    def _parse_graphql_commit(response: Mapping[str, object],
                              expected_head_oid: str) -> BranchCommitResult:
        if not isinstance(response, Mapping):
            raise WriterHold("commit_outcome_unknown_no_retry")
        errors = response.get("errors")
        if errors:
            raise WriterHold("branch_commit_rejected_expected_head_or_api_error")
        try:
            data = response["data"]
            payload = data["createCommitOnBranch"]
            commit = payload["commit"]
            commit_sha = commit["oid"]
            parents = commit["parents"]["nodes"]
            parent_sha = parents[0]["oid"]
        except (KeyError, IndexError, TypeError):
            raise WriterHold("commit_outcome_unknown_no_retry") from None
        if (not isinstance(commit_sha, str) or not _GIT_SHA.fullmatch(commit_sha)
                or parent_sha != expected_head_oid):
            raise WriterHold("branch_commit_response_scope_mismatch")
        return BranchCommitResult(
            repository_id=PUBLIC_REPOSITORY_ID,
            branch=PUBLIC_HEAD_BRANCH,
            expected_head_oid=parent_sha,
            commit_sha=commit_sha,
        )

    def create_draft(self, plan: DraftPrPlan, *, expected_head_sha: str) -> DraftPrCreated:
        """Create a Draft PR only when the exact verified branch head is still current."""
        try:
            authorized = self._authorization_check(plan)
        except Exception:
            raise WriterHold("publisher_gate_hold") from None
        if not authorized:
            raise WriterHold("publisher_gate_receipt_missing")
        self._check_plan_scope(plan)
        if not _GIT_SHA.fullmatch(expected_head_sha):
            raise WriterHold("expected_head_sha_invalid")
        try:
            repository = self._api.get_repository(PUBLIC_REPOSITORY_ID)
            permissions = self._api.get_permissions(PUBLIC_REPOSITORY_ID)
            base = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_BASE_BRANCH)
            head = self._api.get_branch(PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH)
            existing = self._api.find_open_pull_request(
                PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
            )
        except Exception:
            raise WriterHold("github_readback_failed") from None
        if (repository.repository_id != PUBLIC_REPOSITORY_ID
                or repository.full_name != PUBLIC_REPOSITORY or repository.archived):
            raise WriterHold("repository_identity_mismatch")
        if (permissions.repository_id != PUBLIC_REPOSITORY_ID
                or permissions.credential_role != "publisher"
                or permissions.permissions != {
                    "contents": "write", "pull_requests": "write", "actions": "none",
                }):
            raise WriterHold("publisher_permission_scope_mismatch")
        if base.branch != PUBLIC_BASE_BRANCH or base.sha != plan.base_sha:
            raise WriterHold("main_base_sha_changed")
        if (head.branch != PUBLIC_HEAD_BRANCH or head.base_sha != plan.base_sha
                or head.sha != expected_head_sha
                or set(head.file_sha256) != set(plan.changed_paths)
                or dict(head.file_sha256) != dict(plan.file_sha256)):
            raise WriterHold("head_branch_or_file_sha_mismatch")
        if existing:
            raise WriterHold("draft_pr_already_exists")

        request = DraftPrRequest(
            repository_id=PUBLIC_REPOSITORY_ID,
            repository_full_name=PUBLIC_REPOSITORY,
            head=PUBLIC_HEAD_BRANCH,
            base=PUBLIC_BASE_BRANCH,
            title=plan.title,
            body=plan.body,
            draft=True,
        )
        try:
            created = self._api.create_draft_pull_request(request)
        except ClientOutcomeUnknown:
            # Never retry: the remote side may have accepted the request.
            raise WriterHold("create_outcome_unknown_no_retry") from None
        except ClientRejected:
            raise WriterHold("github_explicitly_rejected_draft_pr") from None
        except Exception:
            # Unknown transport failures are ambiguous and are not retried.
            raise WriterHold("create_outcome_unknown_no_retry") from None
        if (created.repository_id != PUBLIC_REPOSITORY_ID or created.number <= 0
                or not created.url.startswith("https://github.com/")
                or created.head != PUBLIC_HEAD_BRANCH or created.base != PUBLIC_BASE_BRANCH
                or created.draft is not True):
            raise WriterHold("create_response_scope_mismatch")
        return created

    @staticmethod
    def _read_verified_artifact(plan: DraftPrPlan, artifact_root: str | Path) -> dict[str, bytes]:
        try:
            root = Path(artifact_root).resolve(strict=True)
            artifact_dir = root / "files"
            if not root.is_dir() or artifact_dir.is_symlink():
                raise OSError
        except OSError:
            raise WriterHold("verified_artifact_root_invalid") from None
        files: dict[str, bytes] = {}
        for relative, expected_sha in plan.file_sha256:
            if relative not in ALLOWED_CHANGED_PATHS:
                raise WriterHold("artifact_path_outside_allowlist")
            path = artifact_dir.joinpath(*relative.split("/"))
            try:
                if path.is_symlink() or not path.is_file():
                    raise OSError
                path.resolve(strict=True).relative_to(artifact_dir.resolve(strict=True))
                content = path.read_bytes()
            except (OSError, ValueError):
                raise WriterHold("artifact_file_missing_or_unsafe") from None
            if hashlib.sha256(content).hexdigest() != expected_sha:
                raise WriterHold("artifact_sha256_mismatch")
            files[relative] = content
        if set(files) != set(plan.changed_paths) or not files:
            raise WriterHold("artifact_path_manifest_mismatch")
        return files

    @staticmethod
    def _check_plan_scope(plan: DraftPrPlan) -> None:
        if (plan.repository_id != PUBLIC_REPOSITORY_ID
                or plan.base_branch != PUBLIC_BASE_BRANCH
                or plan.head_branch != PUBLIC_HEAD_BRANCH
                or plan.base_sha != plan.base_sha.lower()
                or len(plan.base_sha) != 40
                or any(ch not in "0123456789abcdef" for ch in plan.base_sha)):
            raise WriterHold("draft_pr_plan_scope_mismatch")
        if (not plan.changed_paths or len(set(plan.changed_paths)) != len(plan.changed_paths)
                or any(path not in ALLOWED_CHANGED_PATHS for path in plan.changed_paths)
                or len(dict(plan.file_sha256)) != len(plan.file_sha256)
                or set(dict(plan.file_sha256)) != set(plan.changed_paths)
                or any(len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest)
                       for digest in dict(plan.file_sha256).values())):
            raise WriterHold("draft_pr_paths_or_file_sha_not_allowlisted")
