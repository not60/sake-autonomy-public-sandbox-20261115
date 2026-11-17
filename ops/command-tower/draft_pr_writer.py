"""Least-privilege Draft PR writer boundary; all GitHub I/O is injected."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

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


class GitHubApiHold(RuntimeError):
    """GitHub readback or a fixed API boundary failed closed."""


class GitHubPermissionScopeUnverifiable(GitHubApiHold):
    """GitHub does not expose the supplied token's effective fine-grained grant."""


class GitHubApiRejected(RuntimeError):
    """GitHub explicitly rejected a request; the caller must not retry."""


class GitHubReadOnlyCiPending(GitHubApiHold):
    """A read-only PR workflow has not appeared yet; bounded polling may continue."""


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
    head_sha: str = ""
    base_sha: str = ""


@dataclass(frozen=True)
class GitHubWorkflowRunSnapshot:
    run_id: int
    url: str
    head_sha: str
    event: str
    status: str
    conclusion: str | None
    base_sha: str = ""


class DraftPrApi(Protocol):
    """Injected GitHub boundary; writes are limited to branch commit and Draft PR."""

    def get_repository(self, repository_id: int) -> RepositorySnapshot: ...
    def get_permissions(self, repository_id: int) -> PermissionSnapshot: ...
    def get_branch(self, repository_id: int, branch: str) -> BranchSnapshot: ...
    def find_open_pull_request(self, repository_id: int, head: str, base: str) -> bool: ...
    def get_open_draft_pull_request(self, repository_id: int, head: str,
                                    base: str) -> DraftPrCreated: ...
    def execute_graphql(self, query: str,
                        variables: Mapping[str, object]) -> Mapping[str, object]: ...
    def create_draft_pull_request(self, request: DraftPrRequest) -> DraftPrCreated: ...
    def authorize_write(self, plan: DraftPrPlan,
                        permissions: PermissionSnapshot) -> None: ...
    def read_readonly_ci_run(self, pull_request_number: int,
                             expected_head_sha: str,
                             expected_base_sha: str) -> GitHubWorkflowRunSnapshot: ...
    def wait_for_readonly_ci_run(self, pull_request_number: int,
                                 expected_head_sha: str,
                                 expected_base_sha: str) -> GitHubWorkflowRunSnapshot: ...


class DraftPrWriter:
    """Write a Draft PR only after Gate receipt, branch, bytes, and auth readback pass.

    The Writer is transport-agnostic. GitHubDraftPrApi is the fixed-scope
    concrete adapter; unit tests inject an in-memory fake and never connect.
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
            existing = self._api.find_open_pull_request(
                PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
            )
            existing_pr = (self._api.get_open_draft_pull_request(
                PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
            ) if existing else None)
        except GitHubPermissionScopeUnverifiable:
            raise WriterHold("publisher_permission_scope_unverifiable") from None
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
        if existing and (existing_pr is None or not _valid_draft_pr_reference(
                existing_pr, expected_head_sha=expected_head_sha,
                expected_base_sha=plan.base_sha)):
            raise WriterHold("existing_pull_request_not_reusable")

        authorize_write = getattr(self._api, "authorize_write", None)
        if callable(authorize_write):
            try:
                authorize_write(plan, permissions)
            except Exception:
                raise WriterHold("publisher_write_authorization_missing") from None

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
        expected_branch_files = dict(head.file_sha256)
        expected_branch_files.update(dict(plan.file_sha256))
        if (head_after.branch != PUBLIC_HEAD_BRANCH or head_after.sha != committed.commit_sha
                or head_after.base_sha != plan.base_sha
                or dict(head_after.file_sha256) != expected_branch_files):
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
                or any(head.file_sha256.get(path) != digest
                       for path, digest in plan.file_sha256)):
            raise WriterHold("head_branch_or_file_sha_mismatch")
        if existing:
            try:
                existing_pr = self._api.get_open_draft_pull_request(
                    PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
                )
            except Exception:
                raise WriterHold("existing_pull_request_readback_failed") from None
            if not _valid_draft_pr_reference(
                    existing_pr, expected_head_sha=expected_head_sha,
                    expected_base_sha=plan.base_sha):
                raise WriterHold("existing_pull_request_not_reusable")
            return existing_pr

        authorize_write = getattr(self._api, "authorize_write", None)
        if callable(authorize_write):
            try:
                authorize_write(plan, permissions)
            except Exception:
                raise WriterHold("publisher_write_authorization_missing") from None

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
                or not created.url.startswith(
                    "https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/"
                )
                or created.head != PUBLIC_HEAD_BRANCH or created.base != PUBLIC_BASE_BRANCH
                or created.draft is not True or created.head_sha != expected_head_sha
                or created.base_sha != plan.base_sha):
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


class GitHubDraftPrApi:
    """Concrete GitHub REST/GraphQL adapter for the fixed public sandbox.

    The bearer token is held only in memory and is never read from the
    environment, persisted, or included in diagnostics. The adapter refuses
    mutation unless DraftPrWriter first authorizes the exact signed plan and
    permission snapshot. GitHub's repository `permissions` field describes
    the viewer's repository role, not a fine-grained token's effective grant;
    that check therefore remains a fail-closed HOLD.
    """

    API_ROOT = "https://api.github.com"

    def __init__(self, bearer_token: str, *, timeout: float = 15.0,
                 transport: Callable | None = None,
                 sleep_fn: Callable[[float], None] = time.sleep,
                 monotonic_fn: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(bearer_token, str) or not bearer_token.strip():
            raise ValueError("publisher credential is required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._bearer_token = bearer_token
        self._timeout = timeout
        self._transport = transport or self._urlopen_transport
        self._sleep = sleep_fn
        self._monotonic = monotonic_fn
        self._write_authorized = False
        self._graphql_attempted = False
        self._pr_attempted = False

    def get_repository(self, repository_id: int) -> RepositorySnapshot:
        if repository_id != PUBLIC_REPOSITORY_ID:
            raise GitHubApiHold("repository_id_not_allowlisted")
        value = self._request("GET", f"/repositories/{PUBLIC_REPOSITORY_ID}")
        if (value.get("id") != PUBLIC_REPOSITORY_ID
                or value.get("full_name") != PUBLIC_REPOSITORY):
            raise GitHubApiHold("repository_identity_mismatch")
        archived = value.get("archived")
        if not isinstance(archived, bool):
            raise GitHubApiHold("repository_archive_state_missing")
        return RepositorySnapshot(PUBLIC_REPOSITORY_ID, PUBLIC_REPOSITORY, archived)

    def get_permissions(self, repository_id: int) -> PermissionSnapshot:
        if repository_id != PUBLIC_REPOSITORY_ID:
            raise GitHubApiHold("repository_id_not_allowlisted")
        value = self._request("GET", f"/repos/{PUBLIC_REPOSITORY}")
        if value.get("id") != PUBLIC_REPOSITORY_ID or value.get("full_name") != PUBLIC_REPOSITORY:
            raise GitHubApiHold("repository_identity_mismatch")
        # GitHub returns the viewer's repository role here; it does not
        # establish the fine-grained PAT/App token's exact permission grant.
        raise GitHubPermissionScopeUnverifiable("token_permission_scope_not_exposed")

    def get_branch(self, repository_id: int, branch: str) -> BranchSnapshot:
        self._check_repo(repository_id)
        if branch not in {PUBLIC_BASE_BRANCH, PUBLIC_HEAD_BRANCH}:
            raise GitHubApiHold("branch_not_allowlisted")
        ref = self._request(
            "GET", f"/repos/{PUBLIC_REPOSITORY}/branches/{quote(branch, safe='')}"
        )
        head_sha = _required_git_sha(ref.get("commit", {}).get("sha"), "branch_head_invalid")
        if branch == PUBLIC_BASE_BRANCH:
            return BranchSnapshot(branch, head_sha, head_sha, {})

        comparison = self._request(
            "GET", f"/repos/{PUBLIC_REPOSITORY}/compare/{PUBLIC_BASE_BRANCH}...{quote(branch, safe='')}"
        )
        base_sha = _required_git_sha(
            comparison.get("base_commit", {}).get("sha"), "branch_base_invalid",
        )
        compare_head = _required_git_sha(
            comparison.get("head_commit", {}).get("sha"), "branch_compare_head_invalid",
        )
        if compare_head != head_sha:
            raise GitHubApiHold("branch_changed_during_readback")
        changed = comparison.get("files")
        if not isinstance(changed, list):
            raise GitHubApiHold("branch_file_list_unavailable")
        file_digests: dict[str, str] = {}
        for entry in changed:
            if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
                raise GitHubApiHold("branch_file_list_invalid")
            path = entry["filename"]
            if (path not in ALLOWED_CHANGED_PATHS
                    or entry.get("status") not in {"added", "modified", "changed"}):
                raise GitHubApiHold("branch_path_outside_allowlist_or_deleted")
            content = self._request(
                "GET", f"/repos/{PUBLIC_REPOSITORY}/contents/{quote(path, safe='/')}"
                f"?{urlencode({'ref': branch})}"
            )
            if content.get("type") != "file" or content.get("encoding") != "base64":
                raise GitHubApiHold("branch_file_content_unavailable")
            encoded = content.get("content")
            if not isinstance(encoded, str):
                raise GitHubApiHold("branch_file_content_invalid")
            try:
                raw = base64.b64decode("".join(encoded.split()), validate=True)
            except (ValueError, base64.binascii.Error):
                raise GitHubApiHold("branch_file_content_encoding_invalid") from None
            file_digests[path] = hashlib.sha256(raw).hexdigest()
        return BranchSnapshot(branch, head_sha, base_sha, file_digests)

    def find_open_pull_request(self, repository_id: int, head: str, base: str) -> bool:
        return self._matching_open_pull_request(repository_id, head, base) is not None

    def get_open_draft_pull_request(self, repository_id: int, head: str,
                                    base: str) -> DraftPrCreated:
        value = self._matching_open_pull_request(repository_id, head, base)
        if value is None:
            raise GitHubApiHold("open_pull_request_not_found")
        try:
            result = DraftPrCreated(
                repository_id=value["base"]["repo"]["id"], number=value["number"],
                url=value["html_url"], head=value["head"]["ref"],
                base=value["base"]["ref"], draft=value["draft"],
                head_sha=value["head"]["sha"],
                base_sha=value["base"]["sha"],
            )
        except (KeyError, TypeError):
            raise GitHubApiHold("open_pull_request_shape_invalid") from None
        if not _valid_draft_pr_reference(
                result, expected_head_sha=result.head_sha,
                expected_base_sha=result.base_sha):
            raise GitHubApiHold("open_pull_request_scope_invalid")
        return result

    def read_readonly_ci_run(self, pull_request_number: int,
                             expected_head_sha: str,
                             expected_base_sha: str) -> GitHubWorkflowRunSnapshot:
        if (isinstance(pull_request_number, bool) or pull_request_number != 1
                or not isinstance(expected_head_sha, str)
                or not _GIT_SHA.fullmatch(expected_head_sha)
                or not isinstance(expected_base_sha, str)
                or not _GIT_SHA.fullmatch(expected_base_sha)):
            raise GitHubApiHold("readonly_ci_scope_invalid")
        pr = self.get_open_draft_pull_request(
            PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
        )
        if (pr.number != pull_request_number or pr.head_sha != expected_head_sha
                or pr.base_sha != expected_base_sha):
            raise GitHubApiHold("readonly_ci_pr_sha_mismatch")
        query = urlencode({"head_sha": expected_head_sha, "per_page": 100})
        document = self._request(
            "GET", f"/repos/{PUBLIC_REPOSITORY}/actions/workflows/sandbox-pr-readonly.yml/runs?{query}"
        )
        runs = document.get("workflow_runs") if isinstance(document, dict) else None
        if not isinstance(runs, list):
            raise GitHubApiHold("readonly_ci_run_list_invalid")
        matches = [run for run in runs if isinstance(run, dict)
                   and run.get("head_sha") == expected_head_sha
                   and run.get("event") == "pull_request"]
        if not matches:
            raise GitHubReadOnlyCiPending("readonly_ci_run_not_visible_yet")
        if len(matches) != 1:
            raise GitHubApiHold("readonly_ci_run_missing_or_ambiguous")
        run = matches[0]
        run_id, url = run.get("id"), run.get("html_url")
        status, conclusion = run.get("status"), run.get("conclusion")
        if (isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0
                or not isinstance(url, str)
                or not url.startswith("https://github.com/not60/sake-autonomy-public-sandbox-20261115/actions/runs/")
                or status not in {"queued", "in_progress", "completed"}
                or (status == "completed" and conclusion not in {
                    "success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped",
                })
                or (status != "completed" and conclusion is not None)):
            raise GitHubApiHold("readonly_ci_run_shape_invalid")
        return GitHubWorkflowRunSnapshot(
            run_id, url, expected_head_sha, "pull_request", status, conclusion,
            expected_base_sha,
        )

    def wait_for_readonly_ci_run(self, pull_request_number: int,
                                 expected_head_sha: str,
                                 expected_base_sha: str, *,
                                 timeout_seconds: float = 600.0,
                                 poll_interval_seconds: float = 10.0
                                 ) -> GitHubWorkflowRunSnapshot:
        """Wait boundedly for the exact read-only PR run; this method never writes."""
        if (timeout_seconds <= 0 or poll_interval_seconds <= 0
                or poll_interval_seconds > timeout_seconds):
            raise GitHubApiHold("readonly_ci_wait_bounds_invalid")
        deadline = self._monotonic() + timeout_seconds
        while True:
            try:
                result = self.read_readonly_ci_run(
                    pull_request_number, expected_head_sha, expected_base_sha,
                )
            except GitHubReadOnlyCiPending:
                result = None
            if result is not None and result.status == "completed":
                return result
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise GitHubApiHold("readonly_ci_wait_timed_out")
            self._sleep(min(poll_interval_seconds, remaining))

    def _matching_open_pull_request(self, repository_id: int,
                                    head: str, base: str) -> Mapping[str, object] | None:
        self._check_repo(repository_id)
        if head != PUBLIC_HEAD_BRANCH or base != PUBLIC_BASE_BRANCH:
            raise GitHubApiHold("pull_request_scope_not_allowlisted")
        query = urlencode({
            "state": "open", "base": PUBLIC_BASE_BRANCH,
            "head": f"not60:{PUBLIC_HEAD_BRANCH}",
        })
        values = self._request("GET", f"/repos/{PUBLIC_REPOSITORY}/pulls?{query}")
        if not isinstance(values, list):
            raise GitHubApiHold("pull_request_readback_invalid")
        for value in values:
            if not isinstance(value, dict):
                raise GitHubApiHold("pull_request_readback_invalid")
            if (value.get("state") == "open"
                    and value.get("head", {}).get("ref") == PUBLIC_HEAD_BRANCH
                    and value.get("head", {}).get("repo", {}).get("full_name") == PUBLIC_REPOSITORY
                    and value.get("base", {}).get("ref") == PUBLIC_BASE_BRANCH):
                return value
        return None

    def execute_graphql(self, query: str,
                        variables: Mapping[str, object]) -> Mapping[str, object]:
        if not self._write_authorized:
            raise GitHubApiHold("publisher_write_authorization_missing")
        if self._graphql_attempted:
            raise CommitOutcomeUnknown("graphql_commit_attempt_already_used_no_retry")
        self._validate_graphql_commit(query, variables)
        self._graphql_attempted = True
        return self._request("POST", "/graphql", {"query": query, "variables": variables}, mutation=True)

    def create_draft_pull_request(self, request: DraftPrRequest) -> DraftPrCreated:
        if not self._write_authorized:
            raise GitHubApiHold("publisher_write_authorization_missing")
        if self._pr_attempted:
            raise ClientOutcomeUnknown("draft_pr_attempt_already_used_no_retry")
        if (request.repository_id != PUBLIC_REPOSITORY_ID
                or request.repository_full_name != PUBLIC_REPOSITORY
                or request.head != PUBLIC_HEAD_BRANCH or request.base != PUBLIC_BASE_BRANCH
                or request.draft is not True):
            raise GitHubApiHold("draft_pr_scope_invalid")
        self._pr_attempted = True
        value = self._request("POST", f"/repos/{PUBLIC_REPOSITORY}/pulls", {
            "title": request.title, "body": request.body, "head": request.head,
            "base": request.base, "draft": True,
        }, mutation=True)
        try:
            result = DraftPrCreated(
                repository_id=value["base"]["repo"]["id"], number=value["number"],
                url=value["html_url"], head=value["head"]["ref"],
                base=value["base"]["ref"], draft=value["draft"],
                head_sha=value["head"]["sha"],
                base_sha=value["base"]["sha"],
            )
        except (KeyError, TypeError):
            raise ClientOutcomeUnknown("draft_pr_response_invalid_no_retry") from None
        return result

    def authorize_write(self, plan: DraftPrPlan, permissions: PermissionSnapshot) -> None:
        if (not is_gate_approved_draft_pr_plan(plan)
                or permissions.repository_id != PUBLIC_REPOSITORY_ID
                or permissions.credential_role != "publisher"
                or dict(permissions.permissions) != {
                    "contents": "write", "pull_requests": "write", "actions": "none",
                }):
            raise GitHubApiHold("publisher_plan_or_permissions_invalid")
        self._write_authorized = True

    def _request(self, method: str, path: str, payload: object | None = None,
                 *, mutation: bool = False) -> object:
        if (method not in {"GET", "POST"} or not path.startswith("/")
                or path.startswith("//") or ".." in path.split("/")
                or "#" in path):
            raise GitHubApiHold("github_request_outside_fixed_api")
        body = None if payload is None else json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._bearer_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SAKE-public-sandbox-publisher",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            status, response_headers, response_body = self._transport(
                method, self.API_ROOT + path, headers, body, self._timeout,
            )
        except Exception:
            if mutation:
                raise ClientOutcomeUnknown("github_mutation_outcome_unknown_no_retry") from None
            raise GitHubApiHold("github_read_unavailable") from None
        if status < 200 or status >= 300:
            if mutation and status >= 500:
                raise ClientOutcomeUnknown("github_mutation_outcome_unknown_no_retry")
            if mutation:
                raise ClientRejected("github_mutation_rejected")
            raise GitHubApiHold("github_read_rejected")
        try:
            final_url = response_headers.get("X-Final-URL", self.API_ROOT + path)
            if not final_url.startswith(self.API_ROOT + "/"):
                raise ValueError
            value = json.loads(response_body.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            if mutation:
                raise ClientOutcomeUnknown("github_mutation_response_invalid_no_retry") from None
            raise GitHubApiHold("github_read_response_invalid") from None
        if not isinstance(value, (dict, list)):
            raise GitHubApiHold("github_response_shape_invalid")
        return value

    @staticmethod
    def _urlopen_transport(method: str, url: str, headers: Mapping[str, str],
                           body: bytes | None, timeout: float):
        class RejectRedirects(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, newurl):
                return None

        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with build_opener(RejectRedirects).open(request, timeout=timeout) as response:
                response_headers = dict(response.headers.items())
                response_headers["X-Final-URL"] = response.geturl()
                return response.status, response_headers, response.read()
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise GitHubApiHold("github_redirect_rejected") from None
            return exc.code, dict(exc.headers.items()), exc.read()
        except (URLError, TimeoutError, OSError):
            raise

    @staticmethod
    def _check_repo(repository_id: int) -> None:
        if repository_id != PUBLIC_REPOSITORY_ID:
            raise GitHubApiHold("repository_id_not_allowlisted")

    @staticmethod
    def _validate_graphql_commit(query: str, variables: Mapping[str, object]) -> None:
        if "mutation CreateCommitOnBranch(" not in query:
            raise GitHubApiHold("graphql_mutation_not_allowlisted")
        if not isinstance(variables, Mapping) or set(variables) != {"input"}:
            raise GitHubApiHold("graphql_variables_invalid")
        value = variables["input"]
        if not isinstance(value, Mapping) or set(value) != {
                "branch", "message", "fileChanges", "expectedHeadOid"}:
            raise GitHubApiHold("graphql_input_invalid")
        branch = value["branch"]
        if (not isinstance(branch, Mapping)
                or dict(branch) != {"repositoryNameWithOwner": PUBLIC_REPOSITORY,
                                    "branchName": PUBLIC_HEAD_BRANCH}
                or not isinstance(value["expectedHeadOid"], str)
                or not _GIT_SHA.fullmatch(value["expectedHeadOid"])):
            raise GitHubApiHold("graphql_branch_or_head_not_allowlisted")
        changes = value["fileChanges"]
        additions = changes.get("additions") if isinstance(changes, Mapping) else None
        if not isinstance(additions, list) or not additions:
            raise GitHubApiHold("graphql_file_changes_invalid")
        seen: set[str] = set()
        for item in additions:
            if (not isinstance(item, Mapping) or set(item) != {"path", "contents"}
                    or item["path"] not in ALLOWED_CHANGED_PATHS
                    or item["path"] in seen or not isinstance(item["contents"], str)):
                raise GitHubApiHold("graphql_file_outside_allowlist")
            try:
                base64.b64decode(item["contents"], validate=True)
            except (ValueError, base64.binascii.Error):
                raise GitHubApiHold("graphql_file_encoding_invalid") from None
            seen.add(item["path"])


def _required_git_sha(value: object, reason: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA.fullmatch(value):
        raise GitHubApiHold(reason)
    return value


def _valid_draft_pr_reference(value: object, *, expected_head_sha: str,
                              expected_base_sha: str) -> bool:
    return (
        isinstance(value, DraftPrCreated)
        and value.repository_id == PUBLIC_REPOSITORY_ID
        and value.number > 0
        and value.url.startswith("https://github.com/not60/sake-autonomy-public-sandbox-20261115/pull/")
        and value.head == PUBLIC_HEAD_BRANCH
        and value.base == PUBLIC_BASE_BRANCH
        and value.draft is True
        and isinstance(value.head_sha, str)
        and _GIT_SHA.fullmatch(value.head_sha) is not None
        and value.head_sha == expected_head_sha
        and isinstance(value.base_sha, str)
        and _GIT_SHA.fullmatch(value.base_sha) is not None
        and value.base_sha == expected_base_sha
    )
