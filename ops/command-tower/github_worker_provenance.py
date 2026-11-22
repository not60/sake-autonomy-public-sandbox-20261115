"""Read-only provenance checks for a completed Worker artifact run."""
from __future__ import annotations

import json
import re
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"
REPOSITORY_ID = 1458303357
WORKFLOW_PATH = ".github/workflows/public-runner-draft.yml"
TRUSTED_BRANCH = "trusted/f4-nonprod-20261119"
ARTIFACT_NAME = "b09-public-runner-candidate"
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class WorkerProvenanceHold(RuntimeError):
    """Worker run or candidate artifact cannot be tied to its source run."""


def verify_worker_artifact_provenance(
    manifest: object,
    *,
    expected_run_id: str,
    expected_base_sha: str,
    expected_execution_sha: str,
    expected_cycle: int,
    bearer_token: str,
    opener: Callable[..., object] = urlopen,
    timeout: float = 5.0,
) -> Mapping[str, object]:
    """Require the exact successful, completed worker attempt and its artifact metadata."""
    if (not isinstance(manifest, dict)
            or set(manifest) != {
                "schema", "repository_id", "base_sha", "worker_run_id",
                "codex_output_sha256", "changed_paths", "files", "candidate_digest",
            }
            or manifest.get("schema") != 2
            or manifest.get("repository_id") != REPOSITORY_ID
            or manifest.get("base_sha") != expected_base_sha
            or not isinstance(expected_base_sha, str) or not _GIT_SHA.fullmatch(expected_base_sha)
            or not isinstance(expected_execution_sha, str) or not _GIT_SHA.fullmatch(expected_execution_sha)
            or isinstance(expected_cycle, bool) or expected_cycle not in (1, 2)
            or not isinstance(expected_run_id, str) or not expected_run_id.isdigit()
            or not isinstance(bearer_token, str) or not bearer_token
            or timeout <= 0):
        raise WorkerProvenanceHold("worker_manifest_or_scope_invalid")
    prefix = expected_run_id + "-"
    worker_run_id = manifest.get("worker_run_id")
    if not isinstance(worker_run_id, str) or not worker_run_id.startswith(prefix):
        raise WorkerProvenanceHold("worker_run_id_mismatch")
    identity = re.fullmatch(r"([1-9][0-9]*)-cycle-([12])", worker_run_id[len(prefix):])
    if identity is None or int(identity.group(2)) != expected_cycle:
        raise WorkerProvenanceHold("worker_attempt_or_cycle_invalid")
    attempt = int(identity.group(1))

    run = _get_json(
        f"/repos/{REPOSITORY}/actions/runs/{expected_run_id}",
        bearer_token=bearer_token, opener=opener, timeout=timeout,
    )
    artifacts = _get_json(
        f"/repos/{REPOSITORY}/actions/runs/{expected_run_id}/artifacts",
        bearer_token=bearer_token, opener=opener, timeout=timeout,
    )
    repository = run.get("repository") if isinstance(run, Mapping) else None
    if (not isinstance(run, Mapping) or not isinstance(repository, Mapping)
            or repository.get("id") != REPOSITORY_ID
            or run.get("id") != int(expected_run_id)
            or run.get("run_attempt") != attempt
            or run.get("path") != WORKFLOW_PATH
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != TRUSTED_BRANCH
            or run.get("head_sha") != expected_execution_sha
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or not isinstance(artifacts, Mapping)
            or not isinstance(artifacts.get("artifacts"), list)):
        raise WorkerProvenanceHold("worker_run_not_completed_successfully_or_scope_mismatch")
    matches = [item for item in artifacts["artifacts"]
               if isinstance(item, Mapping) and item.get("name") == ARTIFACT_NAME]
    if len(matches) != 1:
        raise WorkerProvenanceHold("worker_artifact_missing_or_duplicated")
    artifact = matches[0]
    linked_run = artifact.get("workflow_run")
    if (not isinstance(linked_run, Mapping)
            or linked_run.get("id") != int(expected_run_id)
            or linked_run.get("repository_id") != REPOSITORY_ID
            or linked_run.get("head_branch") != TRUSTED_BRANCH
            or linked_run.get("head_sha") != expected_execution_sha
            or artifact.get("expired") is not False
            or isinstance(artifact.get("id"), bool)
            or not isinstance(artifact.get("id"), int)
            or artifact.get("id") <= 0
            or not isinstance(artifact.get("digest"), str)
            or not _DIGEST.fullmatch(artifact["digest"])):
        raise WorkerProvenanceHold("worker_artifact_metadata_invalid")
    return {
        "repository_id": REPOSITORY_ID,
        "workflow_run_id": expected_run_id,
        "run_attempt": attempt,
        "workflow_path": WORKFLOW_PATH,
        "source_commit_sha": expected_execution_sha,
        "artifact_name": ARTIFACT_NAME,
        "artifact_id": artifact["id"],
        "archive_digest": artifact["digest"],
        "expired": artifact["expired"],
    }


def _get_json(path: str, *, bearer_token: str,
              opener: Callable[..., object], timeout: float) -> object:
    request = Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + bearer_token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with opener(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise WorkerProvenanceHold("github_read_status_not_ok")
            return json.loads(response.read().decode("utf-8"))
    except WorkerProvenanceHold:
        raise
    except (HTTPError, URLError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise WorkerProvenanceHold("github_worker_provenance_unavailable") from None
