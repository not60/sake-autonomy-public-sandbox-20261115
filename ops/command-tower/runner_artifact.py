"""Build a DRAFT_HOLD bundle from the Worker worktree's actual delta."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArtifactBuildHold(RuntimeError):
    """The requested artifact cannot be packaged within the allowlist."""


def discover_changed_paths(worktree_root: str | Path, base_sha: str) -> tuple[str, ...]:
    root = Path(worktree_root).resolve(strict=True)
    if not _GIT_SHA.fullmatch(base_sha):
        raise ArtifactBuildHold("base_sha_invalid")

    def git(*args: str) -> bytes:
        try:
            return subprocess.run(
                ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            raise ArtifactBuildHold("git_delta_unavailable") from None

    head = git("rev-parse", "HEAD").decode("ascii", "strict").strip()
    if head != base_sha:
        raise ArtifactBuildHold("worktree_head_does_not_match_base_sha")
    if git("ls-files", "-u", "-z"):
        raise ArtifactBuildHold("unmerged_paths_present")

    raw = git("diff", "--name-status", "-z", "--no-renames", base_sha, "--")
    pieces = raw.split(b"\0")
    changed: set[str] = set()
    index = 0
    while index < len(pieces) and pieces[index]:
        status = pieces[index].decode("ascii", "strict")
        index += 1
        if index >= len(pieces) or not pieces[index]:
            raise ArtifactBuildHold("git_delta_malformed")
        path = pieces[index].decode("utf-8", "strict")
        index += 1
        if status not in {"A", "M"}:
            raise ArtifactBuildHold("unsupported_change_type")
        changed.add(path)

    untracked = git("ls-files", "--others", "--exclude-standard", "-z")
    for raw_path in untracked.split(b"\0"):
        if raw_path:
            changed.add(raw_path.decode("utf-8", "strict"))
    if not changed:
        raise ArtifactBuildHold("no_worker_changes")
    return tuple(sorted(changed))


def build_artifact(*, worktree_root: str | Path, output_root: str | Path,
                   repository_id: int, base_sha: str, worker_run_id: str,
                   codex_output_file: str | Path,
                   allowed_paths: tuple[str, ...],
                   changed_paths: tuple[str, ...] | None = None) -> dict[str, object]:
    if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id <= 0:
        raise ArtifactBuildHold("repository_id_invalid")
    if not isinstance(worker_run_id, str) or not worker_run_id or len(worker_run_id) > 160:
        raise ArtifactBuildHold("worker_run_id_invalid")
    if not isinstance(base_sha, str) or not _GIT_SHA.fullmatch(base_sha):
        raise ArtifactBuildHold("base_sha_invalid")
    if not allowed_paths or len(set(allowed_paths)) != len(allowed_paths):
        raise ArtifactBuildHold("allowlist_missing_or_duplicate")
    if any(not _safe_path(path) for path in allowed_paths):
        raise ArtifactBuildHold("allowlist_path_invalid")

    root = Path(worktree_root)
    output = Path(output_root)
    try:
        root = root.resolve(strict=True)
    except OSError:
        raise ArtifactBuildHold("worktree_missing") from None
    if not root.is_dir() or output.exists() or output.is_symlink():
        raise ArtifactBuildHold("output_or_worktree_invalid")

    actual_paths = discover_changed_paths(root, base_sha)
    if changed_paths is not None and tuple(sorted(changed_paths)) != actual_paths:
        raise ArtifactBuildHold("supplied_paths_do_not_match_worker_delta")
    if any(path not in set(allowed_paths) or not _safe_path(path) for path in actual_paths):
        raise ArtifactBuildHold("path_outside_allowlist")

    output_file = Path(codex_output_file)
    if output_file.is_symlink() or not output_file.is_file():
        raise ArtifactBuildHold("codex_output_missing_or_symlink")
    try:
        output_bytes = output_file.read_bytes()
    except OSError:
        raise ArtifactBuildHold("codex_output_unreadable") from None
    if not output_bytes:
        raise ArtifactBuildHold("codex_output_empty")
    codex_output_sha256 = hashlib.sha256(output_bytes).hexdigest()

    file_digests: dict[str, str] = {}
    copied: list[tuple[str, bytes]] = []
    for relative in actual_paths:
        source = root.joinpath(*relative.split("/"))
        if source.is_symlink() or not source.is_file():
            raise ArtifactBuildHold("source_file_missing_or_symlink")
        try:
            source.resolve(strict=True).relative_to(root)
            content = source.read_bytes()
        except (OSError, ValueError):
            raise ArtifactBuildHold("source_file_unreadable") from None
        file_digests[relative] = hashlib.sha256(content).hexdigest()
        copied.append((relative, content))

    material: dict[str, object] = {
        "schema": 2,
        "repository_id": repository_id,
        "base_sha": base_sha,
        "worker_run_id": worker_run_id,
        "codex_output_sha256": codex_output_sha256,
        "changed_paths": list(actual_paths),
        "files": file_digests,
    }
    manifest = {**material, "candidate_digest": hashlib.sha256(_canonical(material)).hexdigest()}
    try:
        output.mkdir(parents=True)
        for relative, content in copied:
            target = output / "files" / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        evidence = output / "evidence"
        evidence.mkdir()
        (evidence / "codex-output.bin").write_bytes(output_bytes)
        (output / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8",
        )
        (output / "permit.json").write_text('{"state":"NOT_ISSUED"}\n', encoding="utf-8")
        (output / "witness.json").write_text('{"state":"NOT_ISSUED"}\n', encoding="utf-8")
        (output / "owner-approvals.json").write_text(
            '{"state":"NOT_APPROVED"}\n', encoding="utf-8",
        )
    except OSError:
        raise ArtifactBuildHold("artifact_output_failed") from None
    return manifest


def _safe_path(path: str) -> bool:
    return (isinstance(path, str) and path.startswith("ops/command-tower/")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package actual Worker changes as DRAFT_HOLD")
    parser.add_argument("--worktree-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--worker-run-id", required=True)
    parser.add_argument("--codex-output-file", required=True)
    parser.add_argument("--allowed-path", required=True, action="append")
    args = parser.parse_args(argv)
    try:
        build_artifact(
            worktree_root=args.worktree_root, output_root=args.output_root,
            repository_id=args.repository_id, base_sha=args.base_sha,
            worker_run_id=args.worker_run_id, codex_output_file=args.codex_output_file,
            allowed_paths=tuple(args.allowed_path),
        )
    except ArtifactBuildHold as exc:
        print(f"HOLD:{exc}", file=sys.stderr)
        return 2
    print("DRAFT_HOLD_ACTUAL_DELTA_PACKAGED_UNAUTHORIZED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
