"""Create a non-authorizing, hash-bound artifact package for runner jobs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class ArtifactBuildHold(RuntimeError):
    """The requested artifact cannot be packaged within the allowlist."""


def build_artifact(*, worktree_root: str | Path, output_root: str | Path,
                   repository_id: int, base_sha: str,
                   changed_paths: tuple[str, ...],
                   allowed_paths: tuple[str, ...]) -> dict[str, object]:
    if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id <= 0:
        raise ArtifactBuildHold("repository_id_invalid")
    if not isinstance(base_sha, str) or not _GIT_SHA.fullmatch(base_sha):
        raise ArtifactBuildHold("base_sha_invalid")
    if not changed_paths or len(set(changed_paths)) != len(changed_paths):
        raise ArtifactBuildHold("changed_paths_missing_or_duplicate")
    if not allowed_paths or len(set(allowed_paths)) != len(allowed_paths):
        raise ArtifactBuildHold("allowlist_missing_or_duplicate")
    if any(not _safe_path(path) for path in allowed_paths):
        raise ArtifactBuildHold("allowlist_path_invalid")
    if any(not _safe_path(path) or path not in set(allowed_paths) for path in changed_paths):
        raise ArtifactBuildHold("path_outside_allowlist")

    root = Path(worktree_root)
    output = Path(output_root)
    try:
        root = root.resolve(strict=True)
    except OSError:
        raise ArtifactBuildHold("worktree_missing") from None
    if not root.is_dir() or output.exists() or output.is_symlink():
        raise ArtifactBuildHold("output_or_worktree_invalid")

    file_digests: dict[str, str] = {}
    copied: list[tuple[str, bytes]] = []
    for relative in sorted(changed_paths):
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
        "schema": 1,
        "repository_id": repository_id,
        "base_sha": base_sha,
        "changed_paths": sorted(changed_paths),
        "files": {path: file_digests[path] for path in sorted(file_digests)},
    }
    manifest = {
        **material,
        "candidate_digest": hashlib.sha256(_canonical(material)).hexdigest(),
    }
    try:
        output.mkdir(parents=True)
        for relative, content in copied:
            target = output / "files" / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        (output / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8",
        )
        # These are explicit absence markers, not Permit or Witness attestations.
        (output / "permit.json").write_text(
            '{"state":"NOT_ISSUED"}\n', encoding="utf-8",
        )
        (output / "witness.json").write_text(
            '{"state":"NOT_ISSUED"}\n', encoding="utf-8",
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
    parser = argparse.ArgumentParser(description="Package a DRAFT_HOLD runner artifact")
    parser.add_argument("--worktree-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--changed-path", required=True, action="append")
    parser.add_argument("--allowed-path", required=True, action="append")
    args = parser.parse_args(argv)
    try:
        build_artifact(
            worktree_root=args.worktree_root,
            output_root=args.output_root,
            repository_id=args.repository_id,
            base_sha=args.base_sha,
            changed_paths=tuple(args.changed_path),
            allowed_paths=tuple(args.allowed_path),
        )
    except ArtifactBuildHold as exc:
        print(f"HOLD:{exc}", file=sys.stderr)
        return 2
    print("DRAFT_HOLD_ARTIFACT_PACKAGED_UNSIGNED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
