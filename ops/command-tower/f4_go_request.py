"""Create an unsigned, exact-source F4 GO request; never signs or authorizes it."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

from f4_go_gate import F4_SOURCE_PATHS, build_f4_go_candidate

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def create_request(*, workspace: str | Path, base_sha: str, approval_id: str,
                   not_before: str, expires_at: str, revocation_sequence: int,
                   output: str | Path) -> dict[str, object]:
    root = Path(workspace).resolve(strict=True)
    target = Path(output).expanduser().absolute()
    if not _GIT_SHA.fullmatch(base_sha):
        raise ValueError("base SHA must be a full commit SHA")
    if target.exists() or target.is_symlink():
        raise FileExistsError("refusing to overwrite an existing GO request")
    try:
        relative = target.resolve(strict=False).relative_to(root).as_posix()
    except ValueError:
        relative = ""
    if relative in F4_SOURCE_PATHS:
        raise ValueError("GO request cannot overwrite a signed source input")
    candidate = build_f4_go_candidate(
        workspace=root, base_sha=base_sha, approval_id=approval_id,
        not_before=not_before, expires_at=expires_at,
        revocation_sequence=revocation_sequence,
    )
    encoded = (json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--approval-id", required=True)
    parser.add_argument("--not-before", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--revocation-sequence", required=True, type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        candidate = create_request(
            workspace=args.workspace, base_sha=args.base_sha,
            approval_id=args.approval_id, not_before=args.not_before,
            expires_at=args.expires_at, revocation_sequence=args.revocation_sequence,
            output=args.output,
        )
    except (OSError, ValueError) as exc:
        print("HOLD: " + type(exc).__name__ + ": " + str(exc))
        return 78
    print("DRAFT_HOLD_REQUEST_CREATED:" + str(candidate["payload"]["repository_id"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
