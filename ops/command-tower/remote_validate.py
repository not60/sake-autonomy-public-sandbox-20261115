#!/usr/bin/env python3
"""Nonproduction, read-only fixture validator for the isolated SAKE sandbox.

This module performs NO GitHub, network, filesystem or Worker operations.
It is a bootstrap test fixture, NOT an execution permit or Publisher guard.
Duplicate paths and unsafe feature branch names are rejected; this does not
authorize any execution GO.
"""
from __future__ import annotations

import re

SANDBOX_REPO = "not60/sake-autonomy-public-sandbox-20261115"
PATH_PREFIX = "ops/command-tower/"


class ValidationError(ValueError):
    """A candidate does not meet the baseline DRAFT/HOLD fixture contract."""


def validate_draft(candidate: object) -> tuple[str, tuple[str, ...]]:
    """Validate a sandbox-only, non-executable test fixture.

    The intentionally narrow baseline does not authorize GitHub writes or
    determine whether a Publisher/Worker may operate. Do not use it as a
    runtime security boundary.
    """
    if not isinstance(candidate, dict):
        raise ValidationError("candidate must be a JSON object")
    if candidate.get("schema") != 1:
        raise ValidationError("unsupported schema")
    if candidate.get("state") != "DRAFT_HOLD":
        raise ValidationError("must remain DRAFT_HOLD")
    if candidate.get("repository") != SANDBOX_REPO:
        raise ValidationError("repository must be the isolated sandbox")
    if candidate.get("write_enabled") is not False:
        raise ValidationError("write_enabled must be false")

    branch = candidate.get("feature_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,100}", branch):
        raise ValidationError("malformed feature branch")
    if (
        not branch.startswith("feature/")
        or ".." in branch
        or any(
            not component
            or component.startswith(".")
            or component.endswith((".", ".lock"))
            for component in branch.split("/")
        )
    ):
        raise ValidationError("unsafe feature branch")

    raw_paths = candidate.get("allowed_changed_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ValidationError("expected a nonempty path list")
    paths = []
    seen_paths = set()
    for path in raw_paths:
        if not isinstance(path, str) or not path.startswith(PATH_PREFIX):
            raise ValidationError("path must be inside the command-tower fixture")
        components = path.split("/")
        if (
            "\\" in path
            or "\x00" in path
            or any(component in {"", ".", ".."} for component in components)
            or path.endswith("/")
        ):
            raise ValidationError("unsafe path")
        if path in seen_paths:
            raise ValidationError("duplicate allowed path")
        seen_paths.add(path)
        paths.append(path)
    return branch, tuple(paths)
