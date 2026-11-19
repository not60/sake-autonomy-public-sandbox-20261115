"""Offline, fail-closed verification and Draft-PR planning for DRAFT_HOLD."""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Mapping

from cas_journal import CasHold, HttpsCasBackend, PermitCasJournal
from durable_store import (
    DurableStore,
    PermitAlreadyConsumed,
    PermitIdAlreadyConsumed,
    PermitIdAlreadyIssued,
)
from trusted_key_registry import TrustedVerificationKey, load_trusted_verification_keys
from f4_limited_delegation import verify_publisher_candidate_authorization

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_GATE_SEAL = object()
PUBLIC_REPOSITORY_ID = 1458303357
PUBLIC_REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"
PUBLIC_BASE_BRANCH = "main"
PUBLIC_HEAD_BRANCH = "review/b09-public-runner-draft-20261116"


class PublisherGateHold(RuntimeError):
    """The offline artifact failed a required signature, scope, or CAS check."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class OfflineVerificationResult:
    repository_id: int
    base_sha: str
    candidate_digest: str
    permit_id: str
    permit_digest: str
    changed_paths: tuple[str, ...]
    file_sha256: tuple[tuple[str, str], ...]
    worker_run_id: str
    codex_output_sha256: str
    witness_digest: str
    draft_pr_ready: bool = False
    publication_authorized: bool = False
    _gate_seal: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class DraftPrPlan:
    """Prepared metadata; creating the PR remains a separate authorized step."""

    repository_id: int
    base_sha: str
    base_branch: str
    head_branch: str
    worker_run_id: str
    candidate_digest: str
    changed_paths: tuple[str, ...]
    file_sha256: tuple[tuple[str, str], ...]
    title: str
    body: str
    draft_pr_ready: bool = True
    _gate_seal: object | None = field(default=None, repr=False, compare=False)


def prepare_draft_pr_plan(result: OfflineVerificationResult) -> DraftPrPlan:
    if (result._gate_seal is not _GATE_SEAL or not result.draft_pr_ready
            or result.publication_authorized):
        raise PublisherGateHold("draft_pr_approval_or_verification_missing")
    if result.repository_id != PUBLIC_REPOSITORY_ID:
        raise PublisherGateHold("draft_pr_repository_not_allowlisted")
    return DraftPrPlan(
        repository_id=result.repository_id,
        base_sha=result.base_sha,
        base_branch=PUBLIC_BASE_BRANCH,
        head_branch=PUBLIC_HEAD_BRANCH,
        worker_run_id=result.worker_run_id,
        candidate_digest=result.candidate_digest,
        changed_paths=result.changed_paths,
        file_sha256=result.file_sha256,
        title=f"Draft: public sandbox worker run {result.worker_run_id}",
        body=("DRAFT_HOLD candidate. Offline Permit, Witness, Owner A/B signatures, "
              "scope, and byte digests were checked. This is a plan only; no GitHub write occurred."),
        _gate_seal=_GATE_SEAL,
    )


def is_gate_approved_draft_pr_plan(plan: DraftPrPlan) -> bool:
    return (isinstance(plan, DraftPrPlan) and plan._gate_seal is _GATE_SEAL
            and plan.draft_pr_ready and plan.repository_id == PUBLIC_REPOSITORY_ID
            and plan.changed_paths == tuple(sorted(set(plan.changed_paths)))
            and {path for path, _ in plan.file_sha256} == set(plan.changed_paths))


class PublisherGate:
    """Verify Worker output, separate role signatures, CAS continuity, and local consumption."""

    @staticmethod
    def verify_limited_delegation(*, delegation_envelope, trusted_owner_keys,
                                  expected_execution_revision, expected_cycle_tasks,
                                  revocation_status, verify_revocation_status,
                                  authorization, evidence, verify_candidate_evidence,
                                  now=None) -> str:
        """Publisher-side entry point for a fully scoped delegated authorization.

        The existing direct Owner A/B approval path remains unchanged. A caller
        using delegation must provide a fresh Publisher-owned Permit/Witness/CAS
        and Worker provenance verifier; the delegation envelope alone is not
        evidence that those checks passed.
        """
        return verify_publisher_candidate_authorization(
            delegation_envelope=delegation_envelope,
            trusted_owner_keys=trusted_owner_keys,
            expected_execution_revision=expected_execution_revision,
            expected_cycle_tasks=expected_cycle_tasks, revocation_status=revocation_status,
            verify_revocation_status=verify_revocation_status,
            authorization=authorization, evidence=evidence,
            verify_candidate_evidence=verify_candidate_evidence, now=now,
        )

    def __init__(self, *, repository_id: int, base_sha: str,
                 allowed_paths: tuple[str, ...],
                 trusted_keys: Mapping[str, TrustedVerificationKey],
                 durable_store: DurableStore,
                 cas_journal: PermitCasJournal | None) -> None:
        if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id <= 0:
            raise ValueError("repository ID must be a positive integer")
        if not isinstance(base_sha, str) or not _GIT_SHA.fullmatch(base_sha):
            raise ValueError("base SHA must be a full Git commit SHA")
        if not allowed_paths or len(set(allowed_paths)) != len(allowed_paths):
            raise ValueError("path allowlist must be nonempty and unique")
        if any(not _safe_path(path) for path in allowed_paths):
            raise ValueError("path allowlist contains an unsafe path")
        self._repository_id = repository_id
        self._base_sha = base_sha
        self._allowed_paths = frozenset(allowed_paths)
        self._trusted_keys = dict(trusted_keys)
        self._store = durable_store
        self._cas_journal = cas_journal

    def verify_bundle(self, *, artifact_root: str | Path,
                      manifest: object, permit: object, witness: object,
                      codex_output_file: str | Path,
                      owner_approvals: object) -> OfflineVerificationResult:
        return self._run_validation(artifact_root, manifest, permit, witness,
                                   codex_output_file, owner_approvals, consume=True)

    def audit_bundle(self, *, artifact_root: str | Path,
                     manifest: object, permit: object, witness: object,
                     codex_output_file: str | Path,
                     owner_approvals: object) -> OfflineVerificationResult:
        """Read-only CAS audit: verifies the prior consume event without writing."""
        return self._run_validation(artifact_root, manifest, permit, witness,
                                   codex_output_file, owner_approvals, consume=False)

    def _run_validation(self, artifact_root: str | Path, manifest: object,
                        permit: object, witness: object, codex_output_file: str | Path,
                        owner_approvals: object, *, consume: bool) -> OfflineVerificationResult:
        try:
            return self._verify_bundle(artifact_root, manifest, permit, witness,
                                       codex_output_file, owner_approvals, consume=consume)
        except PublisherGateHold as exc:
            self._stop(exc.reason)
            raise
        except CasHold:
            self._stop("external_cas_unavailable_or_invalid")
            raise PublisherGateHold("external_cas_unavailable_or_invalid") from None
        except Exception:
            self._stop("unexpected_validation_failure")
            raise PublisherGateHold("unexpected_validation_failure") from None

    def _verify_bundle(self, artifact_root: str | Path, manifest: object,
                       permit: object, witness: object, codex_output_file: str | Path,
                       owner_approvals: object, *, consume: bool) -> OfflineVerificationResult:
        if self._store.state != "DRAFT_HOLD":
            raise PublisherGateHold("durable_runtime_not_active")
        if self._cas_journal is None:
            raise PublisherGateHold("external_cas_not_configured")
        required_manifest = {
            "schema", "repository_id", "base_sha", "worker_run_id",
            "codex_output_sha256", "candidate_digest", "changed_paths", "files",
        }
        if not isinstance(manifest, dict) or set(manifest) != required_manifest:
            raise PublisherGateHold("manifest_missing_or_invalid")
        if manifest["schema"] != 2:
            raise PublisherGateHold("manifest_schema_mismatch")
        repo_id = manifest["repository_id"]
        if isinstance(repo_id, bool) or repo_id != self._repository_id:
            raise PublisherGateHold("repository_id_mismatch")
        base_sha = manifest["base_sha"]
        if base_sha != self._base_sha:
            raise PublisherGateHold("base_sha_mismatch")
        worker_run_id = manifest["worker_run_id"]
        output_digest = manifest["codex_output_sha256"]
        if not isinstance(worker_run_id, str) or not worker_run_id:
            raise PublisherGateHold("worker_run_id_missing")
        if not isinstance(output_digest, str) or not _SHA256.fullmatch(output_digest):
            raise PublisherGateHold("codex_output_digest_invalid")

        changed_paths, files = manifest["changed_paths"], manifest["files"]
        if (not isinstance(changed_paths, list) or not changed_paths
                or any(not isinstance(path, str) for path in changed_paths)
                or len(set(changed_paths)) != len(changed_paths)
                or not isinstance(files, dict) or set(files) != set(changed_paths)):
            raise PublisherGateHold("manifest_paths_invalid")
        ordered_paths = tuple(sorted(changed_paths))
        if any(path not in self._allowed_paths or not _safe_path(path) for path in ordered_paths):
            raise PublisherGateHold("path_outside_allowlist")
        if any(not isinstance(digest, str) or not _SHA256.fullmatch(digest)
               for digest in files.values()):
            raise PublisherGateHold("manifest_file_digest_invalid")

        material = {
            "schema": 2, "repository_id": repo_id, "base_sha": base_sha,
            "worker_run_id": worker_run_id, "codex_output_sha256": output_digest,
            "changed_paths": list(ordered_paths),
            "files": {path: files[path] for path in ordered_paths},
        }
        candidate_digest = _sha256(_canonical(material))
        if manifest["candidate_digest"] != candidate_digest:
            raise PublisherGateHold("candidate_digest_mismatch")
        self._verify_artifact_files(artifact_root, files)
        self._verify_codex_output(codex_output_file, output_digest)

        if not _is_envelope(permit) or not _is_envelope(witness):
            raise PublisherGateHold("signed_permit_and_witness_required")
        permit_payload, witness_payload = permit["payload"], witness["payload"]
        if not isinstance(permit_payload, dict) or not isinstance(witness_payload, dict):
            raise PublisherGateHold("signed_payload_invalid")
        expected_permit_keys = {
            "schema", "permit_id", "issuer_id", "repository_id", "base_sha",
            "candidate_digest", "changed_paths", "issuer_role", "worker_run_id",
        }
        expected_witness_keys = {
            "schema", "witness_id", "permit_digest", "repository_id", "base_sha",
            "candidate_digest", "changed_paths", "issuer_role", "worker_run_id",
            "journal_parent_sha256",
        }
        if set(permit_payload) != expected_permit_keys or set(witness_payload) != expected_witness_keys:
            raise PublisherGateHold("signed_payload_fields_invalid")
        permit_id = permit_payload["permit_id"]
        if not isinstance(permit_id, str) or not permit_id:
            raise PublisherGateHold("permit_id_missing")
        if (permit_payload["schema"] != 2
                or permit_payload["repository_id"] != repo_id
                or permit_payload["base_sha"] != base_sha
                or permit_payload["candidate_digest"] != candidate_digest
                or permit_payload["changed_paths"] != list(ordered_paths)
                or permit_payload["issuer_id"] != permit["key_id"]
                or permit_payload["issuer_role"] != "permit_authority"
                or permit_payload["worker_run_id"] != worker_run_id):
            raise PublisherGateHold("permit_scope_mismatch")

        permit_digest = _sha256(_canonical(permit_payload))
        if (witness_payload["schema"] != 2
                or not isinstance(witness_payload["witness_id"], str)
                or not witness_payload["witness_id"]
                or witness_payload["permit_digest"] != permit_digest
                or witness_payload["repository_id"] != repo_id
                or witness_payload["base_sha"] != base_sha
                or witness_payload["candidate_digest"] != candidate_digest
                or witness_payload["changed_paths"] != list(ordered_paths)
                or witness_payload["witness_id"] != witness["key_id"]
                or witness_payload["issuer_role"] != "witness"
                or witness_payload["worker_run_id"] != worker_run_id):
            raise PublisherGateHold("witness_scope_mismatch")
        if permit["key_id"] == witness["key_id"]:
            raise PublisherGateHold("permit_and_witness_signers_not_independent")
        permit_key = self._verify_signature(permit, "permit_authority")
        witness_key = self._verify_signature(witness, "witness")
        if permit_key.public_key == witness_key.public_key:
            raise PublisherGateHold("permit_and_witness_keys_not_independent")

        witness_digest = _sha256(_canonical(witness))
        snapshot = self._cas_journal.snapshot()
        journal_parent = witness_payload["journal_parent_sha256"]
        owner_keys = self._verify_owner_approvals(
            owner_approvals, repo_id=repo_id, base_sha=base_sha,
            candidate_digest=candidate_digest, changed_paths=ordered_paths,
            permit_digest=permit_digest, witness_digest=witness_digest,
            worker_run_id=worker_run_id,
        )
        if len({permit_key.public_key, witness_key.public_key, *owner_keys}) != 4:
            raise PublisherGateHold("signing_roles_must_use_independent_keys")

        if not isinstance(journal_parent, str) or not _SHA256.fullmatch(journal_parent):
            raise PublisherGateHold("witness_journal_parent_invalid")
        if consume:
            if journal_parent != snapshot.head_sha256:
                raise PublisherGateHold("witness_journal_parent_mismatch")
            try:
                self._cas_journal.record_consumption(
                    permit_id=permit_id, candidate_digest=candidate_digest,
                    permit_digest=permit_digest, witness_digest=witness_digest,
                    worker_run_id=worker_run_id, expected_parent=journal_parent,
                )
                plan_digest = _sha256(_canonical({
                    "candidate_digest": candidate_digest, "permit_digest": permit_digest,
                    "witness_digest": witness_digest, "purpose": "draft_pr_plan_only",
                }))
                self._store.consume_permit_and_record(
                    permit_digest, permit_id=permit_id, candidate_digest=candidate_digest,
                    plan_digest=plan_digest, purpose="draft_pr_plan_only", state="DRAFT_HOLD",
                    repository_id=str(repo_id), base_sha=base_sha,
                    changed_paths=json.dumps(list(ordered_paths), separators=(",", ":")),
                )
            except (CasHold, PermitAlreadyConsumed, PermitIdAlreadyConsumed, PermitIdAlreadyIssued):
                raise PublisherGateHold("external_or_local_permit_replay_conflict") from None
            except Exception:
                raise PublisherGateHold("durability_failure") from None
        else:
            self._verify_consumed_cas_event(
                snapshot.events, permit_id=permit_id, candidate_digest=candidate_digest,
                permit_digest=permit_digest, witness_digest=witness_digest,
                worker_run_id=worker_run_id, journal_parent=journal_parent,
            )

        return OfflineVerificationResult(
            repository_id=repo_id, base_sha=base_sha, candidate_digest=candidate_digest,
            permit_id=permit_id, permit_digest=permit_digest, changed_paths=ordered_paths,
            file_sha256=tuple((path, files[path]) for path in ordered_paths),
            worker_run_id=worker_run_id, codex_output_sha256=output_digest,
            witness_digest=witness_digest, draft_pr_ready=consume,
            publication_authorized=False, _gate_seal=_GATE_SEAL if consume else None,
        )

    @staticmethod
    def _verify_consumed_cas_event(events: tuple[dict[str, object], ...], *,
                                   permit_id: str, candidate_digest: str,
                                   permit_digest: str, witness_digest: str,
                                   worker_run_id: str, journal_parent: str) -> None:
        matches = [event for event in events
                   if isinstance(event.get("payload"), dict)
                   and event["payload"].get("event") == "PERMIT_CONSUMED"
                   and event["payload"].get("permit_id") == permit_id]
        if len(matches) != 1:
            raise PublisherGateHold("auditor_cas_consumption_missing_or_duplicated")
        issued = [event for event in events
                  if isinstance(event.get("payload"), dict)
                  and event["payload"].get("event") == "PERMIT_ISSUED"
                  and event["payload"].get("permit_id") == permit_id]
        if len(issued) != 1:
            raise PublisherGateHold("auditor_cas_issuance_missing_or_duplicated")
        issued_payload = issued[0]["payload"]
        if (issued_payload.get("candidate_digest") != candidate_digest
                or issued_payload.get("permit_digest") != permit_digest
                or issued_payload.get("worker_run_id") != worker_run_id):
            raise PublisherGateHold("auditor_cas_issuance_scope_mismatch")
        event = matches[0]
        payload = event["payload"]
        if (event.get("previous_sha256") != journal_parent
                or payload.get("candidate_digest") != candidate_digest
                or payload.get("permit_digest") != permit_digest
                or payload.get("witness_digest") != witness_digest
                or payload.get("worker_run_id") != worker_run_id):
            raise PublisherGateHold("auditor_cas_consumption_scope_mismatch")

    def _verify_owner_approvals(self, approvals: object, *, repo_id: int, base_sha: str,
                                candidate_digest: str, changed_paths: tuple[str, ...],
                                permit_digest: str, witness_digest: str,
                                worker_run_id: str) -> tuple[bytes, bytes]:
        if not isinstance(approvals, dict) or set(approvals) != {"owner_a", "owner_b"}:
            raise PublisherGateHold("both_owner_draft_approvals_required")
        expected = {
            "schema": 1, "decision": "DRAFT_PR_ONLY", "repository_id": repo_id,
            "base_sha": base_sha, "candidate_digest": candidate_digest,
            "changed_paths": list(changed_paths), "permit_digest": permit_digest,
            "witness_digest": witness_digest, "worker_run_id": worker_run_id,
        }
        keys = []
        for role in ("owner_a", "owner_b"):
            envelope = approvals[role]
            if not _is_envelope(envelope) or envelope["payload"] != expected:
                raise PublisherGateHold("owner_approval_scope_mismatch")
            keys.append(self._verify_signature(envelope, role).public_key)
        if keys[0] == keys[1]:
            raise PublisherGateHold("owner_approvals_not_independent")
        return keys[0], keys[1]

    def _verify_artifact_files(self, artifact_root: str | Path,
                               expected_files: Mapping[str, str]) -> None:
        root = Path(artifact_root)
        try:
            root = root.resolve(strict=True)
        except OSError:
            raise PublisherGateHold("artifact_root_missing") from None
        if not root.is_dir():
            raise PublisherGateHold("artifact_root_invalid")
        observed: set[str] = set()
        try:
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise PublisherGateHold("artifact_symlink_rejected")
                if path.is_file():
                    relative = path.relative_to(root).as_posix()
                    if relative not in expected_files:
                        raise PublisherGateHold("unmanifested_artifact_file")
                    observed.add(relative)
                elif not path.is_dir():
                    raise PublisherGateHold("unsupported_artifact_entry")
        except OSError:
            raise PublisherGateHold("artifact_read_failed") from None
        if observed != set(expected_files):
            raise PublisherGateHold("artifact_file_missing")
        for relative, expected_digest in expected_files.items():
            target = root.joinpath(*relative.split("/"))
            try:
                target.resolve(strict=True).relative_to(root)
                actual_digest = hashlib.sha256(target.read_bytes()).hexdigest()
            except (OSError, ValueError):
                raise PublisherGateHold("artifact_read_failed") from None
            if actual_digest != expected_digest:
                raise PublisherGateHold("artifact_digest_mismatch")

    def _verify_codex_output(self, path: str | Path, expected_digest: str) -> None:
        output = Path(path)
        try:
            if output.is_symlink() or not output.is_file():
                raise PublisherGateHold("codex_output_missing_or_symlink")
            actual = _sha256(output.read_bytes())
        except OSError:
            raise PublisherGateHold("codex_output_unreadable") from None
        if actual != expected_digest:
            raise PublisherGateHold("codex_output_digest_mismatch")

    def _verify_signature(self, envelope: dict[str, object], role: str) -> TrustedVerificationKey:
        key_id, signature_text = envelope["key_id"], envelope["signature"]
        if not isinstance(key_id, str) or not key_id or not isinstance(signature_text, str) or not signature_text:
            raise PublisherGateHold("signature_missing")
        key = self._trusted_keys.get(key_id)
        if key is None or key.key_id != key_id or key.role != role or len(key.public_key) != 32:
            raise PublisherGateHold("trusted_signing_key_missing_or_wrong_role")
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (binascii.Error, ValueError):
            raise PublisherGateHold("signature_encoding_invalid") from None
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise PublisherGateHold("ed25519_verifier_unavailable") from None
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                signature, _canonical(envelope["payload"]),
            )
        except (InvalidSignature, ValueError, TypeError):
            raise PublisherGateHold("signature_invalid") from None
        return key

    def _stop(self, reason: str) -> None:
        try:
            self._store.safe_stop(reason)
        except Exception:
            pass


def _safe_path(path: str) -> bool:
    return (isinstance(path, str) and path.startswith("ops/command-tower/")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _is_envelope(value: object) -> bool:
    return (isinstance(value, dict) and set(value) == {"key_id", "signature", "payload"}
            and bool(value.get("key_id")) and bool(value.get("signature")))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_f4_audit_evidence(path: str | Path, evidence: Mapping[str, object]) -> None:
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise PublisherGateHold("f4_audit_evidence_output_exists")
    encoded = (json.dumps(dict(evidence), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    """Verify a bundle and prepare a local PR plan; never calls GitHub."""
    parser = argparse.ArgumentParser(description="Verify a DRAFT_HOLD Publisher artifact")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--permit", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--codex-output", required=True)
    parser.add_argument("--owner-approvals", required=True)
    parser.add_argument("--trusted-keys", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--allowed-path", required=True, action="append")
    parser.add_argument("--cas-endpoint", default="")
    parser.add_argument("--role", choices=("publisher", "auditor"), default="publisher")
    parser.add_argument("--draft-pr-write", action="store_true",
                        help="request one scoped Draft PR after every existing Publisher gate passes")
    parser.add_argument("--expected-head-sha", default="",
                        help="optional pinned review HEAD; otherwise read once before the atomic write")
    parser.add_argument("--audit-pr-ci", action="store_true",
                        help="read one existing pull_request run for the exact Draft PR head")
    parser.add_argument("--pull-request-number", type=int, default=0)
    parser.add_argument("--expected-pr-head-sha", default="",
                        help="required pinned PR head for read-only CI evidence")
    parser.add_argument("--expected-pr-base-sha", default="",
                        help="required pinned PR base for read-only CI evidence")
    parser.add_argument("--f4-audit-evidence-output", default="",
                        help="write read-only structured evidence after the exact PR/CI audit passes")
    args = parser.parse_args(argv)
    from draft_pr_writer import DraftPrWriter, GitHubDraftPrApi, WriterHold

    store: DurableStore | None = None
    try:
        if args.draft_pr_write and args.role != "publisher":
            raise PublisherGateHold("auditor_cannot_request_github_write")
        if args.audit_pr_ci and (args.role != "auditor" or args.pull_request_number != 1):
            raise PublisherGateHold("readonly_ci_audit_scope_invalid")
        if args.audit_pr_ci and not _GIT_SHA.fullmatch(args.expected_pr_head_sha):
            raise PublisherGateHold("readonly_ci_expected_head_invalid")
        if args.audit_pr_ci and not _GIT_SHA.fullmatch(args.expected_pr_base_sha):
            raise PublisherGateHold("readonly_ci_expected_base_invalid")
        if not args.audit_pr_ci and args.expected_pr_head_sha:
            raise PublisherGateHold("expected_pr_head_without_ci_audit")
        if not args.audit_pr_ci and args.expected_pr_base_sha:
            raise PublisherGateHold("expected_pr_base_without_ci_audit")
        if not args.audit_pr_ci and args.pull_request_number:
            raise PublisherGateHold("pull_request_number_without_ci_audit")
        if args.expected_head_sha and not _GIT_SHA.fullmatch(args.expected_head_sha):
            raise PublisherGateHold("draft_pr_expected_head_invalid")
        if not args.draft_pr_write and args.expected_head_sha:
            raise PublisherGateHold("expected_head_without_write_request")
        if args.f4_audit_evidence_output and not (args.role == "auditor" and args.audit_pr_ci):
            raise PublisherGateHold("f4_audit_evidence_requires_auditor_ci_pass")
        token_name = (
            "B09_CAS_V2_PUBLISHER_BEARER"
            if args.role == "publisher"
            else "B09_CAS_V2_AUDITOR_BEARER"
        )
        token = os.environ.get(token_name, "")
        if not args.cas_endpoint or not token:
            raise PublisherGateHold("external_cas_credentials_not_configured")
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        permit = json.loads(Path(args.permit).read_text(encoding="utf-8"))
        witness = json.loads(Path(args.witness).read_text(encoding="utf-8"))
        approvals = json.loads(Path(args.owner_approvals).read_text(encoding="utf-8"))
        key_document = json.loads(Path(args.trusted_keys).read_text(encoding="utf-8"))
        keys = load_trusted_verification_keys(key_document)
        store = DurableStore(args.database)
        journal = PermitCasJournal(
            HttpsCasBackend(endpoint=args.cas_endpoint, bearer_token=token),
            repository_id=args.repository_id,
        )
        gate = PublisherGate(
            repository_id=args.repository_id, base_sha=args.base_sha,
            allowed_paths=tuple(args.allowed_path), trusted_keys=keys, durable_store=store,
            cas_journal=journal,
        )
        verify = gate.verify_bundle if args.role == "publisher" else gate.audit_bundle
        result = verify(
            artifact_root=args.artifact_root, manifest=manifest, permit=permit,
            witness=witness, codex_output_file=args.codex_output,
            owner_approvals=approvals,
        )
        draft_result = None
        ci_result = None
        if args.role == "publisher":
            plan = prepare_draft_pr_plan(result)
            if args.draft_pr_write:
                github_token = os.environ.get("B09_PUBLISHER_GITHUB_TOKEN", "")
                if not github_token:
                    raise WriterHold("publisher_github_credential_missing")
                api = GitHubDraftPrApi(github_token)
                expected_head = args.expected_head_sha or api.get_branch(
                    PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH,
                ).sha
                draft_result = DraftPrWriter(api).commit_verified_artifact_and_create_draft(
                    plan, artifact_root=args.artifact_root,
                    expected_head_sha=expected_head,
                )
        elif args.role == "auditor" and args.audit_pr_ci:
            if args.expected_pr_base_sha != result.base_sha:
                raise PublisherGateHold("readonly_ci_pr_base_not_bound_to_artifact")
            github_token = os.environ.get("GITHUB_TOKEN", "")
            if not github_token:
                raise WriterHold("auditor_github_token_missing")
            github_api = GitHubDraftPrApi(github_token)
            ci_result = github_api.wait_for_readonly_ci_run(
                args.pull_request_number, args.expected_pr_head_sha, args.expected_pr_base_sha,
            )
            if ci_result.status != "completed" or ci_result.conclusion != "success":
                raise WriterHold("readonly_ci_not_success")
            if args.f4_audit_evidence_output:
                pr = github_api.get_open_draft_pull_request(
                    PUBLIC_REPOSITORY_ID, PUBLIC_HEAD_BRANCH, PUBLIC_BASE_BRANCH,
                )
                snapshot = journal.snapshot()
                if (pr.number != args.pull_request_number
                        or pr.head_sha != args.expected_pr_head_sha
                        or pr.base_sha != args.expected_pr_base_sha
                        or pr.draft is not True):
                    raise WriterHold("f4_audit_pr_readback_mismatch")
                _write_f4_audit_evidence(args.f4_audit_evidence_output, {
                    "schema": 1, "repository_id": result.repository_id,
                    "base_sha": result.base_sha, "worker_run_id": result.worker_run_id,
                    "candidate_digest": result.candidate_digest, "permit_id": result.permit_id,
                    "witness_digest": result.witness_digest,
                    "journal_revision": snapshot.sequence,
                    "journal_head_sha256": snapshot.head_sha256,
                    "pr_number": pr.number, "pr_state": "open",
                    "pr_is_draft": True, "pr_merged": False,
                    "pr_head_sha": pr.head_sha, "pr_base_sha": pr.base_sha,
                    "readonly_ci_run_id": str(ci_result.run_id),
                    "readonly_ci_conclusion": ci_result.conclusion,
                })
    except WriterHold as exc:
        print(f"HOLD:{exc.reason}", file=sys.stderr)
        return 2
    except PublisherGateHold as exc:
        print(f"HOLD:{exc.reason}", file=sys.stderr)
        return 2
    except CasHold:
        print("HOLD:external_cas_unavailable_or_conflict", file=sys.stderr)
        return 2
    except Exception:
        print("HOLD:input_or_configuration_invalid", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
    if args.role == "auditor":
        if ci_result is None:
            print("AUDIT_VERIFIED_READ_ONLY")
        else:
            print(f"AUDIT_AND_READONLY_CI_PASS:{ci_result.run_id}:{ci_result.url}")
    elif draft_result is None:
        print("DRAFT_PR_PLAN_READY_NO_GITHUB_WRITE")
    else:
        print(f"DRAFT_PR_CREATED:{draft_result.number}:{draft_result.head_sha}:{draft_result.base_sha}:{draft_result.url}")
    return 0


if __name__ == "__main__":
    # Keep the gate seal and DraftPrPlan class identity shared with the
    # lazily imported writer when this file is executed as a script.
    sys.modules.setdefault("publisher_gate", sys.modules[__name__])
    raise SystemExit(main())
