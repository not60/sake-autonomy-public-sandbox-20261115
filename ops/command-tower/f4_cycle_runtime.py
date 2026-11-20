"""DRAFT_HOLD adapter joining signed F4, role-scoped CAS and GitHub artifact proof."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
from typing import Mapping

from cas_journal import HttpsCasBackend
from f4_cycle_control import (
    CycleControlHold, F4CycleControlJournal, GitHubArtifactProvenanceReader,
)
from f4_go_gate import F4GoHold, verify_f4_go_candidate
from trusted_key_registry import TrustedVerificationKey, load_trusted_verification_keys

REPOSITORY_ID = 1458303357
CAS_ENDPOINT = "https://bkpofcpaefkocykvtsjv.supabase.co/functions/v1/sake-cas-v1"
_SHA = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ROLE_TOKEN = {
    "initialize": "B09_F4_CONTROL_V2_OWNER_BEARER",
    "claim-cycle1": "B09_F4_CONTROL_V2_WORKER_BEARER",
    "record-cycle1-audit": "B09_F4_CONTROL_V2_AUDITOR_BEARER",
    "claim-cycle2": "B09_F4_CONTROL_V2_WORKER_BEARER",
}


class F4RuntimeHold(RuntimeError):
    pass


def _read_json(path: str | Path) -> object:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 2 * 1024 * 1024:
        raise F4RuntimeHold("input_file_missing_or_unsafe")
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise F4RuntimeHold("input_json_invalid") from None


def _load_auditor_key(document: object, owner_keys: Mapping[str, TrustedVerificationKey]) -> TrustedVerificationKey:
    if not isinstance(document, dict) or set(document) != {"key_id", "role", "public_key"}:
        raise F4RuntimeHold("auditor_trust_key_invalid")
    key_id, role, encoded = document["key_id"], document["role"], document["public_key"]
    if not isinstance(key_id, str) or not key_id or role != "auditor" or not isinstance(encoded, str):
        raise F4RuntimeHold("auditor_trust_key_invalid")
    try:
        public_key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise F4RuntimeHold("auditor_trust_key_encoding_invalid") from None
    key = TrustedVerificationKey(key_id, role, public_key)
    if len(public_key) != 32 or key_id in owner_keys or public_key in {value.public_key for value in owner_keys.values()}:
        raise F4RuntimeHold("auditor_trust_key_not_independent")
    return key


def execution_authorization_check(*, candidate, workspace, expected_base_sha,
                                  trusted_keys, read_signed_revocation):
    """Build the signing-side read-only GO/revocation check from existing contracts.

    The reader is supplied by protected code and must obtain the latest status;
    cached candidate JSON cannot establish revocation freshness.
    """
    from f4_cycle_control import _verify_revocation_status
    from f4_go_gate import verified_f4_go_sha256
    if not callable(read_signed_revocation):
        raise F4RuntimeHold("fresh_signed_revocation_reader_missing")

    def check():
        try:
            status = read_signed_revocation()
            payload = status["payload"]
            simple = {k: payload[k] for k in ("approval_id", "sequence", "status")}
            go = verify_f4_go_candidate(
                candidate=candidate, workspace=workspace,
                expected_repository_id=REPOSITORY_ID, expected_base_sha=expected_base_sha,
                trusted_keys=trusted_keys, revocation_status=simple,
                verify_revocation_status=lambda value: value == simple,
            )
            verified = _verify_revocation_status(
                status, go=go, go_sha256=verified_f4_go_sha256(candidate, go),
                trusted_keys=trusted_keys,
            )
            return verified["status"] == "ACTIVE" and verified["sequence"] >= go.revocation_sequence
        except Exception:
            return False
    return check


def execute(*, operation: str, workspace: str | Path, expected_base_sha: str,
            candidate_path: str | Path, revocation_path: str | Path,
            trusted_keys_path: str | Path, auditor_key_path: str | Path,
            env: Mapping[str, str] | None = None, cycle: int | None = None,
            run_id: str | None = None, source_commit_sha: str | None = None,
            auditor_artifact_path: str | Path | None = None,
            cycle1_auditor_run_id: str | None = None,
            provenance_reader: object = None,
            claim_receipt_path: str | Path | None = None) -> int:
    if operation not in _ROLE_TOKEN:
        raise F4RuntimeHold("operation_invalid")
    if not _GIT_SHA.fullmatch(expected_base_sha):
        raise F4RuntimeHold("expected_base_sha_invalid")
    values = os.environ if env is None else env
    endpoint = values.get("B09_CAS_ENDPOINT", "")
    bearer = values.get(_ROLE_TOKEN[operation], "")
    if endpoint != CAS_ENDPOINT or len(bearer.encode("utf-8")) < 32:
        raise F4RuntimeHold("role_scoped_cas_credential_missing")

    candidate = _read_json(candidate_path)
    revocation = _read_json(revocation_path)
    key_document = _read_json(trusted_keys_path)
    auditor_document = _read_json(auditor_key_path)
    try:
        owner_keys = load_trusted_verification_keys(key_document)
    except (TypeError, ValueError):
        raise F4RuntimeHold("f4_trust_registry_invalid") from None
    auditor_key = _load_auditor_key(auditor_document, owner_keys)
    payload = revocation.get("payload") if isinstance(revocation, dict) else None
    if not isinstance(payload, dict):
        raise F4RuntimeHold("signed_revocation_status_missing")
    simple_status = {key: payload.get(key) for key in ("approval_id", "sequence", "status")}
    try:
        go = verify_f4_go_candidate(
            candidate=candidate, workspace=workspace,
            expected_repository_id=REPOSITORY_ID, expected_base_sha=expected_base_sha,
            trusted_keys=owner_keys, revocation_status=simple_status,
            # The journal then independently verifies this signed envelope before every write.
            verify_revocation_status=lambda value: value == simple_status,
        )
    except (F4GoHold, TypeError, ValueError):
        raise F4RuntimeHold("signed_f4_go_or_source_binding_invalid") from None

    claim_operation = operation in {"claim-cycle1", "claim-cycle2"}
    if claim_operation:
        if (type(cycle) is not int or cycle != int(operation[-1])
                or not isinstance(run_id, str)
                or not re.fullmatch(rf"[1-9][0-9]*-[1-9][0-9]*-cycle-{cycle}", run_id)
                or claim_receipt_path is None):
            raise F4RuntimeHold("claim_receipt_inputs_invalid")
        receipt_target = Path(claim_receipt_path)
        if (not receipt_target.parent.is_dir() or receipt_target.exists()
                or receipt_target.is_symlink()):
            raise F4RuntimeHold("claim_receipt_output_unavailable")

    try:
        backend = HttpsCasBackend(endpoint=endpoint, bearer_token=bearer)
        journal = F4CycleControlJournal(
            backend, trusted_signing_keys=owner_keys, trusted_auditor_key=auditor_key,
        )
        if operation == "initialize":
            state = journal.initialize(candidate=candidate, go=go, revocation_status=revocation)
        elif operation == "claim-cycle1":
            if cycle != 1 or not run_id or not source_commit_sha or not _GIT_SHA.fullmatch(source_commit_sha):
                raise F4RuntimeHold("cycle1_claim_inputs_invalid")
            state = journal.claim_cycle(
                candidate=candidate, go=go, cycle_number=1, run_id=run_id,
                source_commit_sha=source_commit_sha,
            )
        elif operation == "record-cycle1-audit":
            if auditor_artifact_path is None:
                raise F4RuntimeHold("auditor_artifact_missing")
            artifact = _read_json(auditor_artifact_path)
            reader = provenance_reader or _provenance(values, allow_in_progress=True)
            state = journal.record_cycle1_auditor_pass(
                candidate=candidate, go=go, artifact=artifact,
                verify_github_artifact=reader,
            )
        else:
            if cycle != 2 or not run_id or not source_commit_sha or not _GIT_SHA.fullmatch(source_commit_sha):
                raise F4RuntimeHold("cycle2_claim_inputs_invalid")
            if (auditor_artifact_path is None or not isinstance(cycle1_auditor_run_id, str)
                    or not cycle1_auditor_run_id.isdigit()):
                raise F4RuntimeHold("cycle1_auditor_artifact_required")
            artifact = _read_json(auditor_artifact_path)
            payload = artifact.get("payload") if isinstance(artifact, dict) else None
            if not isinstance(payload, dict) or payload.get("workflow_run_id") != cycle1_auditor_run_id:
                raise F4RuntimeHold("cycle1_auditor_run_id_mismatch")
            reader = provenance_reader or _provenance(values, allow_in_progress=False)
            state = journal.claim_cycle(
                candidate=candidate, go=go, cycle_number=2, run_id=run_id,
                source_commit_sha=source_commit_sha,
                cycle1_auditor_artifact=artifact,
                verify_github_artifact=reader,
            )
    except (CycleControlHold, F4RuntimeHold):
        raise
    except Exception:
        # HttpsCasBackend is single-shot; unknown outcomes are surfaced as HOLD, never retried.
        raise F4RuntimeHold("cycle_control_operation_failed_no_retry") from None
    if claim_operation:
        receipt = {
            "repository_id": REPOSITORY_ID, "cycle": cycle, "run_id": run_id,
            "source_commit_sha": source_commit_sha, "go_sha256": state.go_sha256,
            "journal_sequence": state.sequence, "journal_head_sha256": state.head_sha256,
            "journal_version": state.version,
        }
        try:
            fd = os.open(receipt_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(receipt, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise F4RuntimeHold("claim_committed_receipt_save_failed_no_retry") from None
    print(f"F4_CYCLE_CONTROL_OK:{operation}:{state.sequence}")
    return 0


def _provenance(values: Mapping[str, str], *, allow_in_progress: bool):
    token = values.get("GITHUB_TOKEN", "")
    if not token:
        raise F4RuntimeHold("read_only_github_token_missing")
    return GitHubArtifactProvenanceReader(bearer_token=token, allow_in_progress=allow_in_progress)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=tuple(_ROLE_TOKEN), required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--revocation", required=True)
    parser.add_argument("--trusted-keys", required=True)
    parser.add_argument("--auditor-key", required=True)
    parser.add_argument("--cycle", type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--source-commit-sha")
    parser.add_argument("--auditor-artifact")
    parser.add_argument("--cycle1-auditor-run-id")
    parser.add_argument("--claim-receipt")
    args = parser.parse_args()
    receipt = args.claim_receipt
    if receipt is None and args.operation in {"claim-cycle1", "claim-cycle2"}:
        runner_temp = os.environ.get("RUNNER_TEMP")
        if runner_temp and Path(runner_temp).is_absolute():
            receipt = Path(runner_temp) / "f4-worker-claim-receipt.json"
    try:
        return execute(
            operation=args.operation, workspace=args.workspace,
            expected_base_sha=args.expected_base_sha, candidate_path=args.candidate,
            revocation_path=args.revocation, trusted_keys_path=args.trusted_keys,
            auditor_key_path=args.auditor_key, cycle=args.cycle, run_id=args.run_id,
            source_commit_sha=args.source_commit_sha,
            auditor_artifact_path=args.auditor_artifact,
            cycle1_auditor_run_id=args.cycle1_auditor_run_id,
            claim_receipt_path=receipt,
        )
    except (F4RuntimeHold, CycleControlHold) as exc:
        print("HOLD:" + str(exc))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
