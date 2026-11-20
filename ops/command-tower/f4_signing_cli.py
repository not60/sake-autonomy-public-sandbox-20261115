"""Role-scoped CLI core for existing F4 signing contracts.

This module never loads or creates private keys. A trusted role launcher must
inject exactly one signer and its verification context. The default command
line entrypoint has no launcher configured and therefore fails closed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import json
import re
import sys
from typing import Callable, Mapping, Protocol, TextIO

from attestations import canonical_json, issue_permit, issue_witness
from cas_journal import PermitCasJournal
from f4_go_gate import F4GoHold, _verify_ed25519
from f4_limited_delegation import (
    VerifiedDelegation,
    issue_candidate_authorization_for_role,
    verify_delegation_contract,
)
from trusted_key_registry import TrustedVerificationKey

REPOSITORY_ID = 1458303357
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_PERMIT_ROLES = frozenset({"permit_authority", "witness"})
_DELEGATE_ROLES = frozenset({"owner_a_delegate", "owner_b_delegate"})
_ROLES = _PERMIT_ROLES | _DELEGATE_ROLES
_PERMIT_PAYLOAD_KEYS = {
    "schema", "permit_id", "issuer_id", "repository_id", "base_sha",
    "candidate_digest", "changed_paths", "issuer_role", "worker_run_id",
}


class SigningCliHold(RuntimeError):
    """Stable, non-sensitive fail-closed signing error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True)
class SigningContext:
    """One role's in-memory signer plus only that role's required validators."""

    role: str
    signer: Signer | None
    trusted_keys: Mapping[str, TrustedVerificationKey] | None = None
    journal: PermitCasJournal | None = None
    verify_candidate_scope: Callable[[Mapping[str, object]], bool] | None = None
    trusted_owner_keys: Mapping[str, TrustedVerificationKey] | None = None
    expected_execution_revision: str = ""
    expected_cycle_tasks: tuple[str, str] = ()
    revocation_status: object = None
    verify_revocation_status: Callable[[object, Mapping[str, object]], bool] | None = None
    verify_candidate_evidence: Callable[[object, VerifiedDelegation], bool] | None = None
    now: datetime | None = None


def issue_from_cli_request(role: str, request: object, *,
                           context: SigningContext | None) -> dict[str, object]:
    """Dispatch one role-scoped request through the existing signing APIs."""
    if role not in _ROLES or context is None or context.role != role:
        raise SigningCliHold("signer_role_context_mismatch")
    if context.signer is None or not callable(getattr(context.signer, "sign", None)):
        raise SigningCliHold("role_signer_unavailable")
    if not isinstance(request, Mapping):
        raise SigningCliHold("request_invalid")

    if role == "permit_authority":
        return _issue_permit(request, context)
    if role == "witness":
        return _issue_witness(request, context)
    return _issue_delegate_fragment(role, request, context)


def _issue_permit(request: Mapping[str, object], context: SigningContext) -> dict[str, object]:
    required = {"permit_id", "issuer_id", "repository_id", "base_sha",
                "candidate_digest", "changed_paths", "worker_run_id"}
    if set(request) != required:
        raise SigningCliHold("permit_request_fields_invalid")
    _require_journal_and_scope(context)
    key = _trusted_role_key(context.trusted_keys, request.get("issuer_id"), "permit_authority")
    paths = _validate_permit_scope(request)
    _call_scope_verifier(context.verify_candidate_scope, request)
    try:
        permit = issue_permit(
            permit_id=request["permit_id"], issuer_id=key.key_id,
            private_key=context.signer, repository_id=REPOSITORY_ID,
            base_sha=request["base_sha"], candidate_digest=request["candidate_digest"],
            changed_paths=paths, worker_run_id=request["worker_run_id"],
            journal=context.journal,
        )
    except Exception:
        raise SigningCliHold("permit_issue_failed") from None
    _verify_role_envelope(permit, key, "permit_authority")
    return permit


def _issue_witness(request: Mapping[str, object], context: SigningContext) -> dict[str, object]:
    if set(request) != {"witness_id", "permit"}:
        raise SigningCliHold("witness_request_fields_invalid")
    _require_journal_and_scope(context)
    key = _trusted_role_key(context.trusted_keys, request.get("witness_id"), "witness")
    permit = request.get("permit")
    _validate_permit_envelope(permit, context.trusted_keys)
    payload = permit["payload"]
    scope_request = {
        "permit_id": payload["permit_id"], "issuer_id": payload["issuer_id"],
        "repository_id": payload["repository_id"], "base_sha": payload["base_sha"],
        "candidate_digest": payload["candidate_digest"],
        "changed_paths": payload["changed_paths"],
        "worker_run_id": payload["worker_run_id"], "permit": permit,
    }
    _call_scope_verifier(context.verify_candidate_scope, scope_request)
    try:
        witness = issue_witness(
            witness_id=key.key_id, private_key=context.signer,
            permit=dict(permit), journal=context.journal,
        )
    except Exception:
        raise SigningCliHold("witness_issue_failed") from None
    _verify_role_envelope(witness, key, "witness")
    if permit["key_id"] == witness["key_id"]:
        raise SigningCliHold("permit_witness_signers_not_independent")
    permit_key = context.trusted_keys.get(permit["key_id"])
    if permit_key is None or permit_key.public_key == key.public_key:
        raise SigningCliHold("permit_witness_keys_not_independent")
    return witness


def _issue_delegate_fragment(role: str, request: Mapping[str, object],
                             context: SigningContext) -> dict[str, object]:
    required = {"delegation_envelope", "revocation_status", "evidence"}
    if set(request) != required:
        raise SigningCliHold("delegate_request_fields_invalid")
    if (context.trusted_owner_keys is None
            or not _GIT_SHA.fullmatch(context.expected_execution_revision)
            or not isinstance(context.expected_cycle_tasks, tuple)
            or len(context.expected_cycle_tasks) != 2):
        raise SigningCliHold("delegate_verification_context_missing")
    try:
        delegation = verify_delegation_contract(
            envelope=request["delegation_envelope"],
            trusted_owner_keys=context.trusted_owner_keys,
            expected_execution_revision=context.expected_execution_revision,
            expected_cycle_tasks=context.expected_cycle_tasks,
            revocation_status=request["revocation_status"],
            verify_revocation_status=context.verify_revocation_status,
            now=context.now,
        )
        fragment = issue_candidate_authorization_for_role(
            delegation=delegation, role=role, evidence=request["evidence"],
            verify_candidate_evidence=context.verify_candidate_evidence,
            signer=context.signer, now=context.now,
        )
    except Exception:
        raise SigningCliHold("delegate_fragment_issue_failed") from None
    return fragment


def main(argv: list[str] | None = None, *,
         context: SigningContext | None = None,
         stdin: TextIO | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """JSON-in/stdout CLI; no key is read from argv, a file, or environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=sorted(_ROLES))
    args = parser.parse_args(argv)
    source, output, errors = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    if context is None:
        print("HOLD:trusted_role_signer_provider_not_configured", file=errors)
        return 78
    try:
        raw = source.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise SigningCliHold("request_too_large")
        request = json.loads(raw, object_pairs_hook=_unique_object)
        result = issue_from_cli_request(args.role, request, context=context)
        output.write(json.dumps(result, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False) + "\n")
        return 0
    except SigningCliHold as exc:
        print("HOLD:" + exc.code, file=errors)
        return 78
    except Exception:
        print("HOLD:signing_request_invalid_or_unavailable", file=errors)
        return 78


def _trusted_role_key(keys: Mapping[str, TrustedVerificationKey] | None,
                      key_id: object, expected_role: str) -> TrustedVerificationKey:
    if not isinstance(keys, Mapping) or not isinstance(key_id, str):
        raise SigningCliHold("trusted_role_key_missing")
    key = keys.get(key_id)
    if key is None or key.key_id != key_id or key.role != expected_role:
        raise SigningCliHold("trusted_role_key_mismatch")
    return key


def _verify_role_envelope(envelope: object, key: TrustedVerificationKey,
                          expected_role: str) -> None:
    if (not isinstance(envelope, Mapping)
            or set(envelope) != {"key_id", "signature", "payload"}
            or envelope.get("key_id") != key.key_id
            or not isinstance(envelope.get("payload"), dict)
            or not isinstance(envelope.get("signature"), str)):
        raise SigningCliHold("signed_envelope_invalid")
    payload = envelope["payload"]
    expected_issuer_role = "permit_authority" if expected_role == "permit_authority" else "witness"
    if payload.get("issuer_role") != expected_issuer_role:
        raise SigningCliHold("signed_envelope_role_mismatch")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        _verify_ed25519(key.public_key, signature, canonical_json(payload))
    except (binascii.Error, ValueError, F4GoHold):
        raise SigningCliHold("signed_envelope_verification_failed") from None


def _validate_permit_envelope(permit: object,
                              keys: Mapping[str, TrustedVerificationKey] | None) -> None:
    if (not isinstance(permit, Mapping) or set(permit) != {"key_id", "signature", "payload"}
            or not isinstance(permit.get("payload"), dict)
            or set(permit["payload"]) != _PERMIT_PAYLOAD_KEYS):
        raise SigningCliHold("permit_envelope_invalid")
    payload = permit["payload"]
    if (payload.get("schema") != 2 or payload.get("repository_id") != REPOSITORY_ID
            or payload.get("issuer_id") != permit.get("key_id")
            or payload.get("issuer_role") != "permit_authority"):
        raise SigningCliHold("permit_scope_invalid")
    key = _trusted_role_key(keys, permit.get("key_id"), "permit_authority")
    _verify_role_envelope(permit, key, "permit_authority")
    _validate_permit_scope(payload)


def _validate_permit_scope(request: Mapping[str, object]) -> tuple[str, ...]:
    if (request.get("repository_id") != REPOSITORY_ID
            or isinstance(request.get("repository_id"), bool)
            or not isinstance(request.get("base_sha"), str)
            or not _GIT_SHA.fullmatch(request["base_sha"])
            or not isinstance(request.get("candidate_digest"), str)
            or not _SHA256.fullmatch(request["candidate_digest"])
            or not isinstance(request.get("permit_id"), str) or not request["permit_id"]
            or not isinstance(request.get("worker_run_id"), str) or not request["worker_run_id"]):
        raise SigningCliHold("permit_scope_invalid")
    paths = request.get("changed_paths")
    if (not isinstance(paths, (list, tuple)) or not paths
            or any(not isinstance(path, str) or not path or path.startswith("/")
                   or "\\" in path or ".." in path.split("/") for path in paths)
            or len(set(paths)) != len(paths) or tuple(sorted(paths)) != tuple(paths)):
        raise SigningCliHold("permit_paths_invalid")
    return tuple(paths)


def _require_journal_and_scope(context: SigningContext) -> None:
    if context.journal is None:
        raise SigningCliHold("permit_cas_journal_unavailable")
    if context.verify_candidate_scope is None:
        raise SigningCliHold("candidate_scope_verifier_missing")


def _call_scope_verifier(verifier: Callable[[Mapping[str, object]], bool] | None,
                         request: Mapping[str, object]) -> None:
    if verifier is None:
        raise SigningCliHold("candidate_scope_verifier_missing")
    try:
        accepted = verifier(request)
    except Exception:
        accepted = False
    if accepted is not True:
        raise SigningCliHold("candidate_scope_not_verified")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_field")
        result[key] = value
    return result


if __name__ == "__main__":
    raise SystemExit(main())
