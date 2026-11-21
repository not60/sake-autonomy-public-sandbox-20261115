"""DRAFT_HOLD trust-side provider; only a protected launcher may supply context.

Candidate bytes are JSON data for the existing CLI, never imports or code.
No dynamic provider loading, key generation, network, or environment discovery.
OS/Environment isolation must be established externally before enabling this.
"""
from __future__ import annotations

import base64
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
import sys
from typing import Mapping

from f4_signing_cli import (
    SigningContext, SigningCliHold, _unique_object, _verify_signer_binding, main,
)
from trusted_key_registry import TrustedVerificationKey

# New interfaces, not claims that any credential currently exists.
ROLE_ENVIRONMENTS = {
    "permit_authority": "f4-permit", "witness": "f4-witness",
    "owner_a_delegate": "f4-delegate-a", "owner_b_delegate": "f4-delegate-b",
}
ROLE_SECRET_NAMES = {
    "permit_authority": "B09_F4_PERMIT_PRIVATE_KEY_PKCS8_B64",
    "witness": "B09_F4_WITNESS_PRIVATE_KEY_PKCS8_B64",
    "owner_a_delegate": "B09_F4_DELEGATE_A_PRIVATE_KEY_PKCS8_B64",
    "owner_b_delegate": "B09_F4_DELEGATE_B_PRIVATE_KEY_PKCS8_B64",
}
ROLE_REQUEST_FILES = {
    "permit_authority": "permit_authority-request.json",
    "witness": "witness-request.json",
    "owner_a_delegate": "owner_a_delegate-request.json",
    "owner_b_delegate": "owner_b_delegate-request.json",
}
ROLE_REQUEST_FIELDS = {
    "permit_authority": frozenset({
        "permit_id", "issuer_id", "repository_id", "base_sha",
        "candidate_digest", "changed_paths", "worker_run_id",
    }),
    "witness": frozenset({"witness_id", "permit"}),
    "owner_a_delegate": frozenset({"delegation_envelope", "revocation_status", "evidence"}),
    "owner_b_delegate": frozenset({"delegation_envelope", "revocation_status", "evidence"}),
}


def _require_independent_status_readers(*, role: str,
                                        authenticated_execution_check,
                                        read_authenticated_delegation_status,
                                        read_verified_cycle1_audit_digest=None) -> None:
    """Prevent a GO freshness check from being reused as delegation/audit state."""
    if role not in {"owner_a_delegate", "owner_b_delegate"}:
        return
    if (read_authenticated_delegation_status is authenticated_execution_check
            or (read_verified_cycle1_audit_digest is not None
                and read_authenticated_delegation_status is read_verified_cycle1_audit_digest)):
        raise SigningCliHold("delegation_revocation_reader_must_be_independent")


def load_signing_request_file(*, role: str, input_root: str | Path) -> str:
    """Read one bounded JSON request from the protected launcher's data directory.

    This loader treats artifacts only as data. The existing CLI and the
    injected verification context still validate provenance, scope, signatures,
    CAS, and revocation before a signer can be used.
    """
    if role not in ROLE_REQUEST_FILES:
        raise SigningCliHold("signing_request_role_invalid")
    root = Path(input_root)
    if root.is_symlink():
        raise SigningCliHold("signing_request_root_unsafe")
    try:
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir():
            raise SigningCliHold("signing_request_root_unsafe")
        target = resolved_root / ROLE_REQUEST_FILES[role]
        target.resolve(strict=True).relative_to(resolved_root)
        if target.is_symlink():
            raise SigningCliHold("signing_request_file_unsafe")
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
                raise SigningCliHold("signing_request_file_unsafe")
            chunks = bytearray()
            while len(chunks) <= 4 * 1024 * 1024:
                part = os.read(fd, min(65536, 4 * 1024 * 1024 + 1 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
        finally:
            os.close(fd)
        if len(chunks) > 4 * 1024 * 1024:
            raise SigningCliHold("signing_request_too_large")
        raw = bytes(chunks).decode("utf-8", errors="strict")
        request = json.loads(raw, object_pairs_hook=_unique_object)
    except SigningCliHold:
        raise
    except Exception:
        raise SigningCliHold("signing_request_file_invalid_or_unavailable") from None
    if not isinstance(request, dict) or set(request) != ROLE_REQUEST_FIELDS[role]:
        raise SigningCliHold("signing_request_schema_mismatch")
    return raw


def launch_signing_role_from_request_file(*, role: str, environment: str,
                                          role_keys: Mapping[str, TrustedVerificationKey],
                                          encoded_private_key: str,
                                          input_root: str | Path, output: str | Path,
                                          verification_inputs: Mapping[str, object]) -> int:
    """Join a fixed request artifact to the existing trusted role launcher."""
    if not isinstance(verification_inputs, Mapping):
        raise SigningCliHold("trusted_verification_inputs_missing")
    raw = load_signing_request_file(role=role, input_root=input_root)
    return launch_signing_role(
        role=role, environment=environment, role_keys=role_keys,
        encoded_private_key=encoded_private_key, request=io.StringIO(raw),
        output=output, verification_inputs=verification_inputs,
    )


def bind_role_context(*, role: str, environment: str,
                      template: SigningContext,
                      role_keys: Mapping[str, TrustedVerificationKey],
                      encoded_private_key: str) -> SigningContext:
    """Bind ONE launcher-supplied credential to existing trusted validators.

    template/role_keys/environment come from protected code/config, not request
    JSON. role_keys includes all four signing roles and Owner A/B public roots.
    Delegate keys must also match the externally Owner-signed delegation; the
    existing CLI verifies that contract and its revocation on every request.
    """
    if (role not in ROLE_ENVIRONMENTS or environment != ROLE_ENVIRONMENTS[role]
            or not isinstance(template, SigningContext) or template.role != role
            or template.signer is not None):
        raise SigningCliHold("trusted_provider_role_context_invalid")
    required = set(ROLE_ENVIRONMENTS) | {"owner_a", "owner_b"}
    if (not isinstance(role_keys, Mapping) or set(role_keys) != required
            or any(not isinstance(key, TrustedVerificationKey) or key.role != name
                   or not isinstance(key.public_key, bytes) or len(key.public_key) != 32
                   for name, key in role_keys.items())
            or len({key.public_key for key in role_keys.values()}) != len(required)
            or len({key.key_id for key in role_keys.values()}) != len(required)):
        raise SigningCliHold("trusted_provider_independent_keys_required")
    registry = template.trusted_keys if role in {"permit_authority", "witness"} else template.trusted_owner_keys
    needed = {"permit_authority", "witness"} if role in {"permit_authority", "witness"} else {"owner_a", "owner_b"}
    if (not isinstance(registry, Mapping)
            or any(registry.get(role_keys[name].key_id) != role_keys[name] for name in needed)):
        raise SigningCliHold("trusted_provider_registry_mismatch")
    if role in {"permit_authority", "witness"}:
        if template.journal is None or not callable(template.verify_candidate_scope):
            raise SigningCliHold("trusted_provider_journal_or_scope_missing")
    elif (not callable(template.verify_revocation_status)
          or not callable(template.verify_candidate_evidence)):
        raise SigningCliHold("trusted_provider_revocation_or_evidence_missing")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        raw = base64.b64decode(encoded_private_key, validate=True)
        signer = serialization.load_der_private_key(raw, password=None)
        if not isinstance(signer, Ed25519PrivateKey):
            raise ValueError("wrong key type")
        _verify_signer_binding(signer, role_keys[role], role)
    except Exception:
        raise SigningCliHold("trusted_provider_credential_unavailable_or_mismatched") from None
    return replace(template, signer=signer)


def run_trusted_role(*, role: str, environment: str, template: SigningContext,
                     role_keys: Mapping[str, TrustedVerificationKey],
                     encoded_private_key: str, stdin=None, stdout=None, stderr=None) -> int:
    """Trusted launcher's in-process entry; forwards data to the existing CLI."""
    try:
        context = bind_role_context(
            role=role, environment=environment, template=template,
            role_keys=role_keys, encoded_private_key=encoded_private_key,
        )
    except SigningCliHold as exc:
        print("HOLD:" + exc.code, file=stderr or sys.stderr)
        return 78
    return main(["--role", role], context=context, stdin=stdin, stdout=stdout, stderr=stderr)


def build_live_go_execution_check(*, candidate, workspace, expected_base_sha,
                                  trusted_owner_keys, cycle_control_journal):
    """Bind the existing GO verifier to a fresh, read-only cycle-control CAS read.

    This is specifically the F4 GO revocation source. It does not provide or
    substitute for the separate delegation-revocation reader required by
    delegate roles.
    """
    from f4_cycle_control import F4CycleControlJournal, _current_revocation
    from f4_cycle_runtime import execution_authorization_check
    if not isinstance(cycle_control_journal, F4CycleControlJournal):
        raise SigningCliHold("trusted_cycle_control_journal_required")

    def read_latest_go_revocation():
        try:
            state = cycle_control_journal.read()
            if state is None:
                raise SigningCliHold("signed_go_revocation_state_missing")
            envelope = _current_revocation(state.events)
            if envelope is None:
                raise SigningCliHold("signed_go_revocation_state_missing")
            return envelope
        except SigningCliHold:
            raise
        except Exception:
            raise SigningCliHold("signed_go_revocation_state_unavailable") from None

    try:
        return execution_authorization_check(
            candidate=candidate, workspace=workspace,
            expected_base_sha=expected_base_sha,
            trusted_keys=trusted_owner_keys,
            read_signed_revocation=read_latest_go_revocation,
        )
    except Exception:
        raise SigningCliHold("signed_go_verifier_unavailable") from None


def build_verification_context(*, role, gate, journal, artifact_root, manifest,
                               codex_output_file, expected_run_id,
                               expected_execution_sha, cycle, cycle_tasks,
                               github_read_token, worker_archive_path, authenticated_execution_check,
                               read_authenticated_delegation_status,
                               permit=None, witness=None, read_verified_cycle1_audit_digest=None):
    """Protected launcher's concrete validators; no candidate code is imported.

    gate/journal, source files, pinned run/scope, authenticated readers and token
    come ONLY from trusted launcher configuration. Readers must verify freshness
    and the existing signed F4/cycle-control contracts, not a supplied PASS flag.
    DelegationStatusStore readers verify the full signed contract before adapting
    to the existing three-field status; external deployment remains required.
    This factory never consumes a Permit or mutates CAS.
    """
    import hashlib
    import json
    from attestations import canonical_json
    from f4_signing_cli import _validate_permit_envelope, _verify_role_envelope
    from github_worker_provenance import verify_worker_artifact_provenance
    from publisher_gate import PublisherGate
    if (role not in ROLE_ENVIRONMENTS or not isinstance(gate, PublisherGate)
            or gate._cas_journal is not journal or journal is None
            or gate._repository_id != 1458303357
            or not callable(authenticated_execution_check)
            or not callable(read_authenticated_delegation_status)
            or not isinstance(cycle_tasks, tuple) or len(cycle_tasks) != 2
            or len(set(cycle_tasks)) != 2 or type(cycle) is not int or cycle not in (1, 2)
            or (cycle == 2 and not callable(read_verified_cycle1_audit_digest))):
        raise SigningCliHold("trusted_verification_inputs_missing")
    _require_independent_status_readers(
        role=role, authenticated_execution_check=authenticated_execution_check,
        read_authenticated_delegation_status=read_authenticated_delegation_status,
        read_verified_cycle1_audit_digest=read_verified_cycle1_audit_digest,
    )
    # Freeze JSON inputs, so caller mutation cannot change a previously bound request.
    frozen_manifest = json.loads(canonical_json(manifest))
    frozen_permit = json.loads(canonical_json(permit))
    frozen_witness = json.loads(canonical_json(witness))

    def material_and_provenance():
        if authenticated_execution_check() is not True:
            raise SigningCliHold("execution_revoked_or_unverified")
        material = gate.verify_signing_material(
            artifact_root=artifact_root, manifest=frozen_manifest,
            codex_output_file=codex_output_file,
        )
        proof = verify_worker_artifact_provenance(
            frozen_manifest, expected_run_id=expected_run_id,
            expected_base_sha=gate._base_sha,
            expected_execution_sha=expected_execution_sha, expected_cycle=cycle,
            bearer_token=github_read_token,
        )
        # Bind the exact downloaded ZIP to Actions metadata and verified candidate bytes.
        # Read data only; never extract or execute entries in the signing job.
        import io
        import zipfile
        from pathlib import Path
        archive_path = Path(worker_archive_path)
        if archive_path.is_symlink() or not archive_path.is_file() or archive_path.stat().st_size > 32 * 1024 * 1024:
            raise SigningCliHold("worker_archive_missing_or_unsafe")
        archive_bytes = archive_path.read_bytes()
        if "sha256:" + hashlib.sha256(archive_bytes).hexdigest() != proof["archive_digest"]:
            raise SigningCliHold("worker_archive_provenance_mismatch")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            entries = archive.infolist()
            names = [item.filename for item in entries if not item.is_dir()]
            expected_names = {"manifest.json", "evidence/codex-output.bin"} | {"files/" + path for path in material["files"]}
            if len(names) != len(set(names)) or set(names) != expected_names or sum(e.file_size for e in entries) > 32 * 1024 * 1024:
                raise SigningCliHold("worker_archive_members_invalid")
            if json.loads(archive.read("manifest.json")) != frozen_manifest:
                raise SigningCliHold("worker_archive_manifest_mismatch")
            hashes = {"files/" + path: digest for path, digest in material["files"].items()}
            hashes["evidence/codex-output.bin"] = material["codex_output_sha256"]
            if any(hashlib.sha256(archive.read(name)).hexdigest() != digest for name, digest in hashes.items()):
                raise SigningCliHold("worker_archive_bytes_mismatch")
        return material, hashlib.sha256(canonical_json(proof)).hexdigest()

    def verify_scope(request):
        material, _proof = material_and_provenance()
        expected = {name: material[name] for name in (
            "repository_id", "base_sha", "candidate_digest", "changed_paths", "worker_run_id")}
        if any(request.get(name) != value for name, value in expected.items()):
            return False
        snapshot = journal.snapshot()  # validates persistent hash chain each time
        if role == "permit_authority":
            return not any(e["payload"].get("permit_id") == request["permit_id"] for e in snapshot.events)
        signed_permit = request.get("permit")
        _validate_permit_envelope(signed_permit, gate._trusted_keys)
        digest = hashlib.sha256(canonical_json(signed_permit["payload"])).hexdigest()
        expected_event = {"event": "PERMIT_ISSUED", "permit_id": request["permit_id"],
                          "candidate_digest": material["candidate_digest"],
                          "permit_digest": digest, "worker_run_id": material["worker_run_id"]}
        related = [e["payload"] for e in snapshot.events
                   if e["payload"].get("permit_id") == request["permit_id"]]
        return related == [expected_event]

    def verify_revocation(observed, payload):
        if authenticated_execution_check() is not True:
            return False
        current = read_authenticated_delegation_status(payload)
        return (isinstance(current, Mapping) and dict(current) == observed
                and set(current) == {"delegation_id", "sequence", "status"}
                and current["delegation_id"] == payload["delegation_id"]
                and type(current["sequence"]) is int
                and current["sequence"] == payload["revocation"]["sequence"]
                and current["status"] == "ACTIVE")

    def verify_evidence(evidence, delegation):
        material, proof_digest = material_and_provenance()
        if (delegation.execution_revision != expected_execution_sha
                or delegation.cycle_tasks != cycle_tasks):
            return False
        _validate_permit_envelope(frozen_permit, gate._trusted_keys)
        p = frozen_permit["payload"]
        for name in ("repository_id", "base_sha", "candidate_digest", "changed_paths", "worker_run_id"):
            if p[name] != material[name]:
                return False
        key = gate._trusted_keys.get(frozen_witness["key_id"])
        if key is None or key.role != "witness":
            return False
        _verify_role_envelope(frozen_witness, key, "witness")
        permit_key = gate._trusted_keys[frozen_permit["key_id"]]
        if permit_key.public_key == key.public_key:
            return False
        pd = hashlib.sha256(canonical_json(p)).hexdigest()
        wd = hashlib.sha256(canonical_json(frozen_witness)).hexdigest()
        snapshot = journal.snapshot()
        expected_witness = {
            "schema": 2, "witness_id": key.key_id, "permit_digest": pd,
            **{name: material[name] for name in ("repository_id", "base_sha", "candidate_digest", "changed_paths", "worker_run_id")},
            "issuer_role": "witness", "journal_parent_sha256": snapshot.head_sha256,
        }
        if frozen_witness["payload"] != expected_witness:
            return False
        issued = {"event": "PERMIT_ISSUED", "permit_id": p["permit_id"],
                  "candidate_digest": material["candidate_digest"], "permit_digest": pd,
                  "worker_run_id": material["worker_run_id"]}
        related = [e["payload"] for e in snapshot.events if e["payload"].get("permit_id") == p["permit_id"]]
        if related != [issued]:
            return False
        audit_digest = None if cycle == 1 else read_verified_cycle1_audit_digest()
        if cycle == 2:
            import re
            if not isinstance(audit_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", audit_digest):
                return False
        expected = {
            "repository_id": material["repository_id"], "execution_revision": expected_execution_sha,
            "task_id": cycle_tasks[cycle - 1], "cycle_number": cycle,
            "run_id": material["worker_run_id"], "changed_paths": material["changed_paths"],
            "file_sha256": material["files"], "candidate_digest": material["candidate_digest"],
            "permit_digest": pd, "witness_digest": wd,
            "cas_revision": snapshot.sequence, "cas_head_sha256": snapshot.head_sha256,
            "worker_provenance_digest": proof_digest, "cycle1_audit_digest": audit_digest,
        }
        # Validity/allowed paths are independently checked by the existing delegation verifier.
        return isinstance(evidence, Mapping) and all(evidence.get(k) == v for k, v in expected.items())

    return SigningContext(
        role=role, signer=None, trusted_keys=gate._trusted_keys,
        trusted_owner_keys=gate._trusted_keys, journal=journal,
        verify_candidate_scope=verify_scope, expected_execution_revision=expected_execution_sha,
        expected_cycle_tasks=cycle_tasks, verify_revocation_status=verify_revocation,
        verify_candidate_evidence=verify_evidence,
    )


def write_signature_artifact(*, output, role, envelope, trusted_key):
    """Persist only a verified signature envelope to a trusted, exclusive output path."""
    import base64
    import os
    from pathlib import Path
    from attestations import canonical_json
    from f4_go_gate import _verify_ed25519
    from f4_signing_cli import _verify_role_envelope
    if role not in ROLE_ENVIRONMENTS or trusted_key.role != role:
        raise SigningCliHold("signature_artifact_role_invalid")
    if role in {"permit_authority", "witness"}:
        _verify_role_envelope(envelope, trusted_key, role)
    else:
        if (not isinstance(envelope, dict) or set(envelope) != {"schema", "role", "payload", "signature"}
                or envelope["schema"] != 1 or envelope["role"] != role
                or envelope["payload"].get("kind") != "F4_DELEGATED_CANDIDATE_AUTHORIZATION"
                or set(envelope["signature"]) != {"key_id", "signature"}
                or envelope["signature"]["key_id"] != trusted_key.key_id):
            raise SigningCliHold("signature_artifact_fragment_invalid")
        _verify_ed25519(trusted_key.public_key,
            base64.b64decode(envelope["signature"]["signature"], validate=True),
            canonical_json(envelope["payload"]))
    data = canonical_json(envelope) + b"\n"
    target = Path(output)  # directory is owned by protected launcher, never artifact input
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    import hashlib
    return hashlib.sha256(data).hexdigest()


def launch_signing_role(*, role, environment, role_keys, encoded_private_key,
                        request, output, verification_inputs):
    """Protected in-process launcher entry for any of the four signing roles.

    The caller owns the request stream, output directory, and authenticated
    verification inputs. Nothing is loaded from a module named by the request.
    """
    import io
    import json

    target = Path(output)
    if (role not in ROLE_ENVIRONMENTS or environment != ROLE_ENVIRONMENTS[role]
            or target.name != role + ".json" or not target.parent.is_dir()
            or target.exists() or target.is_symlink()):
        raise SigningCliHold("protected_launcher_role_or_output_invalid")
    template = build_verification_context(role=role, **verification_inputs)
    signed = io.StringIO()
    status = run_trusted_role(
        role=role, environment=environment, template=template, role_keys=role_keys,
        encoded_private_key=encoded_private_key, stdin=request, stdout=signed,
    )
    if status != 0:
        raise SigningCliHold("protected_launcher_signing_held")
    return write_signature_artifact(
        output=target, role=role, envelope=json.loads(signed.getvalue()),
        trusted_key=role_keys[role],
    )


if __name__ == "__main__":
    # A secret alone must never substitute for trusted validators/provenance.
    print("HOLD:protected_launcher_verification_context_not_connected", file=sys.stderr)
    raise SystemExit(78)


def build_delegation_status_reader(*, backend, trusted_owner_keys, environment, delegation_payload):
    """Protected caller supplies an authenticated read-only CAS backend and scope."""
    import hashlib
    from attestations import canonical_json
    from delegation_revocation import DelegationStatusStore, authenticated_delegation_reader
    store = DelegationStatusStore(backend, trusted_owner_keys=trusted_owner_keys, environment=environment)
    return authenticated_delegation_reader(
        store, expected_delegation_id=delegation_payload["delegation_id"],
        expected_contract_sha256=hashlib.sha256(canonical_json(delegation_payload)).hexdigest(),
        expected_revision=delegation_payload["execution_revision"],
    )


def build_cycle2_audit_digest_reader(*, journal, reader, archive_path, run_id, attempt,
                                    candidate, go, claim, previous, publication_reader):
    """Return the Cycle2 digest only after the existing archive/provenance verifier seals it."""
    from f4_auditor_artifact import verify_cycle2_archive
    from f4_cycle_control import is_verified_stage_audit
    from pathlib import Path
    path = Path(archive_path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024
            or claim.cycle != 2 or previous is None or previous.claim.cycle != 1):
        raise SigningCliHold("cycle2_audit_archive_unavailable_or_unscoped")
    archive = path.read_bytes()
    try:
        result = verify_cycle2_archive(
            journal=journal, reader=reader, archive=archive, run_id=run_id,
            attempt=attempt, candidate=candidate, go=go, claim=claim,
            previous=previous, publication_reader=publication_reader,
        )
    except Exception:
        raise SigningCliHold("cycle2_audit_verification_failed") from None
    if not is_verified_stage_audit(result, claim, previous):
        raise SigningCliHold("cycle2_audit_not_independently_verified")
    return lambda: result.envelope_sha256
