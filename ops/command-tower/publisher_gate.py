"""Offline, fail-closed verification for a DRAFT_HOLD Publisher artifact.

This module never contacts GitHub or alters artifact files. It only reads the
bundle and records SAFE_STOP/single-use state in a local SQLite DurableStore.
Successful local verification only means that an artifact passed the supplied
checks; it does not authorize publication. A trusted Ed25519 key set and a
DurableStore are required. Missing verifier support, signatures, or keys is a
HOLD.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping

from durable_store import (
    DurableStore,
    PermitAlreadyConsumed,
    PermitIdAlreadyConsumed,
    PermitIdAlreadyIssued,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class PublisherGateHold(RuntimeError):
    """The offline bundle failed closed; the attached reason is non-sensitive."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class TrustedVerificationKey:
    key_id: str
    role: str
    public_key: bytes


@dataclass(frozen=True)
class OfflineVerificationResult:
    repository_id: int
    base_sha: str
    candidate_digest: str
    permit_id: str
    permit_digest: str
    changed_paths: tuple[str, ...]
    file_sha256: tuple[tuple[str, str], ...]
    publication_authorized: bool = False


class PublisherGate:
    """Validate a local artifact and durably consume its signed permit once."""

    def __init__(self, *, repository_id: int, base_sha: str,
                 allowed_paths: tuple[str, ...],
                 trusted_keys: Mapping[str, TrustedVerificationKey],
                 durable_store: DurableStore) -> None:
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

    def verify_bundle(self, *, artifact_root: str | Path,
                      manifest: object, permit: object,
                      witness: object) -> OfflineVerificationResult:
        """Verify offline inputs; any failure persists SAFE_STOP and raises HOLD."""
        try:
            return self._verify_bundle(artifact_root, manifest, permit, witness)
        except PublisherGateHold as exc:
            self._stop(exc.reason)
            raise
        except Exception:
            self._stop("unexpected_validation_failure")
            raise PublisherGateHold("unexpected_validation_failure") from None

    def _verify_bundle(self, artifact_root: str | Path, manifest: object,
                       permit: object, witness: object) -> OfflineVerificationResult:
        if self._store.state != "DRAFT_HOLD":
            raise PublisherGateHold("durable_runtime_not_active")
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "repository_id", "base_sha", "candidate_digest", "changed_paths", "files"
        }:
            raise PublisherGateHold("manifest_missing_or_invalid")
        if manifest["schema"] != 1:
            raise PublisherGateHold("manifest_schema_mismatch")
        repo_id = manifest["repository_id"]
        if isinstance(repo_id, bool) or repo_id != self._repository_id:
            raise PublisherGateHold("repository_id_mismatch")
        base_sha = manifest["base_sha"]
        if base_sha != self._base_sha:
            raise PublisherGateHold("base_sha_mismatch")

        changed_paths = manifest["changed_paths"]
        files = manifest["files"]
        if (not isinstance(changed_paths, list) or not changed_paths
                or any(not isinstance(path, str) for path in changed_paths)
                or len(set(changed_paths)) != len(changed_paths)
                or not isinstance(files, dict)
                or set(files) != set(changed_paths)):
            raise PublisherGateHold("manifest_paths_invalid")
        ordered_paths = tuple(sorted(changed_paths))
        if any(path not in self._allowed_paths or not _safe_path(path) for path in ordered_paths):
            raise PublisherGateHold("path_outside_allowlist")
        if any(not isinstance(digest, str) or not _SHA256.fullmatch(digest)
               for digest in files.values()):
            raise PublisherGateHold("manifest_file_digest_invalid")

        material = {
            "schema": 1,
            "repository_id": repo_id,
            "base_sha": base_sha,
            "changed_paths": list(ordered_paths),
            "files": {path: files[path] for path in ordered_paths},
        }
        candidate_digest = _sha256(_canonical(material))
        if manifest["candidate_digest"] != candidate_digest:
            raise PublisherGateHold("candidate_digest_mismatch")
        self._verify_artifact_files(artifact_root, files)

        if not _is_envelope(permit) or not _is_envelope(witness):
            raise PublisherGateHold("signed_permit_and_witness_required")
        permit_payload = permit["payload"]
        witness_payload = witness["payload"]
        if not isinstance(permit_payload, dict) or not isinstance(witness_payload, dict):
            raise PublisherGateHold("signed_payload_invalid")
        expected_permit_keys = {
            "schema", "permit_id", "issuer_id", "repository_id", "base_sha", "candidate_digest",
            "changed_paths", "issuer_role",
        }
        expected_witness_keys = {
            "schema", "witness_id", "permit_digest", "repository_id", "base_sha",
            "candidate_digest", "changed_paths", "issuer_role",
        }
        if set(permit_payload) != expected_permit_keys or set(witness_payload) != expected_witness_keys:
            raise PublisherGateHold("signed_payload_fields_invalid")
        permit_id = permit_payload["permit_id"]
        if not isinstance(permit_id, str) or not permit_id:
            raise PublisherGateHold("permit_id_missing")
        if (permit_payload["schema"] != 1
                or permit_payload["repository_id"] != repo_id
                or permit_payload["base_sha"] != base_sha
                or permit_payload["candidate_digest"] != candidate_digest
                or permit_payload["changed_paths"] != list(ordered_paths)
                or permit_payload["issuer_id"] != permit["key_id"]
                or permit_payload["issuer_role"] != "permit_authority"):
            raise PublisherGateHold("permit_scope_mismatch")

        permit_digest = _sha256(_canonical(permit_payload))
        if (witness_payload["schema"] != 1
                or not isinstance(witness_payload["witness_id"], str)
                or not witness_payload["witness_id"]
                or witness_payload["permit_digest"] != permit_digest
                or witness_payload["repository_id"] != repo_id
                or witness_payload["base_sha"] != base_sha
                or witness_payload["candidate_digest"] != candidate_digest
                or witness_payload["changed_paths"] != list(ordered_paths)
                or witness_payload["witness_id"] != witness["key_id"]
                or witness_payload["issuer_role"] != "witness"):
            raise PublisherGateHold("witness_scope_mismatch")
        if permit["key_id"] == witness["key_id"]:
            raise PublisherGateHold("permit_and_witness_signers_not_independent")
        permit_key = self._verify_signature(permit, "permit_authority")
        witness_key = self._verify_signature(witness, "witness")
        if permit_key.public_key == witness_key.public_key:
            raise PublisherGateHold("permit_and_witness_keys_not_independent")

        plan_digest = _sha256(_canonical({
            "candidate_digest": candidate_digest,
            "permit_digest": permit_digest,
            "purpose": "offline_publisher_verification",
        }))
        try:
            self._store.consume_permit_and_record(
                permit_digest,
                permit_id=permit_id,
                candidate_digest=candidate_digest,
                plan_digest=plan_digest,
                purpose="offline_publisher_verification",
                state="DRAFT_HOLD",
                repository_id=str(repo_id),
                base_sha=base_sha,
                changed_paths=json.dumps(list(ordered_paths), separators=(",", ":")),
            )
        except (PermitAlreadyConsumed, PermitIdAlreadyConsumed, PermitIdAlreadyIssued):
            raise PublisherGateHold("permit_replay_or_id_reuse") from None
        except Exception:
            raise PublisherGateHold("durability_failure") from None
        return OfflineVerificationResult(
            repo_id, base_sha, candidate_digest, permit_id, permit_digest,
            ordered_paths, tuple((path, files[path]) for path in ordered_paths), False,
        )

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

    def _verify_signature(self, envelope: dict[str, object], role: str) -> TrustedVerificationKey:
        key_id = envelope["key_id"]
        signature_text = envelope["signature"]
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
            # Process-local caller still receives HOLD if persistent stop fails.
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


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for an offline Publisher job; never performs publication."""
    parser = argparse.ArgumentParser(description="Verify a DRAFT_HOLD artifact offline")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--permit", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--trusted-keys", required=True,
                        help="JSON file containing public Ed25519 verification keys")
    parser.add_argument("--database", required=True,
                        help="local SQLite journal path for durable single-use checks")
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--allowed-path", required=True, action="append")
    args = parser.parse_args(argv)
    store: DurableStore | None = None
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        permit = json.loads(Path(args.permit).read_text(encoding="utf-8"))
        witness = json.loads(Path(args.witness).read_text(encoding="utf-8"))
        key_document = json.loads(Path(args.trusted_keys).read_text(encoding="utf-8"))
        if not isinstance(key_document, dict) or set(key_document) != {"keys"}:
            raise ValueError("invalid trusted-key document")
        if not isinstance(key_document["keys"], list):
            raise ValueError("invalid trusted-key list")
        keys: dict[str, TrustedVerificationKey] = {}
        for item in key_document["keys"]:
            if not isinstance(item, dict) or set(item) != {"key_id", "role", "public_key"}:
                raise ValueError("invalid trusted-key entry")
            key_id, role, encoded = item["key_id"], item["role"], item["public_key"]
            if not all(isinstance(value, str) and value for value in (key_id, role, encoded)):
                raise ValueError("invalid trusted-key values")
            if key_id in keys:
                raise ValueError("duplicate trusted-key ID")
            keys[key_id] = TrustedVerificationKey(
                key_id, role, base64.b64decode(encoded, validate=True),
            )
        store = DurableStore(args.database)
        gate = PublisherGate(
            repository_id=args.repository_id,
            base_sha=args.base_sha,
            allowed_paths=tuple(args.allowed_path),
            trusted_keys=keys,
            durable_store=store,
        )
        gate.verify_bundle(artifact_root=args.artifact_root, manifest=manifest,
                           permit=permit, witness=witness)
    except PublisherGateHold as exc:
        print(f"HOLD:{exc.reason}", file=sys.stderr)
        return 2
    except Exception:
        print("HOLD:input_or_configuration_invalid", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
    print("OFFLINE_CHECK_PASSED_NO_PUBLICATION_AUTHORIZED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
