"""Test-only F4 signature and sequential-cycle contract checks."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from attestations import canonical_json
from f4_go_gate import (
    F4_SOURCE_PATHS,
    F4GoHold,
    VerifiedF4Go,
    authorize_cycle,
    build_f4_go_candidate,
    verify_f4_go_candidate,
)
from trusted_key_registry import TrustedVerificationKey


BASE_SHA = "a" * 40
NOW = datetime(2026, 11, 18, 3, 0, tzinfo=timezone.utc)
VALID_FROM = "2026-11-18T02:00:00Z"
EXPIRES_AT = "2026-11-18T04:00:00Z"
APPROVAL_ID = "fixture-f4-two-cycle-approval"
ROLES = ("permit_authority", "witness", "owner_a", "owner_b")
_DEFAULT_VERIFIER = object()


class EphemeralEd25519:
    """Use short-lived test-only keys; never print private key material."""

    _NODE = r'''
const fs = require("fs");
const crypto = require("crypto");
const [action, ...paths] = process.argv.slice(1);
if (action === "generate") {
  const pair = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(paths[0], pair.privateKey.export({format:"der", type:"pkcs8"}));
  fs.writeFileSync(paths[1], pair.publicKey.export({format:"der", type:"spki"}));
} else if (action === "sign") {
  const key = crypto.createPrivateKey({key:fs.readFileSync(paths[0]), format:"der", type:"pkcs8"});
  fs.writeFileSync(paths[2], crypto.sign(null, fs.readFileSync(paths[1]), key));
} else if (action === "verify") {
  const raw = fs.readFileSync(paths[0]);
  const spki = raw.length === 32
    ? Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]) : raw;
  const key = crypto.createPublicKey({key:spki, format:"der", type:"spki"});
  if (!crypto.verify(null, fs.readFileSync(paths[2]), key, fs.readFileSync(paths[1]))) process.exit(3);
} else process.exit(2);
'''

    def __init__(self, root: Path) -> None:
        self.root = root
        self.node = shutil.which("node")
        if not self.node:
            raise RuntimeError("test requires the available Node.js Ed25519 implementation")
        self.private_paths = {}
        self.public_keys = {}
        for role in ROLES:
            private_path = root / (role + ".test-only.pk8")
            public_path = root / (role + ".test-only.spki")
            subprocess.run(
                [self.node, "-e", self._NODE, "generate", str(private_path), str(public_path)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            encoded = public_path.read_bytes()
            if len(encoded) < 32:
                raise RuntimeError("unexpected test Ed25519 public-key encoding")
            self.private_paths[role] = private_path
            self.public_keys[role] = encoded[-32:]

    def sign(self, role: str, message: bytes) -> bytes:
        message_path = self.root / "sign-message.bin"
        signature_path = self.root / "signature.bin"
        message_path.write_bytes(message)
        subprocess.run(
            [self.node, "-e", self._NODE, "sign", str(self.private_paths[role]),
             str(message_path), str(signature_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        return signature_path.read_bytes()

    def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None:
        public_path = self.root / "verify-public.pub"
        message_path = self.root / "verify-message.bin"
        signature_path = self.root / "verify-signature.bin"
        public_path.write_bytes(public_key)
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        subprocess.run(
            [self.node, "-e", self._NODE, "verify", str(public_path), str(signature_path), str(message_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )


class F4GoGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="b12-f4-go-test-")
        self.root = Path(self.temp.name)
        for path in F4_SOURCE_PATHS:
            target = self.root.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("fixture source: " + path + "\n").encode("utf-8"))
        self.keys = EphemeralEd25519(self.root)
        self.trusted_keys = {
            role + "-test-key": TrustedVerificationKey(
                role + "-test-key", role, self.keys.public_keys[role],
            )
            for role in ROLES
        }
        self.candidate = self._signed_candidate()
        self.revocation = {
            "approval_id": APPROVAL_ID,
            "sequence": 1,
            "status": "ACTIVE",
        }
        self.verify_patch = patch("f4_go_gate._verify_ed25519", self.keys.verify)
        self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _signed_candidate(self):
        candidate = build_f4_go_candidate(
            workspace=self.root,
            base_sha=BASE_SHA,
            approval_id=APPROVAL_ID,
            not_before=VALID_FROM,
            expires_at=EXPIRES_AT,
            revocation_sequence=1,
        )
        payload = candidate["payload"]
        approvals = {}
        for role in ("owner_a", "owner_b"):
            approvals[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(self.keys.sign(role, canonical_json(payload))).decode("ascii"),
                "payload": payload,
            }
        return {**candidate, "state": "SIGNED_GO", "approvals": approvals}

    def _verify(self, candidate=None, root=None, status=None,
                verifier=_DEFAULT_VERIFIER, now=NOW):
        check_revocation = (lambda value: value == self.revocation
                            if verifier is _DEFAULT_VERIFIER else verifier)
        if verifier is not _DEFAULT_VERIFIER:
            check_revocation = verifier
        return verify_f4_go_candidate(
            candidate=self.candidate if candidate is None else candidate,
            workspace=self.root if root is None else root,
            expected_repository_id=1458303357,
            expected_base_sha=BASE_SHA,
            trusted_keys=self.trusted_keys,
            revocation_status=self.revocation if status is None else status,
            verify_revocation_status=check_revocation,
            now=now,
        )

    def test_two_independent_owner_signatures_verify_exact_four_source_bundle(self) -> None:
        go = self._verify()
        self.assertEqual(go.max_worker_cycles, 2)
        self.assertEqual(tuple(path for path, _ in go.source_sha256s), tuple(sorted(F4_SOURCE_PATHS)))

    def test_unsigned_draft_and_legacy_draft_pr_approvals_are_not_f4_go(self) -> None:
        draft = build_f4_go_candidate(
            workspace=self.root, base_sha=BASE_SHA, approval_id=APPROVAL_ID,
            not_before=VALID_FROM, expires_at=EXPIRES_AT, revocation_sequence=1,
        )
        with self.assertRaisesRegex(F4GoHold, "not_owner_signed"):
            self._verify(candidate=draft)
        legacy_approvals = {role: {
            "key_id": role + "-test-key", "signature": base64.b64encode(b"x" * 64).decode("ascii"),
            "payload": {"decision": "DRAFT_PR_ONLY"},
        } for role in ("owner_a", "owner_b")}
        legacy_candidate = {**self.candidate, "approvals": legacy_approvals}
        with self.assertRaisesRegex(F4GoHold, "owner_envelope_invalid"):
            self._verify(candidate=legacy_candidate)

    def test_tampered_signature_source_scope_and_expiry_fail_closed(self) -> None:
        tampered = {**self.candidate, "approvals": dict(self.candidate["approvals"])}
        tampered["approvals"]["owner_a"] = {
            **tampered["approvals"]["owner_a"], "signature": base64.b64encode(b"x" * 64).decode("ascii"),
        }
        with self.assertRaisesRegex(F4GoHold, "signature_invalid"):
            self._verify(candidate=tampered)

        changed = self.root / F4_SOURCE_PATHS[0]
        changed.write_bytes(changed.read_bytes() + b"tampered")
        with self.assertRaisesRegex(F4GoHold, "source_sha_mismatch"):
            self._verify()

        changed.write_bytes(("fixture source: " + F4_SOURCE_PATHS[0] + "\n").encode("utf-8"))
        with self.assertRaisesRegex(F4GoHold, "scope_mismatch"):
            payload = dict(self.candidate["payload"])
            payload["scope"] = {**payload["scope"], "max_worker_cycles": 3}
            bad = self._resign_payload(payload)
            self._verify(candidate=bad)

        with self.assertRaisesRegex(F4GoHold, "expired"):
            self._verify(now=datetime(2026, 11, 18, 4, 0, tzinfo=timezone.utc))

    def _resign_payload(self, payload):
        approvals = {}
        for role in ("owner_a", "owner_b"):
            approvals[role] = {
                "key_id": role + "-test-key",
                "signature": base64.b64encode(self.keys.sign(role, canonical_json(payload))).decode("ascii"),
                "payload": payload,
            }
        return {"schema": 1, "state": "SIGNED_GO", "payload": payload, "approvals": approvals}

    def test_missing_revocation_verifier_revoked_status_and_base_mismatch_hold(self) -> None:
        with self.assertRaisesRegex(F4GoHold, "revocation_status_verifier_missing"):
            self._verify(verifier=None)
        with self.assertRaisesRegex(F4GoHold, "revocation_status_not_authenticated"):
            self._verify(verifier=lambda _value: False)
        with self.assertRaisesRegex(F4GoHold, "revocation_status_missing_or_invalid"):
            self._verify(status={**self.revocation, "status": "REVOKED"},
                         verifier=lambda _value: True)
        with self.assertRaisesRegex(F4GoHold, "base_sha_mismatch"):
            verify_f4_go_candidate(
                candidate=self.candidate, workspace=self.root, expected_repository_id=1458303357,
                expected_base_sha="b" * 40, trusted_keys=self.trusted_keys,
                revocation_status=self.revocation,
                verify_revocation_status=lambda value: value == self.revocation, now=NOW,
            )

    def test_cycle_two_requires_verified_cycle_one_audit_and_atomic_claim(self) -> None:
        go = self._verify()
        claimed = []
        claim = lambda approval_id, cycle: claimed.append((approval_id, cycle)) is None
        authorize_cycle(go=go, cycle_number=1, atomic_cycle_claim=claim,
                        revocation_status=self.revocation,
                        verify_revocation_status=lambda value: value == self.revocation, now=NOW)
        self.assertEqual(claimed, [(APPROVAL_ID, 1)])
        with self.assertRaisesRegex(F4GoHold, "audit_verifier_missing"):
            authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=claim,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda value: value == self.revocation,
                            now=NOW)
        receipt = {
            "approval_id": APPROVAL_ID, "cycle_number": 1, "outcome": "PASS",
            "repository_id": 1458303357, "base_sha": BASE_SHA,
            "worker_run_id": "test-cycle-1-worker", "auditor_run_id": "test-cycle-1-auditor",
            "journal_revision": 2, "journal_head_sha256": "c" * 64,
        }
        before_revoked_cycle_2 = list(claimed)
        with self.assertRaisesRegex(F4GoHold, "revocation_status_missing_or_invalid"):
            authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=claim,
                            revocation_status={**self.revocation, "status": "REVOKED"},
                            verify_revocation_status=lambda _value: True,
                            cycle_1_audit_receipt=receipt,
                            verify_audit_receipt=lambda value: value == receipt, now=NOW)
        self.assertEqual(claimed, before_revoked_cycle_2)
        with self.assertRaisesRegex(F4GoHold, "audit_not_passed"):
            authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=claim,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda value: value == self.revocation,
                            cycle_1_audit_receipt=receipt,
                            verify_audit_receipt=lambda _value: False, now=NOW)
        authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=claim,
                        revocation_status=self.revocation,
                        verify_revocation_status=lambda value: value == self.revocation,
                        cycle_1_audit_receipt=receipt,
                        verify_audit_receipt=lambda value: value == receipt, now=NOW)
        self.assertEqual(claimed[-1], (APPROVAL_ID, 2))
        with self.assertRaisesRegex(F4GoHold, "duplicate_or_ambiguous"):
            authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=lambda *_args: False,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda value: value == self.revocation,
                            cycle_1_audit_receipt=receipt,
                            verify_audit_receipt=lambda _value: True, now=NOW)

    def test_cycle_two_receipt_scope_and_expired_go_are_rejected(self) -> None:
        go = self._verify()
        receipt = {
            "approval_id": APPROVAL_ID, "cycle_number": 1, "outcome": "PASS",
            "repository_id": 1458303357, "base_sha": "d" * 40,
            "worker_run_id": "test-cycle-1-worker", "auditor_run_id": "test-cycle-1-auditor",
            "journal_revision": 2, "journal_head_sha256": "c" * 64,
        }
        with self.assertRaisesRegex(F4GoHold, "receipt_scope_mismatch"):
            authorize_cycle(go=go, cycle_number=2, atomic_cycle_claim=lambda *_args: True,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda value: value == self.revocation,
                            cycle_1_audit_receipt=receipt,
                            verify_audit_receipt=lambda _value: True, now=NOW)
        with self.assertRaisesRegex(F4GoHold, "expired"):
            authorize_cycle(go=go, cycle_number=1, atomic_cycle_claim=lambda *_args: True,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda value: value == self.revocation,
                            now=datetime(2026, 11, 18, 4, 0, tzinfo=timezone.utc))

    def test_cycle_requires_fresh_authenticated_nonrevoked_status(self) -> None:
        go = self._verify()
        with self.assertRaisesRegex(F4GoHold, "revocation_status_verifier_missing"):
            authorize_cycle(go=go, cycle_number=1, atomic_cycle_claim=lambda *_args: True,
                            now=NOW)
        with self.assertRaisesRegex(F4GoHold, "revocation_status_not_authenticated"):
            authorize_cycle(go=go, cycle_number=1, atomic_cycle_claim=lambda *_args: True,
                            revocation_status=self.revocation,
                            verify_revocation_status=lambda _value: False, now=NOW)
        with self.assertRaisesRegex(F4GoHold, "revocation_status_missing_or_invalid"):
            authorize_cycle(go=go, cycle_number=1, atomic_cycle_claim=lambda *_args: True,
                            revocation_status={**self.revocation, "status": "REVOKED"},
                            verify_revocation_status=lambda _value: True, now=NOW)


if __name__ == "__main__":
    unittest.main()
