"""DRAFT_HOLD trust-side provider; only a protected launcher may supply context.

Candidate bytes are JSON data for the existing CLI, never imports or code.
No dynamic provider loading, key generation, network, or environment discovery.
OS/Environment isolation must be established externally before enabling this.
"""
from __future__ import annotations

import base64
from dataclasses import replace
import sys
from typing import Mapping

from f4_signing_cli import SigningContext, SigningCliHold, _verify_signer_binding, main
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


if __name__ == "__main__":
    # A secret alone must never substitute for trusted validators/provenance.
    print("HOLD:protected_launcher_verification_context_not_connected", file=sys.stderr)
    raise SystemExit(78)
