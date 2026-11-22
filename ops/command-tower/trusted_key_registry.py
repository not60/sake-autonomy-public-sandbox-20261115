"""Strict, standard-library-only loading for independent Ed25519 trust roles."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Dict, FrozenSet, Set


@dataclass(frozen=True)
class TrustedVerificationKey:
    key_id: str
    role: str
    public_key: bytes


SIGNING_ROLES: FrozenSet[str] = frozenset({
    "permit_authority", "witness", "owner_a", "owner_b",
})


def load_trusted_verification_keys(document: object) -> Dict[str, TrustedVerificationKey]:
    """Load a complete, role-separated Ed25519 trust set or fail closed."""
    if (not isinstance(document, dict) or set(document) != {"keys"}
            or not isinstance(document["keys"], list) or not document["keys"]):
        raise ValueError("invalid or empty trusted-key document")
    keys: Dict[str, TrustedVerificationKey] = {}
    seen_public_keys: Set[bytes] = set()
    roles: Set[str] = set()
    for item in document["keys"]:
        if not isinstance(item, dict) or set(item) != {"key_id", "role", "public_key"}:
            raise ValueError("invalid trusted-key entry")
        key_id, role, encoded = item["key_id"], item["role"], item["public_key"]
        if (not isinstance(key_id, str) or not key_id or len(key_id) > 128
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in key_id)
                or not isinstance(role, str) or role not in SIGNING_ROLES
                or not isinstance(encoded, str) or not encoded or key_id in keys):
            raise ValueError("invalid trusted-key values")
        try:
            public_key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("invalid trusted-key encoding") from None
        if len(public_key) != 32 or public_key in seen_public_keys:
            raise ValueError("invalid or shared Ed25519 public key")
        keys[key_id] = TrustedVerificationKey(key_id, role, public_key)
        seen_public_keys.add(public_key)
        roles.add(role)
    if roles != SIGNING_ROLES:
        raise ValueError("trusted keys for all independent signing roles are required")
    return keys
