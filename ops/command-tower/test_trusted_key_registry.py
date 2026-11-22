"""Focused fail-closed tests for the Publisher's public trust-key registry."""
from __future__ import annotations

import base64
from pathlib import Path
import unittest
from typing import Optional, Tuple

from trusted_key_registry import load_trusted_verification_keys


ROLES = ("permit_authority", "witness", "owner_a", "owner_b")


def document(public_keys: Optional[Tuple[bytes, ...]] = None) -> dict[str, object]:
    values = public_keys or tuple(bytes([index]) * 32 for index in range(1, 5))
    return {"keys": [
        {"key_id": f"test-{role}", "role": role,
         "public_key": base64.b64encode(values[index]).decode("ascii")}
        for index, role in enumerate(ROLES)
    ]}


class TrustedKeyRegistryTests(unittest.TestCase):
    def test_loads_four_distinct_role_keys(self) -> None:
        keys = load_trusted_verification_keys(document())
        self.assertEqual({key.role for key in keys.values()}, set(ROLES))
        self.assertEqual(len({key.public_key for key in keys.values()}), 4)

    def test_empty_or_incomplete_registry_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid or empty"):
            load_trusted_verification_keys({"keys": []})
        with self.assertRaisesRegex(ValueError, "all independent"):
            load_trusted_verification_keys({"keys": document()["keys"][:3]})

    def test_shared_public_key_is_rejected(self) -> None:
        shared = bytes([7]) * 32
        with self.assertRaisesRegex(ValueError, "shared Ed25519"):
            load_trusted_verification_keys(document((shared, shared, bytes([8]) * 32,
                                                       bytes([9]) * 32)))

    def test_wrong_key_size_and_unknown_role_are_rejected(self) -> None:
        entries = document()["keys"]
        assert isinstance(entries, list)
        short_key = [dict(item) for item in entries]
        short_key[0]["public_key"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(ValueError, "invalid or shared"):
            load_trusted_verification_keys({"keys": short_key})
        unknown_role = [dict(item) for item in entries]
        unknown_role[0]["role"] = "publisher"
        with self.assertRaisesRegex(ValueError, "invalid trusted-key values"):
            load_trusted_verification_keys({"keys": unknown_role})

    def test_publisher_cli_uses_registry_loader_for_gate_keys(self) -> None:
        source = (Path(__file__).with_name("publisher_gate.py")).read_text(encoding="utf-8")
        self.assertIn(
            "from trusted_key_registry import TrustedVerificationKey, load_trusted_verification_keys",
            source,
        )
        self.assertIn("keys = load_trusted_verification_keys(key_document)", source)
        self.assertIn("trusted_keys=keys", source)


if __name__ == "__main__":
    unittest.main()
