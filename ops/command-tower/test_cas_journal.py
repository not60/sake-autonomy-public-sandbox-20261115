"""Offline CAS tests using two clients and one shared conditional store."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from cas_journal import CasConflict, CasHold, CasValue, HttpsCasBackend, PermitCasJournal


class MemoryCasBackend:
    def __init__(self) -> None:
        self.objects: dict[str, CasValue] = {}
        self.revision = 0

    def read(self, key: str) -> CasValue | None:
        return self.objects.get(key)

    def compare_and_swap(self, key: str, version: str | None, body: bytes) -> str:
        current = self.objects.get(key)
        if (current is None) != (version is None):
            raise CasConflict("cas_version_conflict")
        if current is not None and current.version != version:
            raise CasConflict("cas_version_conflict")
        self.revision += 1
        next_version = str(self.revision)
        self.objects[key] = CasValue(body, next_version)
        return next_version


class PermitCasJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = MemoryCasBackend()
        self.authority = PermitCasJournal(self.backend, repository_id=1458303357)
        self.publisher = PermitCasJournal(self.backend, repository_id=1458303357)

    def test_cross_client_issue_witness_parent_and_single_consumption(self) -> None:
        issued = self.authority.record_issuance(
            permit_id="permit-1", candidate_digest="c" * 64,
            permit_digest="d" * 64, worker_run_id="run-1",
        )
        self.assertEqual(issued.sequence, 1)
        consumed = self.publisher.record_consumption(
            permit_id="permit-1", candidate_digest="c" * 64,
            permit_digest="d" * 64, witness_digest="e" * 64,
            worker_run_id="run-1", expected_parent=issued.head_sha256,
        )
        self.assertEqual(consumed.sequence, 2)
        self.assertEqual(self.authority.snapshot().head_sha256, consumed.head_sha256)
        with self.assertRaisesRegex(CasHold, "permit_id_reused_across_runs"):
            self.authority.record_issuance(
                permit_id="permit-1", candidate_digest="f" * 64,
                permit_digest="1" * 64, worker_run_id="run-2",
            )
        with self.assertRaisesRegex(CasHold, "permit_id_already_consumed_across_runs"):
            self.publisher.record_consumption(
                permit_id="permit-1", candidate_digest="c" * 64,
                permit_digest="d" * 64, witness_digest="e" * 64,
                worker_run_id="run-1", expected_parent=consumed.head_sha256,
            )

    def test_stale_witness_parent_and_unissued_permit_hold(self) -> None:
        self.authority.record_issuance(
            permit_id="permit-2", candidate_digest="c" * 64,
            permit_digest="d" * 64, worker_run_id="run-2",
        )
        with self.assertRaisesRegex(CasConflict, "witness_journal_parent_mismatch"):
            self.publisher.record_consumption(
                permit_id="permit-2", candidate_digest="c" * 64,
                permit_digest="d" * 64, witness_digest="e" * 64,
                worker_run_id="run-2", expected_parent="0" * 64,
            )
        with self.assertRaisesRegex(CasHold, "permit_issuance_not_found_or_scope_mismatch"):
            self.publisher.record_consumption(
                permit_id="missing", candidate_digest="c" * 64,
                permit_digest="d" * 64, witness_digest="e" * 64,
                worker_run_id="run-2", expected_parent=self.authority.snapshot().head_sha256,
            )

    def test_journal_hash_chain_tamper_holds(self) -> None:
        issued = self.authority.record_issuance(
            permit_id="permit-3", candidate_digest="c" * 64,
            permit_digest="d" * 64, worker_run_id="run-3",
        )
        key = self.authority._key
        stored = self.backend.read(key)
        document = json.loads(stored.body)
        document["events"][0]["payload"]["candidate_digest"] = "tampered"
        self.backend.revision += 1
        self.backend.objects[key] = CasValue(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
            str(self.backend.revision),
        )
        with self.assertRaisesRegex(CasHold, "cas_journal_chain_invalid"):
            self.publisher.snapshot()

    def test_http_backend_uses_conditional_https_put_without_network(self) -> None:
        class Response:
            headers = {"ETag": '"etag-1"'}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return b"{}"

        captured = []

        def fake_urlopen(request, timeout):
            captured.append((request, timeout))
            return Response()

        backend = HttpsCasBackend(endpoint="https://cas.example.invalid/v1", bearer_token="test-only")
        with patch("cas_journal.urlopen", side_effect=fake_urlopen):
            version = backend.compare_and_swap("repositories/1458303357/journal.json", None, b"{}")
        request, timeout = captured[0]
        self.assertEqual(version, '"etag-1"')
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(request.get_header("If-none-match"), "*")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-only")
        self.assertEqual(timeout, 5.0)


if __name__ == "__main__":
    unittest.main()
