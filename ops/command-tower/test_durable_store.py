"""Focused durability and crash-recovery tests for the isolated runtime."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from durable_store import DurableStore, PermitAlreadyConsumed
from isolated_runtime import IsolatedRuntime, Principal, Role, SafeStop


PATHS = ("ops/command-tower/isolated_runtime.py", "ops/command-tower/test_isolated_runtime.py")


def runtime(store: DurableStore) -> IsolatedRuntime:
    return IsolatedRuntime(
        worker=Principal("worker-1", Role.WORKER),
        publisher=Principal("publisher-1", Role.PUBLISHER),
        auditor=Principal("auditor-1", Role.AUDITOR),
        witness=Principal("witness-1", Role.WITNESS),
        permit_authority=Principal("authority-1", Role.PERMIT_AUTHORITY),
        allowed_paths=PATHS,
        durable_store=store,
    )


class DurableStoreTests(unittest.TestCase):
    def test_runtime_journal_persists_and_permit_replay_stops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = DurableStore(Path(directory) / "runtime.sqlite3")
            rt = runtime(store)
            candidate = rt.create_candidate(rt.worker, branch="feature/durable", paths=PATHS,
                                            content_digest="fixture-sha")
            permit = rt.issue_permit(rt.permit_authority, candidate, permit_id="durable-1")
            attestation = rt.witness_permit(rt.witness, permit)
            rt.prepare_publication(rt.publisher, candidate, permit, attestation)
            self.assertTrue(rt.journal.verify())
            events = [entry.event for entry in rt.journal.entries]
            self.assertIn("PERMIT_CONSUMED", events)
            self.assertIn("LOCAL_PLAN_PREPARED", events)
            with self.assertRaises(SafeStop):
                rt.prepare_publication(rt.publisher, candidate, permit, attestation)
            self.assertEqual(store.state, "SAFE_STOPPED")
            self.assertEqual(rt.journal.entries[-1].event, "SAFE_STOP")
            store.close()

    def test_unclean_restart_enters_persistent_safe_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite3"
            first = DurableStore(path)
            first.journal.append("LOCAL_PROGRESS", item="before-interruption")
            first.close()  # Simulates process loss without a clean-close marker.

            recovered = DurableStore(path)
            self.assertEqual(recovered.state, "SAFE_STOPPED")
            self.assertEqual(recovered.stop_reason, "unclean_restart")
            self.assertEqual(recovered.journal.entries[-1].event, "SAFE_STOP")
            self.assertTrue(recovered.journal.verify())
            recovered.close()

    def test_permit_consumption_is_durable_and_unique(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite3"
            store = DurableStore(path)
            store.consume_permit_and_record("permit-digest", plan_digest="plan", state="DRAFT_HOLD")
            with self.assertRaises(PermitAlreadyConsumed):
                store.consume_permit_and_record("permit-digest", plan_digest="plan", state="DRAFT_HOLD")
            self.assertTrue(store.journal.verify())
            store.close()

    def test_runtime_refuses_to_start_after_unclean_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite3"
            first = DurableStore(path)
            first.close()
            recovered = DurableStore(path)
            rt = runtime(recovered)
            self.assertEqual(rt.state, "SAFE_STOPPED")
            with self.assertRaises(SafeStop):
                rt.create_candidate(rt.worker, branch="feature/restart", paths=PATHS,
                                    content_digest="fixture-sha")
            recovered.close()

    def test_clean_restart_preserves_consumed_permit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite3"
            first = DurableStore(path)
            first.consume_permit_and_record("used-digest", plan_digest="plan", state="DRAFT_HOLD")
            first.close_cleanly()
            first.close()

            resumed = DurableStore(path)
            with self.assertRaises(PermitAlreadyConsumed):
                resumed.consume_permit_and_record("used-digest", plan_digest="plan", state="DRAFT_HOLD")
            self.assertTrue(resumed.journal.verify())
            resumed.close()


if __name__ == "__main__":
    unittest.main()
