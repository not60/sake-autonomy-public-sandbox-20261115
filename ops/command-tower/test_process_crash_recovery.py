"""Real child-process crash/recovery tests for the local SQLite sandbox store."""
from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from durable_store import DurableStore
from isolated_runtime import IsolatedRuntime, Principal, Role, SafeStop


PATHS = ("ops/command-tower/isolated_runtime.py", "ops/command-tower/test_isolated_runtime.py")


def _runtime(store: DurableStore) -> IsolatedRuntime:
    return IsolatedRuntime(
        worker=Principal("worker-1", Role.WORKER),
        publisher=Principal("publisher-1", Role.PUBLISHER),
        auditor=Principal("auditor-1", Role.AUDITOR),
        witness=Principal("witness-1", Role.WITNESS),
        permit_authority=Principal("authority-1", Role.PERMIT_AUTHORITY),
        allowed_paths=PATHS,
        durable_store=store,
    )


def _child_main(mode: str, database: str) -> int:
    store = DurableStore(database)
    runtime = _runtime(store)
    if mode == "recover":
        events = [entry.event for entry in runtime.journal.entries]
        consumed_count = store._connection.execute(
            "SELECT count(*) FROM consumed_permits"
        ).fetchone()[0]
        blocked = False
        try:
            runtime.create_candidate(runtime.worker, branch="feature/after-recovery",
                                     paths=PATHS, content_digest="must-not-run")
        except SafeStop:
            blocked = True
        print(json.dumps({
            "state": store.state,
            "stop_reason": store.stop_reason,
            "journal_valid": runtime.journal.verify(),
            "events": events,
            "consumed_count": consumed_count,
            "resume_blocked": blocked,
        }, sort_keys=True), flush=True)
        store.close()
        return 0

    candidate = runtime.create_candidate(
        runtime.worker, branch="feature/crash-proof", paths=PATHS,
        content_digest="nonsecret-test-fixture",
    )
    permit = runtime.issue_permit(runtime.permit_authority, candidate, permit_id="process-permit-1")
    attestation = runtime.witness_permit(runtime.witness, permit)

    if mode == "commit-and-wait":
        runtime.prepare_publication(runtime.publisher, candidate, permit, attestation)
        print("COMMITTED", flush=True)
        while True:
            signal.pause()
    elif mode == "crash-inside-transaction":
        store._connection.create_function(
            "crash_after_consumed_insert", 0,
            lambda: os.kill(os.getpid(), signal.SIGKILL),
        )
        runtime.prepare_publication(runtime.publisher, candidate, permit, attestation)
        print("UNEXPECTED_RETURN", flush=True)
        return 3
    else:
        return 2


def _wait_for_line(process: subprocess.Popen[str], timeout: float = 10.0) -> str:
    selector = selectors.DefaultSelector()
    assert process.stdout is not None
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise AssertionError(f"child did not signal readiness; exit={process.poll()}")
        return process.stdout.readline().strip()
    finally:
        selector.close()


def _start_child(mode: str, database: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--child", mode, str(database)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, close_fds=True,
    )


def _recover_in_new_child(database: Path) -> dict[str, object]:
    process = _start_child("recover", database)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()  # This Popen owns the exact test child PID.
        process.wait(timeout=5)
        raise AssertionError("recovery child did not exit")
    if process.returncode != 0:
        raise AssertionError(f"recovery child failed with status {process.returncode}: {stderr}")
    return json.loads(stdout.strip().splitlines()[-1])


class ProcessCrashRecoveryTests(unittest.TestCase):
    def test_committed_permit_and_plan_survive_crash_then_recover_stopped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b08-crash-commit-") as raw_directory:
            directory = Path(raw_directory)
            database = directory / "runtime.sqlite3"
            process = _start_child("commit-and-wait", database)
            try:
                self.assertEqual(_wait_for_line(process), "COMMITTED")
                self.assertIsNone(process.poll(), "test child exited before forced termination")
                target_pid = process.pid
                process.send_signal(signal.SIGKILL)
                self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
                self.assertEqual(target_pid, process.pid)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL)
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

            recovered = _recover_in_new_child(database)
            self.assertEqual(recovered["state"], "SAFE_STOPPED")
            self.assertEqual(recovered["stop_reason"], "unclean_restart")
            self.assertTrue(recovered["journal_valid"])
            self.assertTrue(recovered["resume_blocked"])
            self.assertEqual(recovered["consumed_count"], 1)
            self.assertIn("PERMIT_CONSUMED", recovered["events"])
            self.assertIn("LOCAL_PLAN_PREPARED", recovered["events"])
            self.assertEqual(recovered["events"].count("PERMIT_CONSUMED"), 1)
            self.assertEqual(recovered["events"].count("LOCAL_PLAN_PREPARED"), 1)
        self.assertFalse(directory.exists(), "temporary database directory leaked")

    def test_sigkill_inside_transaction_rolls_back_both_events_and_consumption(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b08-crash-rollback-") as raw_directory:
            directory = Path(raw_directory)
            database = directory / "runtime.sqlite3"
            schema = sqlite3.connect(database)
            schema.executescript(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "CREATE TABLE journal (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, "
                "payload TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);"
                "CREATE TABLE consumed_permits (permit_digest TEXT PRIMARY KEY, "
                "consumed_at_entry INTEGER NOT NULL);"
            )
            schema.execute(
                "CREATE TRIGGER crash_between_consume_and_plan "
                "AFTER INSERT ON consumed_permits "
                "BEGIN SELECT crash_after_consumed_insert(); END"
            )
            schema.commit()
            schema.close()

            process = _start_child("crash-inside-transaction", database)
            try:
                self.assertEqual(process.wait(timeout=10), -signal.SIGKILL)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL)
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

            recovered = _recover_in_new_child(database)
            self.assertEqual(recovered["state"], "SAFE_STOPPED")
            self.assertEqual(recovered["stop_reason"], "unclean_restart")
            self.assertTrue(recovered["journal_valid"])
            self.assertTrue(recovered["resume_blocked"])
            self.assertEqual(recovered["consumed_count"], 0)
            self.assertNotIn("PERMIT_CONSUMED", recovered["events"])
            self.assertNotIn("LOCAL_PLAN_PREPARED", recovered["events"])
        self.assertFalse(directory.exists(), "temporary database directory leaked")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    unittest.main()
