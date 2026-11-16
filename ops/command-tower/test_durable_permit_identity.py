"""Focused restart test for durable permit-ID uniqueness."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import textwrap
import tempfile
import unittest

from durable_store import DurableStore
from isolated_runtime import IsolatedRuntime, Principal, Role


PATHS = ("ops/command-tower/candidate.py",)


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


class DurablePermitIdentityTests(unittest.TestCase):
    def test_permit_id_cannot_be_reissued_for_another_candidate_in_new_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "runtime.sqlite3"
            first_store = DurableStore(database)
            first_runtime = runtime(first_store)
            original = first_runtime.create_candidate(
                first_runtime.worker, branch="feature/first", paths=PATHS,
                content_digest="candidate-one",
            )
            first_runtime.issue_permit(
                first_runtime.permit_authority, original, permit_id="permit-reused",
            )
            changed = first_runtime.create_candidate(
                first_runtime.worker, branch="feature/second", paths=PATHS,
                content_digest="candidate-two",
            )
            self.assertNotEqual(original.digest(), changed.digest())
            first_store.close_cleanly()
            first_store.close()

            child = textwrap.dedent("""
                import sys
                from durable_store import DurableStore
                from isolated_runtime import IsolatedRuntime, Principal, Role, SafeStop
                path = sys.argv[1]
                paths = ("ops/command-tower/candidate.py",)
                store = DurableStore(path)
                runtime = IsolatedRuntime(
                    worker=Principal("worker-1", Role.WORKER),
                    publisher=Principal("publisher-1", Role.PUBLISHER),
                    auditor=Principal("auditor-1", Role.AUDITOR),
                    witness=Principal("witness-1", Role.WITNESS),
                    permit_authority=Principal("authority-1", Role.PERMIT_AUTHORITY),
                    allowed_paths=paths, durable_store=store,
                )
                candidate = runtime.create_candidate(
                    runtime.worker, branch="feature/second", paths=paths,
                    content_digest="candidate-two",
                )
                try:
                    runtime.issue_permit(runtime.permit_authority, candidate,
                                         permit_id="permit-reused")
                except SafeStop as exc:
                    if str(exc) != "permit_id_reuse" or store.state != "SAFE_STOPPED":
                        raise SystemExit(3)
                    print("SAFE_STOPPED:permit_id_reuse")
                else:
                    raise SystemExit(4)
                store.close()
            """)
            child_result = subprocess.run(
                [sys.executable, "-c", child, str(database)],
                cwd=Path(__file__).parent,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(child_result.returncode, 0, child_result.stderr)
            self.assertEqual(child_result.stdout.strip(), "SAFE_STOPPED:permit_id_reuse")

            recovered = DurableStore(database)
            self.assertEqual(recovered.state, "SAFE_STOPPED")
            self.assertEqual(recovered.stop_reason, "permit_id_reuse")
            self.assertTrue(recovered.journal.verify())
            row = recovered._connection.execute(
                "SELECT candidate_digest FROM issued_permit_ids WHERE permit_id=?",
                ("permit-reused",),
            ).fetchone()
            self.assertEqual(row[0], original.digest())
            recovered.close()


if __name__ == "__main__":
    unittest.main()
