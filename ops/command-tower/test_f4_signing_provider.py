"""Offline integration contract checks; no keys, network or candidate execution."""
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import re
import unittest
from unittest.mock import patch
from f4_signing_provider import (
    ROLE_ENVIRONMENTS, ROLE_REQUEST_FILES, ROLE_SECRET_NAMES,
    SigningCliHold, _require_independent_status_readers,
    build_live_go_execution_check,
    launch_signing_role_from_request_file, load_signing_request_file,
)
from f4_limited_delegation import build_delegation_payload

ROOT = Path(__file__).resolve().parent


class SigningProviderContractTests(unittest.TestCase):
    def test_four_stopped_jobs_use_one_environment_and_only_their_own_secret(self):
        text = (ROOT / "f4-signing-jobs.draft.yml").read_text()
        self.assertNotRegex(text, r"(?m)^on:")
        self.assertNotIn("workflow_dispatch", text)
        self.assertNotIn("workflow_run", text)
        for role, environment in ROLE_ENVIRONMENTS.items():
            # Slice at the next job's exact two-space indentation.
            start = text.index("  " + role + ":\n")
            tail = text[start:]
            match = re.search(r"\n  [a-z_]+:\n", tail)
            part = tail[:match.start()] if match else tail
            self.assertIn("if: ${{ false }}", part)
            self.assertIn("environment: " + environment, part)
            self.assertEqual(re.findall(r"secrets\.([A-Z0-9_]+)", part), [ROLE_SECRET_NAMES[role]])
            self.assertIn("ref: ${{ vars.B09_F4_SIGNER_CODE_SHA }}", part)
            self.assertIn("persist-credentials: false", part)
            self.assertNotIn("download-artifact", part)
            self.assertIn("if-no-files-found: error", part)
        self.assertEqual(len(set(ROLE_SECRET_NAMES.values())), 4)
        for action_sha in re.findall(r"uses: [^@]+@([^\s]+)", text):
            self.assertRegex(action_sha, r"^[0-9a-f]{40}$")

    def test_protected_launcher_forwards_each_role_and_never_saves_held_output(self):
        from f4_signing_provider import SigningCliHold, launch_signing_role

        def sign(**arguments):
            arguments["stdout"].write('{"signed":true}')
            return 0

        with TemporaryDirectory() as directory, \
             patch("f4_signing_provider.build_verification_context") as build, \
             patch("f4_signing_provider.run_trusted_role", side_effect=sign) as run, \
             patch("f4_signing_provider.write_signature_artifact") as save:
            for role, environment in ROLE_ENVIRONMENTS.items():
                with self.subTest(role=role):
                    output = Path(directory) / (role + ".json")
                    args = dict(role=role, environment=environment, request=io.StringIO("{}"),
                                role_keys={role: object()}, encoded_private_key="fixture",
                                output=output, verification_inputs={"cycle": 2})
                    run.side_effect = sign
                    launch_signing_role(**args)
                    build.assert_called_with(role=role, cycle=2)
                    self.assertEqual(run.call_args.kwargs["environment"], environment)
                    self.assertIs(run.call_args.kwargs["template"], build.return_value)
                    save.assert_called_with(output=output, role=role, envelope={"signed": True},
                                            trusted_key=args["role_keys"][role])
                    save.reset_mock()
                    run.side_effect = lambda **_: 78
                    with self.assertRaisesRegex(SigningCliHold, "protected_launcher_signing_held"):
                        launch_signing_role(**args)
                    save.assert_not_called()

    def test_fixed_request_file_is_data_only_bounded_and_role_scoped(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            request = {
                "permit_id": "fixture-permit", "issuer_id": "permit-key",
                "repository_id": 1458303357, "base_sha": "a" * 40,
                "candidate_digest": "b" * 64, "changed_paths": ["ops/command-tower/example.py"],
                "worker_run_id": "123-1-cycle-1",
            }
            target = root / ROLE_REQUEST_FILES["permit_authority"]
            target.write_text(json.dumps(request), encoding="utf-8")
            loaded = json.loads(load_signing_request_file(
                role="permit_authority", input_root=root,
            ))
            self.assertEqual(loaded, request)

            target.write_text(json.dumps({**request, "private_key": "forbidden"}), encoding="utf-8")
            with self.assertRaisesRegex(SigningCliHold, "schema_mismatch"):
                load_signing_request_file(role="permit_authority", input_root=root)

            target.unlink()
            target.symlink_to(root / "missing.json")
            with self.assertRaisesRegex(SigningCliHold, "invalid_or_unavailable|file_unsafe"):
                load_signing_request_file(role="permit_authority", input_root=root)

    def test_request_file_is_forwarded_to_existing_launcher_without_rebuilding_context(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            request = {"witness_id": "witness-key", "permit": {"fixture": True}}
            (root / ROLE_REQUEST_FILES["witness"]).write_text(json.dumps(request), encoding="utf-8")
            template = object()
            saved = {}

            def sign(**arguments):
                saved["request"] = json.load(arguments["stdin"])
                arguments["stdout"].write('{"schema":1,"role":"witness","payload":{},"signature":{"key_id":"w","signature":"AA=="}}')
                return 0

            with patch("f4_signing_provider.build_verification_context", return_value=template) as build, \
                 patch("f4_signing_provider.run_trusted_role", side_effect=sign) as run, \
                 patch("f4_signing_provider.write_signature_artifact", return_value="digest") as save:
                result = launch_signing_role_from_request_file(
                    role="witness", environment="f4-witness", role_keys={"witness": object()},
                    encoded_private_key="test-only", input_root=root,
                    output=root / "witness.json", verification_inputs={"fixture": object()},
                )
            self.assertEqual(result, "digest")
            self.assertEqual(saved["request"], request)
            build.assert_called_once()
            self.assertIs(run.call_args.kwargs["template"], template)
            save.assert_called_once()

    def test_go_revocation_reader_cannot_substitute_for_delegation_status(self):
        reader = lambda *_: {"status": "ACTIVE"}
        with self.assertRaisesRegex(SigningCliHold, "delegation_revocation_reader_must_be_independent"):
            _require_independent_status_readers(
                role="owner_a_delegate", authenticated_execution_check=reader,
                read_authenticated_delegation_status=reader,
            )
        _require_independent_status_readers(
            role="owner_a_delegate", authenticated_execution_check=lambda: True,
            read_authenticated_delegation_status=lambda _scope: {
                "delegation_id": "d", "sequence": 1, "status": "ACTIVE",
            },
        )

    def test_go_check_reads_latest_signed_status_from_existing_cycle_control_journal(self):
        from types import SimpleNamespace
        from f4_cycle_control import F4CycleControlJournal

        journal = object.__new__(F4CycleControlJournal)
        current = {"payload": {"kind": "F4_REVOCATION_STATUS", "sequence": 1}}
        calls = []
        journal.read = lambda: (calls.append(True) or SimpleNamespace(events=(
            {"payload": {"event": "CONTROL_CREATED", "revocation_status": current}},
        )))
        with patch("f4_cycle_runtime.execution_authorization_check", return_value="go-check") as build:
            check = build_live_go_execution_check(
                candidate={"fixture": True}, workspace=Path("/trusted"),
                expected_base_sha="a" * 40, trusted_owner_keys={"owner": "public-key"},
                cycle_control_journal=journal,
            )
        self.assertEqual(check, "go-check")
        reader = build.call_args.kwargs["read_signed_revocation"]
        self.assertIs(reader(), current)
        current = {"payload": {"kind": "F4_REVOCATION_STATUS", "sequence": 2}}
        self.assertIs(reader(), current)
        self.assertEqual(len(calls), 2)

    def test_go_status_reader_holds_when_control_record_is_absent(self):
        from f4_cycle_control import F4CycleControlJournal

        journal = object.__new__(F4CycleControlJournal)
        journal.read = lambda: None
        with patch("f4_cycle_runtime.execution_authorization_check") as build:
            build_live_go_execution_check(
                candidate={}, workspace=Path("/trusted"), expected_base_sha="a" * 40,
                trusted_owner_keys={}, cycle_control_journal=journal,
            )
            reader = build.call_args.kwargs["read_signed_revocation"]
            with self.assertRaisesRegex(SigningCliHold, "state_missing"):
                reader()

    def test_delegation_allowlist_cannot_authorize_signer_or_job_source_changes(self):
        for path in ("f4_signing_cli.py", "f4_signing_provider.py", "f4-signing-jobs.draft.yml"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe_or_noncanonical"):
                build_delegation_payload(
                    delegation_id="provider-boundary-test", execution_revision="a" * 40,
                    cycle_tasks=("task-1", "task-2"),
                    allowed_paths=("ops/command-tower/" + path,),
                    not_before="2026-11-19T00:00:00Z", expires_at="2026-11-20T00:00:00Z",
                    revocation_sequence=1, delegates={},
                )

    def test_job_fragment_declares_role_specific_request_file_contract(self):
        text = (ROOT / "f4-signing-jobs.draft.yml").read_text()
        for role, filename in ROLE_REQUEST_FILES.items():
            self.assertIn(f"{role}: {filename}", text)
        self.assertNotRegex(text, r"(?m)^on:")
        self.assertNotIn("workflow_dispatch", text)
