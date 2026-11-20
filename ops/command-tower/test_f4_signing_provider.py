"""Offline integration contract checks; no keys, network or candidate execution."""
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import re
import unittest
from unittest.mock import patch
from f4_signing_provider import ROLE_ENVIRONMENTS, ROLE_SECRET_NAMES
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
