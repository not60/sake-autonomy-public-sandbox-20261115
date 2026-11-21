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
    def test_fixed_protected_inputs_drive_four_real_test_key_signatures(self):
        """Exercise the real request-file -> trusted-context -> signer path offline."""
        import base64
        import hashlib
        from datetime import datetime, timedelta, timezone
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from attestations import canonical_json, sign_envelope
        from f4_limited_delegation import (
            build_delegation_payload, verify_delegation_contract,
            combine_candidate_authorization_fragments,
        )
        from f4_signing_provider import launch_signing_role_from_request_file
        from publisher_gate import TrustedVerificationKey
        from delegation_revocation import DelegationStatusStore
        from f4_signing_provider import build_delegation_status_reader
        from test_cas_journal import MemoryCasBackend
        from test_publisher_gate_crypto import (
            PublisherGateCryptoTests, REPOSITORY_ID, BASE_SHA, public_bytes,
        )
        from github_worker_provenance import verify_worker_artifact_provenance

        fixture = PublisherGateCryptoTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        params, permit_request, _unused_contract, _unused_status, _unused_evidence, github_read = (
            fixture._trusted_connection_case()
        )
        cycle_tasks = ("fixture-f4-task-cycle1", "fixture-f4-task-cycle2")
        now = datetime.now(timezone.utc)
        def stamp(value):
            return value.isoformat().replace("+00:00", "Z")

        delegate_private = {
            "owner_a_delegate": Ed25519PrivateKey.generate(),
            "owner_b_delegate": Ed25519PrivateKey.generate(),
        }
        private_by_role = {
            "permit_authority": fixture.keys["permit_authority"],
            "witness": fixture.keys["witness"],
            **delegate_private,
        }
        role_keys = {
            role: fixture.trusted_keys[role + "-key"]
            for role in ("permit_authority", "witness", "owner_a", "owner_b")
        }
        for role, private_key in delegate_private.items():
            role_keys[role] = TrustedVerificationKey(
                role + "-provider-integration", role, public_bytes(private_key),
            )
        delegate_entries = {
            role: {
                "key_id": role_keys[role].key_id,
                "public_key": base64.b64encode(role_keys[role].public_key).decode("ascii"),
            }
            for role in delegate_private
        }
        payload = build_delegation_payload(
            delegation_id="provider-four-role-integration",
            execution_revision=BASE_SHA, cycle_tasks=cycle_tasks,
            allowed_paths=("ops/command-tower/candidate.py",),
            not_before=stamp(now - timedelta(minutes=5)),
            expires_at=stamp(now + timedelta(minutes=10)),
            revocation_sequence=1, delegates=delegate_entries,
        )
        delegation = {
            "schema": 1, "state": "SIGNED_DELEGATION", "payload": payload,
            "approvals": {
                owner: sign_envelope(
                    key_id=owner + "-key", private_key=fixture.keys[owner], payload=payload,
                )
                for owner in ("owner_a", "owner_b")
            },
        }
        status_payload = {
            "schema": 1, "kind": "DELEGATION_REVOCATION_STATUS",
            "delegation_id": payload["delegation_id"],
            "contract_sha256": hashlib.sha256(canonical_json(payload)).hexdigest(),
            "repository_id": REPOSITORY_ID, "execution_revision": BASE_SHA,
            "environment": "test", "sequence": 1, "status": "ACTIVE",
            "issued_at": stamp(now - timedelta(minutes=1)),
            "expires_at": stamp(now + timedelta(minutes=10)),
        }
        status_envelope = {
            "payload": status_payload,
            "approvals": {
                owner: {
                    "key_id": owner + "-key",
                    "signature": base64.b64encode(
                        fixture.keys[owner].sign(canonical_json(status_payload))
                    ).decode("ascii"),
                }
                for owner in ("owner_a", "owner_b")
            },
        }
        status_backend = MemoryCasBackend()
        status_store = DelegationStatusStore(
            status_backend, trusted_owner_keys=fixture.trusted_keys, environment="test",
        )
        status_store.update(status_envelope, now=now)
        read_status = build_delegation_status_reader(
            backend=status_backend, trusted_owner_keys=fixture.trusted_keys,
            environment="test", delegation_payload=payload,
        )
        status = read_status(payload)

        def auth_check():
            return True  # isolated fixture only; not a live GO or revocation source

        def delegation_reader(scope):
            if scope.get("delegation_id") != status["delegation_id"]:
                return None
            return read_status(scope)

        def encoded_key(role):
            return base64.b64encode(private_by_role[role].private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )).decode("ascii")

        verification_inputs = {
            **params,
            "cycle_tasks": cycle_tasks,
            "authenticated_execution_check": auth_check,
            "read_authenticated_delegation_status": delegation_reader,
            "read_verified_cycle1_audit_digest": None,
        }

        with TemporaryDirectory() as directory, \
                patch("github_worker_provenance._get_json", side_effect=github_read):
            root = Path(directory)

            def launch(role, request, *, permit=None, witness=None):
                request_path = root / ROLE_REQUEST_FILES[role]
                request_path.write_text(json.dumps(request), encoding="utf-8")
                scoped_inputs = {**verification_inputs, "permit": permit, "witness": witness}
                output = root / (role + ".json")
                launch_signing_role_from_request_file(
                    role=role, environment=ROLE_ENVIRONMENTS[role], role_keys=role_keys,
                    encoded_private_key=encoded_key(role), input_root=root, output=output,
                    verification_inputs=scoped_inputs,
                )
                return json.loads(output.read_text(encoding="utf-8"))

            permit = launch("permit_authority", permit_request)
            witness = launch(
                "witness", {"witness_id": "witness-key", "permit": permit}, permit=permit,
            )

            material = params["gate"].verify_signing_material(
                artifact_root=params["artifact_root"], manifest=params["manifest"],
                codex_output_file=params["codex_output_file"],
            )
            proof = verify_worker_artifact_provenance(
                params["manifest"], expected_run_id=params["expected_run_id"],
                expected_base_sha=params["gate"]._base_sha,
                expected_execution_sha=params["expected_execution_sha"], expected_cycle=1,
                bearer_token=params["github_read_token"],
            )
            snapshot = params["journal"].snapshot()
            evidence = {
                "repository_id": material["repository_id"],
                "execution_revision": BASE_SHA,
                "task_id": cycle_tasks[0], "cycle_number": 1,
                "run_id": material["worker_run_id"],
                "changed_paths": material["changed_paths"],
                "file_sha256": material["files"],
                "candidate_digest": material["candidate_digest"],
                "permit_digest": hashlib.sha256(canonical_json(permit["payload"])).hexdigest(),
                "witness_digest": hashlib.sha256(canonical_json(witness)).hexdigest(),
                "cas_revision": snapshot.sequence, "cas_head_sha256": snapshot.head_sha256,
                "worker_provenance_digest": hashlib.sha256(canonical_json(proof)).hexdigest(),
                "cycle1_audit_digest": None,
                "issued_at": stamp(now - timedelta(minutes=1)),
                "expires_at": stamp(now + timedelta(minutes=5)),
            }
            delegate_request = {
                "delegation_envelope": delegation,
                "revocation_status": status,
                "evidence": evidence,
            }
            fragment_a = launch("owner_a_delegate", delegate_request, permit=permit, witness=witness)
            fragment_b = launch("owner_b_delegate", delegate_request, permit=permit, witness=witness)

            verified_delegation = verify_delegation_contract(
                envelope=delegation, trusted_owner_keys=fixture.trusted_keys,
                expected_execution_revision=BASE_SHA, expected_cycle_tasks=cycle_tasks,
                revocation_status=status,
                verify_revocation_status=lambda observed, scope: observed == read_status(scope),
                now=now,
            )
            authorization = combine_candidate_authorization_fragments(
                delegation=verified_delegation, fragments=(fragment_a, fragment_b),
            )
            self.assertEqual(set(authorization["signatures"]), {
                "owner_a_delegate", "owner_b_delegate",
            })
            self.assertEqual(params["journal"].snapshot().sequence, 1)
            self.assertEqual(permit["key_id"], role_keys["permit_authority"].key_id)
            self.assertEqual(witness["key_id"], role_keys["witness"].key_id)
            self.assertNotEqual(permit["key_id"], witness["key_id"])

    def test_cycle2_reader_uses_existing_archive_verifier_and_returns_sealed_digest(self):
        import base64
        import hashlib
        from zipfile import ZipFile
        from f4_auditor_artifact import create_cycle2_artifact
        from f4_cycle_control import (
            AUDIT_WORKFLOW_PATH, CYCLE2_AUDIT_ARTIFACT_NAME,
            GitHubArtifactProvenanceReader, build_cycle1_auditor_artifact,
        )
        from f4_signing_provider import build_cycle2_audit_digest_reader
        from test_f4_cycle_control import F4CycleControlTests, BASE_SHA, NOW

        fixture = F4CycleControlTests()
        fixture.setUp()
        # setUp() is called directly here, so unittest will not automatically
        # run this fixture's registered cleanup callbacks (including patches).
        self.addCleanup(fixture.tearDown)
        self.addCleanup(fixture.doCleanups)
        cycle1_run, cycle2_run = "101-1-cycle-1", "102-1-cycle-2"
        cycle1_source = cycle2_source = "b" * 40
        state1 = fixture.control.claim_cycle(
            candidate=fixture.candidate, go=fixture.go, cycle_number=1,
            run_id=cycle1_run, source_commit_sha=cycle1_source, now=NOW,
        )
        cycle1_payload = dict(fixture._artifact()["payload"])
        cycle1_payload.update(
            worker_run_id=cycle1_run, auditor_run_id="201:1:auditor",
            workflow_run_id="201", source_commit_sha=cycle1_source,
        )
        cycle1_envelope = build_cycle1_auditor_artifact(
            payload=cycle1_payload, key_id=fixture.auditor_key.key_id,
            private_key=type("FixtureSigner", (), {
                "sign": lambda _self, message: fixture.auditor_test_keys.sign("witness", message),
            })(),
        )
        claim1 = fixture._read_claim(1, cycle1_run, state1)
        fixture.control.record_cycle1_auditor_pass(
            candidate=fixture.candidate, go=fixture.go, artifact=cycle1_envelope,
            verify_github_artifact=fixture._provenance, now=NOW,
        )
        cycle1_fields = (
            "worker_run_id", "go_sha256", "pr_number", "pr_head_sha", "pr_base_sha",
            "pr_state", "pr_is_draft", "pr_merged", "readonly_ci_run_id",
            "readonly_ci_conclusion", "permit_id", "candidate_digest", "witness_digest",
            "journal_revision", "journal_head_sha256",
        )
        previous = fixture.control.verify_stage_audit(
            candidate=fixture.candidate, go=fixture.go, claim=claim1,
            artifact=cycle1_envelope, previous=None,
            verify_github_artifact=fixture._provenance,
            read_verified_publication=lambda *_: {
                key: cycle1_payload[key] for key in cycle1_fields
            }, now=NOW,
        )

        state2 = fixture.control.claim_cycle(
            candidate=fixture.candidate, go=fixture.go, cycle_number=2,
            run_id=cycle2_run, source_commit_sha=cycle2_source,
            cycle1_auditor_artifact=cycle1_envelope,
            verify_github_artifact=fixture._provenance, now=NOW,
        )
        claim2 = fixture._read_claim(2, cycle2_run, state2)
        publication = {
            "worker_run_id": cycle2_run, "go_sha256": claim2.go_sha256,
            "pr_number": 1, "pr_head_sha": cycle2_source, "pr_base_sha": BASE_SHA,
            "pr_state": "open", "pr_is_draft": True, "pr_merged": False,
            "readonly_ci_run_id": "ci-102", "readonly_ci_conclusion": "success",
            "permit_id": "permit-cycle2", "candidate_digest": "c" * 64,
            "witness_digest": "d" * 64, "journal_revision": 4,
            "journal_head_sha256": "e" * 64, "permit_sha256": "f" * 64,
        }

        with TemporaryDirectory() as directory:
            root = Path(directory)
            envelope_path = root / "auditor-envelope.json"
            archive_path = root / "cycle2.zip"
            owner_keys = {"keys": [
                {"key_id": key.key_id, "role": key.role,
                 "public_key": base64.b64encode(key.public_key).decode("ascii")}
                for key in fixture.owner_keys.values()
            ]}
            auditor_key = {
                "key_id": fixture.auditor_key.key_id, "role": "auditor",
                "public_key": base64.b64encode(fixture.auditor_key.public_key).decode("ascii"),
            }
            signer = type("FixtureCycle2Signer", (), {
                "sign": lambda _self, message: fixture.auditor_test_keys.sign("witness", message),
            })()
            with patch("f4_auditor_artifact._SignerProxy", return_value=signer):
                create_cycle2_artifact(
                    claim=claim2, previous=previous,
                    publication_reader=lambda *_: dict(publication), output=envelope_path,
                    candidate=fixture.candidate, workspace=fixture.root,
                    expected_base_sha=BASE_SHA, trusted_keys=owner_keys,
                    auditor_key_document=auditor_key, revocation_envelope=fixture.revocation,
                    workflow_run_id="202", run_attempt=1,
                    source_commit_sha=cycle2_source, now=NOW,
                )
            with ZipFile(archive_path, "w") as archive:
                archive.write(envelope_path, "auditor-envelope.json")
            archive_bytes = archive_path.read_bytes()
            archive_digest = "sha256:" + hashlib.sha256(archive_bytes).hexdigest()
            reader = GitHubArtifactProvenanceReader(bearer_token="test-only")

            def github_fixture(path):
                if path.endswith("/artifacts"):
                    return {"artifacts": [{
                        "id": 9002, "name": CYCLE2_AUDIT_ARTIFACT_NAME,
                        "expired": False, "workflow_run": {"id": 202},
                        "digest": archive_digest,
                    }]}
                return {
                    "id": 202, "run_attempt": 1, "path": AUDIT_WORKFLOW_PATH,
                    "head_sha": cycle2_source, "status": "completed",
                    "conclusion": "success", "repository": {"id": 1458303357},
                }

            with patch.object(reader, "_get_json", side_effect=github_fixture), \
                 patch("f4_cycle_control._now", return_value=NOW):
                read = build_cycle2_audit_digest_reader(
                    journal=fixture.control, reader=reader, archive_path=archive_path,
                    run_id="202", attempt=1, candidate=fixture.candidate, go=fixture.go,
                    claim=claim2, previous=previous,
                    publication_reader=lambda *_: {
                        key: publication[key] for key in (
                            "worker_run_id", "go_sha256", "pr_number", "pr_head_sha",
                            "pr_base_sha", "pr_state", "pr_is_draft", "pr_merged",
                            "readonly_ci_run_id", "readonly_ci_conclusion", "permit_id",
                            "candidate_digest", "witness_digest", "journal_revision",
                            "journal_head_sha256", "permit_sha256",
                        )
                    },
                )
                self.assertRegex(read(), r"^[a-f0-9]{64}$")
                tampered = root / "tampered.zip"
                tampered.write_bytes(archive_bytes + b"x")
                with self.assertRaisesRegex(SigningCliHold, "cycle2_audit_verification_failed"):
                    build_cycle2_audit_digest_reader(
                        journal=fixture.control, reader=reader, archive_path=tampered,
                        run_id="202", attempt=1, candidate=fixture.candidate, go=fixture.go,
                        claim=claim2, previous=previous,
                        publication_reader=lambda *_: publication,
                    )

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
