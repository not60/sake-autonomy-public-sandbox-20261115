"""Local-only consistency checks for unsigned public runner candidates."""
from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).parent
FILES = {
    "policy": ROOT / "policy-public-runner.draft.json",
    "runtime": ROOT / "runtime-public-runner.draft.json",
    "backlog": ROOT / "backlog-public-runner.draft.json",
}
REPOSITORY = "not60/sake-autonomy-public-sandbox-20261115"
REPOSITORY_ID = 1458303357


def load_candidates() -> dict[str, dict[str, object]]:
    return {name: json.loads(path.read_text(encoding="utf-8")) for name, path in FILES.items()}


class PublicRunnerDraftContractTests(unittest.TestCase):
    def test_candidates_are_unsigned_and_fail_closed(self) -> None:
        candidates = load_candidates()
        for name, candidate in candidates.items():
            with self.subTest(candidate=name):
                self.assertEqual(candidate["state"], "DRAFT_HOLD")
                self.assertIs(candidate["signed"], False)
                self.assertIsNone(candidate["signature"])
                if name == "policy":
                    self.assertEqual(candidate["repository"]["id"], REPOSITORY_ID)
                    self.assertEqual(candidate["repository"]["full_name"], REPOSITORY)
                else:
                    self.assertEqual(candidate["repository_id"], REPOSITORY_ID)
                    self.assertEqual(candidate["repository"], REPOSITORY)
        policy, runtime, backlog = candidates["policy"], candidates["runtime"], candidates["backlog"]
        self.assertIs(policy["execution"]["enabled"], False)
        self.assertIs(policy["execution"]["formal_worker_enabled"], False)
        self.assertIs(policy["execution"]["external_write_enabled"], False)
        self.assertIs(runtime["enabled"], False)
        self.assertEqual(backlog["status"]["stage2"], "NO_GO")
        self.assertEqual(backlog["status"]["worker_success_count"], "0/2")

    def test_legacy_preflight_authority_is_not_reused(self) -> None:
        legacy = load_candidates()["policy"]["legacy_source"]
        self.assertEqual(legacy["repository"], "not60/sake-tasting-log")
        self.assertEqual(legacy["source_sha"], "34fb092782af9dcd86577f3425820157c183d6a3")
        self.assertEqual(legacy["policy_mode"], "PREFLIGHT_ONLY")
        self.assertIs(legacy["authorization_reused"], False)

    def test_role_permissions_are_separated_and_minimal(self) -> None:
        roles = {role["role"]: role for role in load_candidates()["policy"]["roles"]}
        self.assertEqual(set(roles), {"worker", "publisher", "auditor"})
        self.assertEqual(len({role["job_id"] for role in roles.values()}), 3)
        self.assertEqual(roles["worker"]["github_permissions"], {
            "contents": "read", "pull_requests": "none", "actions": "none"
        })
        self.assertEqual(roles["publisher"]["github_permissions"], {
            "contents": "read", "pull_requests": "write", "actions": "none"
        })
        publisher_credential = roles["publisher"]["credential_candidate"]
        self.assertEqual(publisher_credential["required_permissions"], {
            "contents": "write", "pull_requests": "write", "actions": "none"
        })
        self.assertEqual(publisher_credential["default_github_token_permissions"], {
            "contents": "read", "pull_requests": "write", "actions": "none"
        })
        self.assertIs(publisher_credential["default_github_token_expanded"], False)
        self.assertEqual(publisher_credential["status"], "NOT_CONFIGURED_NOT_CREATED")
        self.assertEqual(roles["auditor"]["github_permissions"], {
            "contents": "read", "pull_requests": "read", "actions": "read"
        })
        self.assertEqual(roles["auditor"]["secrets"], ["B09_CAS_READ_TOKEN"])
        self.assertEqual(roles["auditor"]["write_permissions"], [])
        self.assertEqual(roles["publisher"]["credential_candidate"]["status"], "NOT_CONFIGURED_NOT_CREATED")
        self.assertEqual(roles["auditor"]["credential_candidate"]["worker_or_publisher_credentials"], "NONE")
        self.assertNotIn("allow_users", roles["worker"]["codex_action"])
        self.assertIn("no_bypass", roles["worker"]["codex_action"]["write_access_guard"])

    def test_artifact_gate_binds_digests_and_remains_held_without_signer(self) -> None:
        policy = load_candidates()["policy"]
        gate = policy["artifact_gate"]
        required = set(gate["required_manifest_fields"])
        self.assertTrue({"repository_id", "base_sha", "worker_run_id", "codex_output_sha256",
                         "candidate_digest", "changed_paths"}.issubset(required))
        self.assertTrue(gate["fail_closed"])
        self.assertEqual(gate["manifest_schema"], 2)
        self.assertEqual(gate["changed_paths_source"], "actual_git_delta_against_exact_base_sha")
        self.assertEqual(gate["permit_witness_signature_scheme"], "Ed25519_DISTINCT_ROLE_KEYS")
        runtime = load_candidates()["runtime"]
        self.assertEqual(runtime["witness"]["journal_parent_binding"],
                         "CAS_head_sha256_after_permit_issuance")
        self.assertFalse(runtime["local_followup"]["external_cas"]["endpoint_configured"])
        self.assertEqual(runtime["local_followup"]["external_cas"]["legacy_supabase_write"], False)
        self.assertEqual(runtime["journal"]["cross_run_retention_and_replay_protection"],
                         "HOLD_UNRESOLVED")

    def test_reused_runtime_hashes_match_existing_approval_evidence(self) -> None:
        runtime = load_candidates()["runtime"]
        refs = {item["path"]: item["sha256"] for item in runtime["reused_local_runtime"]}
        self.assertEqual(refs["ops/command-tower/isolated_runtime.py"],
                         "137a548b641e0c2f102cab6580f3d10e212e3465fcdb7fb31dadccee93a99acc")
        self.assertEqual(refs["ops/command-tower/durable_store.py"],
                         "6bcdda43761650be0100b144da6d0e6bc2690d4aba581cfde50bb2696f4577b6")
        self.assertEqual(refs["ops/command-tower/test_process_crash_recovery.py"],
                         "611a37b4d990d9a9d3a6cb75bbc04388e19e42bd021fb01d25c41758c1d4e816")


if __name__ == "__main__":
    unittest.main()
