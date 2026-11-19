"""Targeted static checks for the un-deployed F4 external integration candidate."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "ops/command-tower/supabase-cas-draft/migrations/20261119000100_f4_cycle_control.sql"
ROLLBACK = ROOT / "ops/command-tower/supabase-cas-draft/migrations/20261119000100_f4_cycle_control.rollback.sql"
EDGE = ROOT / "ops/command-tower/supabase-cas-draft/supabase/functions/sake-cas-v1/cycle_control.ts"
INDEX = ROOT / "ops/command-tower/supabase-cas-draft/supabase/functions/sake-cas-v1/index.ts"
WORKFLOW = ROOT / ".github/workflows/public-runner-draft.yml"


class F4ExternalCandidateTests(unittest.TestCase):
    def test_migration_is_transactional_fixed_key_only_and_non_destructive(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        self.assertTrue(sql.startswith("-- LOCAL DRAFT ONLY"))
        self.assertRegex(sql, r"(?m)^BEGIN;$")
        self.assertRegex(sql, r"(?m)^COMMIT;$")
        self.assertIn("documents_fixed_public_repo_key", sql)
        for key in (
            "repositories/1458303357/b09-permit-journal-v1.json",
            "repositories/1458303357/b09-permit-journal-test-v1.json",
            "repositories/1458303357/b09-f4-cycle-control-v1.json",
            "repositories/1458303357/b09-f4-cycle-control-test-v1.json",
        ):
            self.assertIn(key, sql)
        self.assertNotRegex(sql, r"(?i)\b(?:DELETE\s+FROM|TRUNCATE|DROP\s+TABLE)\b")
        self.assertIn("ON CONFLICT (cas_key) DO NOTHING", sql)
        self.assertIn("WHERE cas_key = p_key AND revision = p_expected_revision", sql)
        self.assertIn("RAISE EXCEPTION 'F4 migration RLS policy drift'", sql)
        self.assertIn("F4 cycle-control key already exists; do not overwrite", sql)

    def test_rollback_is_guarded_and_never_deletes_cycle_records(self) -> None:
        sql = ROLLBACK.read_text(encoding="utf-8")
        self.assertTrue(sql.startswith("-- LOCAL DRAFT ONLY"))
        self.assertRegex(sql, r"(?m)^BEGIN;$")
        self.assertRegex(sql, r"(?m)^COMMIT;$")
        self.assertIn("rollback refused: F4 cycle-control records exist", sql)
        self.assertIn("rollback refused: schema or RLS policy drift", sql)
        self.assertNotRegex(sql, r"(?i)\b(?:DELETE\s+FROM|TRUNCATE|DROP\s+TABLE)\b")
        self.assertIn("documents_fixed_public_repo_key", sql)
        self.assertIn("b09-f4-cycle-control-test-v1.json", sql)

    def test_edge_boundary_is_separate_and_cycle_two_requires_auditor_event(self) -> None:
        edge = EDGE.read_text(encoding="utf-8")
        index = INDEX.read_text(encoding="utf-8")
        self.assertIn("B09_F4_CONTROL_OWNER_BEARER", edge)
        self.assertIn("B09_F4_CONTROL_WORKER_BEARER", edge)
        self.assertIn("B09_F4_CONTROL_AUDITOR_BEARER", edge)
        self.assertIn("B09_F4_CONTROL_READ_BEARER", edge)
        self.assertIn("B09_F4_TEST_CONTROL_OWNER_BEARER", edge)
        self.assertIn("event.event === \"CYCLE_CLAIMED\" ? role === \"worker\"", edge)
        self.assertIn("event.event === \"CYCLE1_AUDITOR_PASS\" ? role === \"auditor\"", edge)
        self.assertIn("cycle === 2 && (!audited || claims.length !== 1)", edge)
        self.assertIn("constantEqual", edge)
        self.assertIn("if-match", edge)
        self.assertIn("updateIfRevision", edge)
        self.assertIn("handleF4ControlRequest", index)
        self.assertIn("...F4_CONTROL_KEYS", index)

    def test_workflow_cross_run_artifact_path_is_pinned_and_jobs_remain_hard_disabled(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("cycle1_auditor_run_id:", source)
        self.assertIn("name: b09-f4-cycle1-auditor-evidence", source)
        self.assertIn("run-id: ${{ inputs.cycle1_auditor_run_id }}", source)
        self.assertIn("actions: read", source)
        self.assertIn("signed Auditor envelope missing", source)
        self.assertIn("if: ${{ false }}", source)
        for job_name, next_name in (("worker", "publisher"), ("publisher", "auditor")):
            start = source.index(f"  {job_name}:\n")
            end = source.index(f"  {next_name}:\n", start)
            self.assertRegex(source[start:end], r"(?m)^    if: \$\{\{ false(?: &&[^\n]*)? \}\}$")
        auditor = source[source.index("  auditor:\n"):]
        self.assertRegex(auditor, r"(?m)^    if: \$\{\{ false(?: &&[^\n]*)? \}\}$")
        uses = re.findall(r"(?m)^\s+uses:\s+[^@\s]+@([^\s#]+)", source)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in uses))


if __name__ == "__main__":
    unittest.main()
