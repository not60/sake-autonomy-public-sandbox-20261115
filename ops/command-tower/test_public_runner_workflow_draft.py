"""Static contract tests for the disabled three-job runner workflow."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
DRAFT_WORKFLOW = ROOT / ".github/workflows/public-runner-draft.yml"
PR_WORKFLOW = ROOT / ".github/workflows/sandbox-pr-readonly.yml"


def section(source: str, name: str, following: str | None) -> str:
    start = source.index(f"  {name}:\n")
    end = source.index(f"  {following}:\n", start) if following else len(source)
    return source[start:end]


class PublicRunnerWorkflowDraftTests(unittest.TestCase):
    def test_draft_workflow_is_manual_and_every_job_hard_stopped(self) -> None:
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^on:\n  workflow_dispatch:\s*$")
        self.assertNotRegex(source, r"(?m)^  (?:push|pull_request|pull_request_target):")
        worker = section(source, "worker", "publisher")
        publisher = section(source, "publisher", "auditor")
        auditor = section(source, "auditor", None)
        for job in (worker, publisher, auditor):
            self.assertRegex(job, r"(?m)^    if: \$\{\{ false(?: &&[^\n]*)? \}\}$")
        self.assertIn("environment: f4-worker", worker)
        self.assertIn("environment: f4-publisher", publisher)
        self.assertIn("environment: f4-auditor", auditor)
        self.assertIn("contents: read", worker)
        self.assertIn("contents: read", publisher)
        self.assertIn("pull-requests: write", publisher)
        self.assertIn("contents: read", auditor)
        self.assertIn("pull-requests: read", auditor)
        self.assertIn("actions: read", auditor)
        self.assertIn("B09_CAS_READ_TOKEN: ${{ secrets.B09_CAS_READ_TOKEN }}", auditor)
        self.assertNotIn("B09_CAS_TOKEN: ${{ secrets.B09_CAS_TOKEN }}", auditor)
        self.assertNotIn("OPENAI_API_KEY", publisher + auditor)
        codex_step = source.split("      - name: Codex candidate generation\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: ${{ false }}", codex_step)
        self.assertNotIn("allow-users:", codex_step)
        self.assertIn("output-file: ${{ runner.temp }}/codex-final-message.txt", codex_step)

    def test_finite_stages_are_explicit_cross_run_handoffs_and_not_self_triggered(self):
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("execution_stage:", source)
        self.assertIn("options: ['worker', 'publish-audit']", source)
        self.assertIn("worker_run_id:", source)
        self.assertNotRegex(source, r"(?m)^  workflow_run:")
        self.assertNotRegex(source, r"(?m)^  push:")
        self.assertIn("if: ${{ false && github.ref == 'refs/heads/trusted/f4-nonprod-20261119' && inputs.execution_stage == 'worker' }}", source)
        expected_publish_if = "if: ${{ false && github.ref == 'refs/heads/trusted/f4-nonprod-20261119' && inputs.execution_stage == 'publish-audit' }}"
        self.assertIn(expected_publish_if, section(source, "publisher", "auditor"))
        self.assertIn(expected_publish_if, section(source, "auditor", None))
        publisher = section(source, "publisher", "auditor")
        auditor = section(source, "auditor", None)
        self.assertNotRegex(publisher, r"(?m)^    needs:")
        self.assertIn("run-id: ${{ inputs.worker_run_id }}", publisher)
        self.assertIn("run-id: ${{ inputs.publisher_attestation_run_id }}", publisher)
        self.assertIn("run-id: ${{ inputs.worker_run_id }}", auditor)
        self.assertIn("needs: [publisher]", auditor)
        self.assertIn("F4_CYCLE2_AUDITOR_COMPLETE_SAFE_STOP", auditor)

    def test_worker_packages_actual_delta_and_binds_codex_output(self) -> None:
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        package = source.split("      - name: Package exact candidate bytes and hash manifest\n", 1)[1]
        self.assertNotIn("--changed-path", package)
        self.assertIn("--worker-run-id", package)
        self.assertIn("--codex-output-file", package)
        self.assertIn("--allowed-path", package)

    def test_all_actions_are_pinned_and_no_publication_command_exists(self) -> None:
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"(?m)^\s+uses:\s+[^@\s]+@([^\s#]+)", source)
        self.assertGreaterEqual(len(uses), 4)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in uses))
        self.assertNotRegex(source, r"(?i)\b(?:gh\s+pr\s+create|git\s+push|curl\s)")
        self.assertIn("bdf19a4a223ec2549a3e2274a0cf61556bc07675", source)

    def test_existing_readonly_pr_ci_installs_the_pinned_verifier(self) -> None:
        source = PR_WORKFLOW.read_text(encoding="utf-8")
        install = source.index("requirements-publisher.txt")
        tests = source.index("python3 -m unittest discover")
        self.assertLess(install, tests)
        self.assertIn("persist-credentials: false", source)

    def test_shell_inputs_use_env_and_provenance_binds_execution_and_cycle(self) -> None:
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn('[[ "${{ inputs.publisher_attestation_run_id }}"', source)
        self.assertNotIn('test "${{ inputs.f4_cycle }}"', source)
        self.assertIn('--base-sha "$F4_BASE_SHA"', source)
        self.assertIn('--worker-run-id "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-cycle-$F4_CYCLE"', source)
        self.assertEqual(source.count('expected_execution_sha=os.environ["EXPECTED_EXECUTION_SHA"]'), 2)
        self.assertEqual(source.count('expected_cycle=int(os.environ["F4_CYCLE"])'), 2)
        self.assertIn("test \"$F4_CYCLE\" = '2'", source)

    def test_publisher_writer_is_connected_but_remains_hard_disabled(self) -> None:
        source = DRAFT_WORKFLOW.read_text(encoding="utf-8")
        publisher = section(source, "publisher", "auditor")
        self.assertIn("if: ${{ false && github.ref == 'refs/heads/trusted/f4-nonprod-20261119' && inputs.execution_stage == 'publish-audit' }}", publisher)
        self.assertIn("B09_PUBLISHER_GITHUB_TOKEN: ${{ secrets.B09_PUBLISHER_GITHUB_TOKEN }}", publisher)
        self.assertIn("--draft-pr-write", publisher)
        self.assertIn("pr_head_sha: ${{ steps.publish.outputs.pr_head_sha }}", publisher)
        self.assertIn("result=\"$(python ops/command-tower/publisher_gate.py", publisher)
        self.assertIn("--trusted-keys", publisher)
        self.assertIn("B09_CAS_TOKEN: ${{ secrets.B09_CAS_TOKEN }}", publisher)
        auditor = section(source, "auditor", None)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", auditor)
        self.assertIn("--audit-pr-ci", auditor)
        self.assertIn("--expected-pr-head-sha", auditor)


if __name__ == "__main__":
    unittest.main()
