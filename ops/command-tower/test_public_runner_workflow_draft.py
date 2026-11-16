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


if __name__ == "__main__":
    unittest.main()
