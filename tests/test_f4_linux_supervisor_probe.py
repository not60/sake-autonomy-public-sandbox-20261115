"""Probe boundary tests and separately gated formal F4 contract tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COMMAND_TOWER = ROOT / "ops" / "command-tower"
sys.path.insert(0, str(COMMAND_TOWER))
sys.path.insert(0, str(ROOT / "tools"))

F4_CYCLE_CONTROL_AVAILABLE = (COMMAND_TOWER / "f4_cycle_control.py").is_file()
if F4_CYCLE_CONTROL_AVAILABLE:
    import f4_cycle_control
    from f4_cycle_control import VerifiedStageAudit
else:
    f4_cycle_control = None
    VerifiedStageAudit = None

from f4_linux_supervisor_probe import (
    LinuxDockerSupervisor,
    ProcessObservation,
    SupervisorHold,
    validate_container_inspect,
)


IMAGE = "amd64/ubuntu@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d"
CONTAINER_ID = "a" * 64
SAFE_COMMAND = [
    "/bin/sh", "-c",
    "if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ] || [ -e /run/host-secrets ] || [ \"${GITHUB_TOKEN+x}\" = x ] || [ \"${ACTIONS_RUNTIME_TOKEN+x}\" = x ] || [ \"${DOCKER_HOST+x}\" = x ] || [ \"${F4_STOP_OBSERVER_PRIVATE_KEY+x}\" = x ]; then exit 41; fi; sleep 2 & child=$!; kill -0 \"$child\"; wait \"$child\"",
]


def inspect_document(*, privileged=False, pid_mode="", bind=False, extra_env=None):
    mounts = ([{"Type": "bind", "Source": "/", "Destination": "/host"}]
              if bind else [{"Type": "tmpfs", "Source": "", "Destination": "/tmp"}])
    env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "F4_PROBE_ONLY=1"]
    if extra_env:
        env.append(extra_env)
    return [{
        "Id": CONTAINER_ID,
        "Config": {"Image": IMAGE, "User": "65532:65532", "Cmd": SAFE_COMMAND, "Env": env},
        "HostConfig": {
            "Privileged": privileged, "PidMode": pid_mode, "NetworkMode": "none",
            "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"], "Binds": [], "Devices": [],
            "DeviceRequests": [], "PidsLimit": 64, "Memory": 268435456,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=1m"}, "NanoCpus": 500000000,
        },
        "Mounts": mounts,
        "State": {"Running": False, "Pid": 0},
    }]


def bound_scope(supervisor):
    return {
        "executor": f"docker-container:{supervisor.container_id}",
        "process_namespace": f"private-pidns:{supervisor.container_id}",
        "continuation_namespace": f"cgroup-v2:{supervisor.cgroup_path}",
    }


class SupervisorBoundaryNegativeTests(unittest.TestCase):
    def test_mutable_image_reference_is_rejected(self):
        with self.assertRaisesRegex(SupervisorHold, "digest"):
            validate_container_inspect(inspect_document(), expected_image="ubuntu:24.04")

    def test_privileged_or_host_pid_container_is_rejected(self):
        for changed in (inspect_document(privileged=True), inspect_document(pid_mode="host")):
            with self.subTest(changed=changed[0]["HostConfig"]):
                with self.assertRaises(SupervisorHold):
                    validate_container_inspect(changed, expected_image=IMAGE)

    def test_host_bind_mount_and_unapproved_secret_environment_are_rejected(self):
        for changed in (inspect_document(bind=True), inspect_document(extra_env="GITHUB_TOKEN=present")
                        ):
            with self.subTest(changed=changed[0]):
                with self.assertRaises(SupervisorHold):
                    validate_container_inspect(changed, expected_image=IMAGE)

class FormalF4SafeStopContractTests(unittest.TestCase):
    """These tests run only when the real F4 contract source is present."""

    def test_unsealed_or_pre_audit_observation_never_signs(self):
        supervisor = LinuxDockerSupervisor.__new__(LinuxDockerSupervisor)
        supervisor.container_id = CONTAINER_ID
        supervisor.cgroup_path = "/sys/fs/cgroup/f4-probe"
        scope = bound_scope(supervisor)
        with self.assertRaisesRegex(SupervisorHold, "verified_audit"):
            supervisor.sign_after_verified_audit(
                audit=None, previous_audit=None, observer_key=None, observer_private_key=None,
                expected_scope=scope,
            )

        claim = type("Claim", (), {
            "cycle": 1, "run_id": "test-run-1", "source_commit_sha": "b" * 40,
            "go_sha256": "c" * 64,
        })()
        future = datetime.now(timezone.utc) + timedelta(minutes=1)
        audit = VerifiedStageAudit(
            claim=claim, envelope_sha256="d" * 64, previous_sha256=None,
            workflow_run_id="audit-run", run_attempt=1, observed_after=future,
            expires_at=future + timedelta(minutes=5), auditor_public_key=b"e" * 32,
            permit_id="test-permit", ci_run_id="test-ci", _seal=f4_cycle_control._EVIDENCE_SEAL,
        )
        before = ProcessObservation(CONTAINER_ID, IMAGE, supervisor.cgroup_path,
                                    datetime.now(timezone.utc), False, ())
        with patch.object(supervisor, "observe_processes", return_value=before):
            with self.assertRaisesRegex(SupervisorHold, "post_audit_observation"):
                supervisor.sign_after_verified_audit(
                    audit=audit, previous_audit=None, observer_key=None, observer_private_key=None,
                    expected_scope=scope,
                )

    def test_residual_process_state_is_rejected_before_signing(self):
        supervisor = LinuxDockerSupervisor.__new__(LinuxDockerSupervisor)
        supervisor.container_id = CONTAINER_ID
        supervisor.cgroup_path = "/sys/fs/cgroup/f4-probe"
        claim = type("Claim", (), {
            "cycle": 1, "run_id": "test-run-1", "source_commit_sha": "b" * 40,
            "go_sha256": "c" * 64,
        })()
        now = datetime.now(timezone.utc)
        audit = VerifiedStageAudit(
            claim=claim, envelope_sha256="d" * 64, previous_sha256=None,
            workflow_run_id="audit-run", run_attempt=1, observed_after=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5), auditor_public_key=b"e" * 32,
            permit_id="test-permit", ci_run_id="test-ci", _seal=f4_cycle_control._EVIDENCE_SEAL,
        )
        live = ProcessObservation(CONTAINER_ID, IMAGE, supervisor.cgroup_path, now, True, (4321,))
        with patch.object(supervisor, "observe_processes", return_value=live):
            with self.assertRaisesRegex(SupervisorHold, "residual_processes"):
                supervisor.sign_after_verified_audit(
                    audit=audit, previous_audit=None, observer_key=None, observer_private_key=None,
                    expected_scope=bound_scope(supervisor),
                )

    def test_scope_not_bound_to_observed_container_is_rejected(self):
        supervisor = LinuxDockerSupervisor.__new__(LinuxDockerSupervisor)
        supervisor.container_id = CONTAINER_ID
        supervisor.cgroup_path = "/sys/fs/cgroup/f4-probe"
        claim = type("Claim", (), {
            "cycle": 1, "run_id": "test-run-1", "source_commit_sha": "b" * 40,
            "go_sha256": "c" * 64,
        })()
        now = datetime.now(timezone.utc)
        audit = VerifiedStageAudit(
            claim=claim, envelope_sha256="d" * 64, previous_sha256=None,
            workflow_run_id="audit-run", run_attempt=1, observed_after=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5), auditor_public_key=b"e" * 32,
            permit_id="test-permit", ci_run_id="test-ci", _seal=f4_cycle_control._EVIDENCE_SEAL,
        )
        with patch.object(supervisor, "observe_processes") as observe:
            with self.assertRaisesRegex(SupervisorHold, "scope_not_bound"):
                supervisor.sign_after_verified_audit(
                    audit=audit, previous_audit=None, observer_key=None, observer_private_key=None,
                    expected_scope={"executor": "other", "process_namespace": "private-pidns",
                                    "continuation_namespace": "other-cgroup"},
                )
        observe.assert_not_called()


FormalF4SafeStopContractTests = unittest.skipUnless(
    F4_CYCLE_CONTROL_AVAILABLE,
    "requires the F4 cycle-control source, which is outside the probe-only tree",
)(FormalF4SafeStopContractTests)


@unittest.skipUnless(os.environ.get("F4_RUN_DOCKER_PROBE") == "1", "requires the approved GitHub-hosted Linux runner")
class HostedLinuxProcessObservationTest(unittest.TestCase):
    def test_unprivileged_container_process_is_seen_and_exits_without_residue(self):
        image = os.environ.get("F4_PROBE_IMAGE", "")
        supervisor = LinuxDockerSupervisor(image=image)
        try:
            supervisor.start_probe()
            first = supervisor.observe_processes()
            self.assertTrue(first.running)
            self.assertTrue(first.process_ids)
            supervisor.wait_probe(timeout_seconds=15)
            final = supervisor.observe_processes()
            self.assertFalse(final.running)
            self.assertEqual(final.process_ids, ())
            self.assertTrue(final.cgroup_path.startswith("/sys/fs/cgroup/"))
        finally:
            supervisor.cleanup()


if __name__ == "__main__":
    unittest.main()
