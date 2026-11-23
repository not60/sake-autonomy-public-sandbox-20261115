"""Non-production Linux/Docker probe for the F4 SAFE STOP supervisor boundary.

This module only runs a fixed, short-lived test process. It is not a Worker
launcher and accepts no caller-provided command, mount, environment, or image
tag. A caller must provide an already verified ``VerifiedStageAudit`` before
the supervisor signs a post-audit observation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Callable, Mapping
from uuid import uuid4


class SupervisorHold(RuntimeError):
    """The probe could not prove the required isolation or stopped state."""


_DIGEST_IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_MAX_WAIT_SECONDS = 30
_PROBE_COMMAND = [
    "/bin/sh", "-c",
    "if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ] || [ -e /run/host-secrets ] || [ \"${GITHUB_TOKEN+x}\" = x ] || [ \"${ACTIONS_RUNTIME_TOKEN+x}\" = x ] || [ \"${DOCKER_HOST+x}\" = x ] || [ \"${F4_STOP_OBSERVER_PRIVATE_KEY+x}\" = x ]; then exit 41; fi; sleep 2 & child=$!; kill -0 \"$child\"; wait \"$child\"",
]


@dataclass(frozen=True)
class ProcessObservation:
    container_id: str
    image: str
    cgroup_path: str
    observed_at: datetime
    running: bool
    process_ids: tuple[int, ...]


def _run(argv: list[str], *, timeout: int = 10, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SupervisorHold("supervisor_command_unavailable_or_timeout") from None
    if check and result.returncode != 0:
        raise SupervisorHold("supervisor_command_failed")
    return result


def _require_linux_docker(image: str) -> None:
    if not _DIGEST_IMAGE.fullmatch(image):
        raise SupervisorHold("probe_image_must_be_pinned_by_sha256_digest")
    if not Path("/proc/self/cgroup").is_file() or not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise SupervisorHold("linux_cgroup_v2_required")
    version = _run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], timeout=10)
    if not version.stdout.strip().startswith("linux/"):
        raise SupervisorHold("linux_docker_daemon_required")
    image_info = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], timeout=10)
    if not image_info.stdout.strip().startswith("sha256:"):
        raise SupervisorHold("pinned_probe_image_not_present")


def validate_container_inspect(document: object, *, expected_image: str) -> tuple[str, str]:
    """Validate Docker's actual container config; return ID and host cgroup path."""
    if not isinstance(expected_image, str) or not _DIGEST_IMAGE.fullmatch(expected_image):
        raise SupervisorHold("probe_image_must_be_pinned_by_sha256_digest")
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise SupervisorHold("container_inspect_shape_invalid")
    item = document[0]
    config, host, state = item.get("Config"), item.get("HostConfig"), item.get("State")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(state, dict):
        raise SupervisorHold("container_inspect_sections_missing")
    container_id = item.get("Id")
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise SupervisorHold("container_id_invalid")
    if config.get("Image") != expected_image or config.get("User") != "65532:65532":
        raise SupervisorHold("container_image_or_user_mismatch")
    env_entries = config.get("Env")
    env_names = set()
    if isinstance(env_entries, list):
        for entry in env_entries:
            if isinstance(entry, str) and "=" in entry:
                env_names.add(entry.split("=", 1)[0])
    if (config.get("Cmd") != _PROBE_COMMAND or "F4_PROBE_ONLY=1" not in (env_entries or [])
            or env_names - {"PATH", "F4_PROBE_ONLY"}):
        raise SupervisorHold("container_command_or_environment_mismatch")
    if (host.get("Privileged") is not False or host.get("PidMode") == "host"
            or host.get("NetworkMode") != "none" or host.get("ReadonlyRootfs") is not True
            or "ALL" not in (host.get("CapDrop") or [])
            or host.get("CapAdd") not in (None, [])
            or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
            or host.get("Binds") not in (None, [])
            or host.get("Devices") not in (None, [])
            or host.get("DeviceRequests") not in (None, [])):
        raise SupervisorHold("container_privilege_or_mount_boundary_mismatch")
    mounts = item.get("Mounts")
    if (not isinstance(mounts, list)
            or any(not isinstance(mount, dict) or mount.get("Type") != "tmpfs"
                   or mount.get("Destination") != "/tmp" for mount in mounts)):
        raise SupervisorHold("container_host_mount_forbidden")
    if not isinstance(host.get("PidsLimit"), int) or not 1 <= host["PidsLimit"] <= 64:
        raise SupervisorHold("container_pids_limit_invalid")
    if not isinstance(host.get("Memory"), int) or not 1 <= host["Memory"] <= 256 * 1024 * 1024:
        raise SupervisorHold("container_memory_limit_invalid")
    tmpfs = host.get("Tmpfs") or {}
    tmpfs_opts = tmpfs.get("/tmp") if isinstance(tmpfs, dict) else None
    if (not isinstance(tmpfs_opts, str)
            or any(flag not in tmpfs_opts.split(",") for flag in ("rw", "noexec", "nosuid", "nodev"))):
        raise SupervisorHold("container_tmpfs_options_invalid")
    if not isinstance(host.get("NanoCpus"), int) or not 1 <= host["NanoCpus"] <= 500_000_000:
        raise SupervisorHold("container_cpu_limit_invalid")
    if state.get("Running") is not True and state.get("Pid") in (0, None):
        return container_id, ""
    if not isinstance(state.get("Pid"), int) or state["Pid"] <= 0:
        raise SupervisorHold("container_host_pid_unavailable")
    cgroup_file = Path(f"/proc/{state['Pid']}/cgroup")
    try:
        entries = cgroup_file.read_text(encoding="ascii").splitlines()
    except OSError:
        raise SupervisorHold("container_cgroup_unavailable") from None
    v2 = [entry.split(":", 2)[2] for entry in entries if entry.startswith("0::")]
    if len(v2) != 1 or not v2[0].startswith("/") or ".." in Path(v2[0]).parts:
        raise SupervisorHold("container_cgroup_path_invalid")
    root = Path("/sys/fs/cgroup").resolve()
    cgroup = (root / v2[0].lstrip("/")).resolve()
    if cgroup != root and root not in cgroup.parents:
        raise SupervisorHold("container_cgroup_escaped_root")
    return container_id, str(cgroup)


def _cgroup_process_ids(cgroup: str) -> tuple[int, ...]:
    root = Path("/sys/fs/cgroup").resolve()
    path = Path(cgroup).resolve()
    if path != root and root not in path.parents:
        raise SupervisorHold("container_cgroup_escaped_root")
    if not path.exists():
        return ()
    pids: set[int] = set()
    for directory, subdirs, _files in os.walk(path, followlinks=False):
        base = Path(directory)
        subdirs[:] = [name for name in subdirs if not (base / name).is_symlink()]
        procs = base / "cgroup.procs"
        try:
            for line in procs.read_text(encoding="ascii").splitlines():
                if line:
                    pid = int(line)
                    if pid > 0:
                        pids.add(pid)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            raise SupervisorHold("cgroup_process_observation_failed") from None
    return tuple(sorted(pids))


class LinuxDockerSupervisor:
    """Run one fixed test process and retain its container for post-audit readback."""

    def __init__(self, *, image: str, run: Callable = _run) -> None:
        _require_linux_docker(image)
        self.image = image
        self._run = run
        self.container_id: str | None = None
        self.cgroup_path: str | None = None

    def start_probe(self) -> str:
        if self.container_id is not None:
            raise SupervisorHold("probe_already_started")
        name = "f4-stop-probe-" + uuid4().hex
        created = self._run([
            "docker", "create", "--name", name, "--pull=never", "--platform=linux/amd64",
            "--network=none", "--user=65532:65532", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64",
            "--memory=256m", "--cpus=0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m", "--env", "F4_PROBE_ONLY=1",
            self.image, *_PROBE_COMMAND,
        ], timeout=10)
        container_id = created.stdout.strip()
        if not _CONTAINER_ID.fullmatch(container_id):
            raise SupervisorHold("container_create_receipt_invalid")
        try:
            inspect = self._run(["docker", "inspect", container_id], timeout=10)
            try:
                cid, _cgroup = validate_container_inspect(json.loads(inspect.stdout), expected_image=self.image)
            except (json.JSONDecodeError, TypeError):
                raise SupervisorHold("container_inspect_unparseable") from None
            if cid != container_id:
                raise SupervisorHold("container_identity_changed")
            self._run(["docker", "start", container_id], timeout=10)
            # Read the actual host PID and cgroup after start; do not trust create output.
            inspect = self._run(["docker", "inspect", container_id], timeout=10)
            try:
                cid2, cgroup2 = validate_container_inspect(json.loads(inspect.stdout), expected_image=self.image)
            except (json.JSONDecodeError, TypeError):
                raise SupervisorHold("container_inspect_unparseable_after_start") from None
            if cid2 != container_id or not cgroup2:
                raise SupervisorHold("container_identity_or_cgroup_changed")
        except Exception:
            self._remove_probe(container_id)
            raise
        self.container_id, self.cgroup_path = container_id, cgroup2
        return container_id

    def wait_probe(self, *, timeout_seconds: int = _MAX_WAIT_SECONDS) -> None:
        if self.container_id is None or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= _MAX_WAIT_SECONDS:
            raise SupervisorHold("probe_wait_scope_invalid")
        deadline = time.monotonic() + timeout_seconds
        saw_host_process = False
        while time.monotonic() < deadline:
            observation = self.observe_processes()
            saw_host_process = saw_host_process or bool(observation.process_ids)
            inspect = self._run(["docker", "inspect", self.container_id], timeout=10)
            try:
                state = json.loads(inspect.stdout)[0]["State"]
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                raise SupervisorHold("container_state_unreadable") from None
            if state.get("Running") is False:
                if not saw_host_process or state.get("ExitCode") != 0:
                    raise SupervisorHold("probe_exit_or_process_observation_invalid")
                return
            time.sleep(0.1)
        raise SupervisorHold("probe_or_residual_process_timeout")

    def observe_processes(self) -> ProcessObservation:
        if self.container_id is None or self.cgroup_path is None:
            raise SupervisorHold("probe_not_started")
        inspect = self._run(["docker", "inspect", self.container_id], timeout=10)
        try:
            item = json.loads(inspect.stdout)[0]
            running = item["State"]["Running"] is True
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            raise SupervisorHold("container_state_unreadable") from None
        pids = _cgroup_process_ids(self.cgroup_path)
        if running:
            top = self._run(["docker", "top", self.container_id, "-eo", "pid,ppid,stat,args"], timeout=10)
            top_pids = _parse_top_pids(top.stdout)
            if not top_pids or not pids or not set(top_pids).intersection(pids):
                raise SupervisorHold("docker_top_and_cgroup_observation_disagree")
        elif pids:
            raise SupervisorHold("residual_processes_observed")
        return ProcessObservation(self.container_id, self.image, self.cgroup_path,
                                  datetime.now(timezone.utc), running, pids)

    def sign_after_verified_audit(self, *, audit: object, previous_audit: object,
                                  observer_key: object, observer_private_key: object,
                                  expected_scope: Mapping[str, str]
                                  ) -> tuple[dict[str, object], ProcessObservation]:
        if self.container_id is None:
            raise SupervisorHold("probe_not_started")
        try:
            import sys
            command_tower = str(Path(__file__).resolve().parents[1] / "ops" / "command-tower")
            if command_tower not in sys.path:
                sys.path.insert(0, command_tower)
            from attestations import sign_envelope
            import f4_cycle_control
            valid = f4_cycle_control.is_verified_stage_audit(audit, audit.claim, previous_audit)
        except Exception:
            raise SupervisorHold("verified_audit_contract_unavailable") from None
        if not valid:
            raise SupervisorHold("verified_audit_required_before_observation")
        bound_scope = {
            "executor": f"docker-container:{self.container_id}",
            "process_namespace": f"private-pidns:{self.container_id}",
            "continuation_namespace": f"cgroup-v2:{self.cgroup_path}",
        }
        if not isinstance(expected_scope, Mapping) or dict(expected_scope) != bound_scope:
            raise SupervisorHold("safe_stop_scope_not_bound_to_observed_container")
        observation = self.observe_processes()
        if observation.running or observation.process_ids:
            raise SupervisorHold("residual_processes_observed")
        observed_at = observation.observed_at
        if observed_at < audit.observed_after:
            raise SupervisorHold("post_audit_observation_not_yet_available")
        claim = audit.claim
        payload = {
            "schema": 1, "kind": "F4_SAFE_STOP", "repository_id": f4_cycle_control.REPOSITORY_ID,
            "cycle": claim.cycle, "worker_run_id": claim.run_id,
            "audit_run_id": audit.workflow_run_id, "audit_run_attempt": audit.run_attempt,
            "source_commit_sha": claim.source_commit_sha, "go_sha256": claim.go_sha256,
            "audit_sha256": audit.envelope_sha256,
            "observation_scope": dict(expected_scope), "execution_terminated": True,
            "live_processes": [], "pending_executions": [],
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        }
        try:
            envelope = sign_envelope(key_id=observer_key.key_id,
                                     private_key=observer_private_key, payload=payload)
            f4_cycle_control.verify_safe_stop(envelope=envelope, audit=audit,
                                              observer_key=observer_key,
                                              expected_scope=expected_scope)
        except Exception:
            raise SupervisorHold("safe_stop_signature_or_contract_rejected") from None
        return envelope, observation

    def cleanup(self) -> None:
        if self.container_id is not None:
            self._remove_probe(self.container_id)
            self.container_id = None

    def _remove_probe(self, container_id: str) -> None:
        result = self._run(["docker", "rm", "--force", container_id], timeout=10, check=False)
        if result.returncode != 0:
            raise SupervisorHold("probe_cleanup_failed")
        inspect = self._run(["docker", "inspect", container_id], timeout=10, check=False)
        if inspect.returncode == 0:
            raise SupervisorHold("probe_container_remains_after_cleanup")
        if self.cgroup_path and _cgroup_process_ids(self.cgroup_path):
            raise SupervisorHold("probe_processes_remain_after_cleanup")


def _parse_top_pids(output: str) -> tuple[int, ...]:
    lines = output.splitlines()[1:]
    pids: list[int] = []
    for line in lines:
        fields = line.split(None, 1)
        if fields and fields[0].isdigit():
            pids.append(int(fields[0]))
    return tuple(pids)
