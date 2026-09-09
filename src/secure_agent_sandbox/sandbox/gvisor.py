"""Linux-only, explicit runsc execution. Never fall back to ordinary Docker or host exec."""

import datetime as dt
import json
import re
import subprocess
import sys
import uuid
from typing import Literal

_MANAGED_LABEL = "secure-agent-sandbox.managed=1"
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")


def reap_expired(max_age_seconds: int, *, now: dt.datetime | None = None) -> tuple[str, ...]:
    """Remove only expired containers started by this adapter.

    Run this from an independent host watchdog. It never discovers containers by
    name prefix alone, and it does not remove a container unless Docker confirms
    the adapter's exact management label and a valid creation timestamp.
    """
    if sys.platform != "linux":
        raise RuntimeError("gVisor requires a provisioned Linux execution node")
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 86_400:
        raise ValueError("max_age_seconds must be an integer between 1 and 86400")
    current = now or dt.datetime.now(dt.UTC)
    if current.tzinfo is None:
        raise ValueError("now must include a timezone")

    listed = subprocess.run(
        ["docker", "ps", "-aq", "--no-trunc", "--filter", "label=" + _MANAGED_LABEL],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    reaped: list[str] = []
    for container_id in listed.stdout.splitlines():
        if not _CONTAINER_ID.fullmatch(container_id):
            raise RuntimeError("Docker returned an invalid managed container ID")
        inspected = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if inspected.returncode:
            # The container completed between list and inspect; it cannot be
            # safely acted on and will not be retried through an arbitrary ID.
            continue
        try:
            record = json.loads(inspected.stdout)[0]
            labels = record["Config"]["Labels"]
            created = dt.datetime.fromisoformat(record["Created"].replace("Z", "+00:00"))
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Docker returned an invalid managed container record") from error
        if labels.get("secure-agent-sandbox.managed") != "1" or created.tzinfo is None:
            raise RuntimeError("Docker returned a container outside the adapter contract")
        if (current - created).total_seconds() < max_age_seconds:
            continue
        removed = subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if removed.returncode and b"No such container" not in removed.stderr:
            raise RuntimeError("sandbox cleanup unconfirmed; quarantine execution node")
        reaped.append(container_id)
    return tuple(reaped)


def execute(source: bytes, image: str, language: Literal["python", "bash"] = "python") -> int:
    if sys.platform != "linux":
        raise RuntimeError("gVisor requires a provisioned Linux execution node")
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("an operator-approved image digest is required")
    if type(source) is not bytes or len(source) > 65536:
        raise ValueError("source too large")
    command = {"python": ["python3", "-I", "-"], "bash": ["bash", "--noprofile", "--norc", "-s"]}
    if language not in command:
        raise ValueError("unsupported language")
    name = "sas-" + uuid.uuid4().hex
    args = [
        "docker",
        "run",
        "--name",
        name,
        "--label=" + _MANAGED_LABEL,
        "--pull=never",
        "--rm",
        "-i",
        "--runtime=runsc",
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32",
        "--memory=128m",
        "--memory-swap=128m",
        "--cpus=0.5",
        "--ulimit=cpu=5:5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=1048576:1048576",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--log-driver=none",
        "--entrypoint=" + command[language][0],
        image,
        *command[language][1:],
    ]
    try:
        # No stdout capture: an output flood must not fill controller RAM/disk.
        result = subprocess.run(
            args,
            input=source,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        return result.returncode
    finally:
        # Timeout kills the CLI, not necessarily the container; explicitly remove it.
        cleanup = subprocess.run(
            ["docker", "rm", "-f", name], capture_output=True, timeout=10, check=False
        )
        if cleanup.returncode and b"No such container" not in cleanup.stderr:
            raise RuntimeError("sandbox cleanup unconfirmed; quarantine execution node")
