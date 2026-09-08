"""Linux-only, explicit runsc execution. Never fall back to ordinary Docker or host exec."""

import re
import subprocess
import sys
import uuid
from typing import Literal


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
