"""Build the sandbox image and run one job in a disposable container."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


class SandboxError(RuntimeError):
    pass


@dataclass
class Runtime:
    name: str      # value for --runtime
    label: str     # what the report says about the isolation boundary


def _docker(*args: str, **kw) -> subprocess.CompletedProcess:
    if not shutil.which("docker"):
        raise SandboxError("docker is not installed or not on PATH")
    return subprocess.run(["docker", *args], capture_output=True, **kw)


def pick_runtime(requested: str, allow_runc: bool) -> Runtime:
    info = _docker("info", "--format", "{{json .}}", text=True)
    if info.returncode != 0:
        lines = info.stderr.strip().splitlines()
        raise SandboxError("cannot reach the Docker daemon" + (f": {lines[-1]}" if lines else ""))
    data = json.loads(info.stdout or "{}")
    runtimes = set((data.get("Runtimes") or {}).keys())
    desktop = "Docker Desktop" in (data.get("OperatingSystem") or "")

    if requested in ("auto", "runsc") and "runsc" in runtimes:
        return Runtime("runsc", "gVisor (runsc)")
    if requested == "runsc":
        raise SandboxError("gVisor (runsc) is not registered with Docker. See https://gvisor.dev/docs/user_guide/install/")
    if desktop:
        return Runtime("runc", "runc inside the Docker Desktop VM")
    if allow_runc or requested == "runc":
        return Runtime("runc", "runc on the host kernel (weaker: no gVisor)")
    raise SandboxError(
        "gVisor (runsc) is not installed. Install it (https://gvisor.dev/docs/user_guide/install/) "
        "or pass --allow-runc to accept plain container isolation on the host kernel.")


def _sandbox_dir() -> Path:
    return Path(str(resources.files("honeyrun") / "sandbox"))


def image_tag() -> str:
    h = hashlib.sha256()
    for name in ("Dockerfile", "agent.py"):
        h.update((_sandbox_dir() / name).read_bytes())
    return f"honeyrun-sandbox:{h.hexdigest()[:12]}"


def ensure_image(quiet: bool = False) -> str:
    tag = image_tag()
    if _docker("image", "inspect", tag).returncode == 0:
        return tag
    if not quiet:
        print(f"building sandbox image {tag} (first run only)...", flush=True)
    res = _docker("build", "-t", tag, str(_sandbox_dir()), text=True)
    if res.returncode != 0:
        raise SandboxError("image build failed:\n" + res.stderr[-2000:])
    return tag


def pack(src: Path) -> bytes:
    """The repo travels into the sandbox as a tar on stdin: no host path is ever mounted."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(str(src), arcname=".", filter=lambda m: None if m.isdev() else m)
    return buf.getvalue()


def run_job(src: Path, job: dict, runtime: Runtime, image: str, timeout: int,
            memory: str = "2g", cpus: str = "2") -> dict[str, bytes]:
    name = f"honeyrun-{uuid.uuid4().hex[:10]}"
    tmp = Path(tempfile.mkdtemp(prefix="honeyrun-"))
    args = [
        "run", "--rm", "-i", "--name", name,
        "--runtime", runtime.name,
        "--hostname", "devbox",
        "--read-only",
        "--cap-drop", "ALL",
        # root agent only: plant bait, drop to `runner`, trace it, kill it, bind :53/:80/:443
        "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--cap-add", "SYS_PTRACE", "--cap-add", "KILL", "--cap-add", "NET_BIND_SERVICE",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", memory, "--cpus", cpus,
        "--tmpfs", "/workspace:rw,exec,size=2g",
        "--tmpfs", "/home/runner:rw,exec,size=512m",
        "--tmpfs", "/tmp:rw,exec,size=512m",
        "--tmpfs", "/trace:rw,size=512m,mode=0700",
    ]
    if job["network"] == "offline":
        (tmp / "resolv.conf").write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        args += ["--network", "none", "-v", f"{tmp / 'resolv.conf'}:/etc/resolv.conf:ro"]
    else:
        args += ["--network", "bridge"]
    args.append(image)

    try:
        proc = subprocess.run(["docker", *args], input=json.dumps(job).encode() + b"\n" + pack(src),
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _docker("kill", name)
        raise SandboxError(f"sandbox did not finish within {timeout}s and was killed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not proc.stdout:
        raise SandboxError("sandbox produced no trace:\n" + proc.stderr.decode(errors="replace")[-2000:])

    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:gz") as tf:
        for member in tf:
            if member.isfile():
                f = tf.extractfile(member)
                if f:
                    out[os.path.basename(member.name)] = f.read()
    out["_agent.stderr"] = proc.stderr
    return out
