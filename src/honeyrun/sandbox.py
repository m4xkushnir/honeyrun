"""Build the sandbox image and run one job in a disposable container."""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


class SandboxError(RuntimeError):
    pass


@dataclass
class Runtime:
    name: str               # value for --runtime ("" = the engine's default)
    label: str              # what the report says about the isolation boundary
    engine: str = "docker"  # docker | podman | container (Apple)


ENGINES = ("docker", "podman", "container")


def _cli(engine: str, *args: str, **kw) -> subprocess.CompletedProcess:
    if not shutil.which(engine):
        raise SandboxError(f"{engine} is not installed or not on PATH")
    return subprocess.run([engine, *args], capture_output=True, **kw)


def _docker_runtime(requested: str, allow_runc: bool) -> Runtime:
    info = _cli("docker", "info", "--format", "{{json .}}", text=True)
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
        "gVisor (runsc) is not installed. Install it (https://gvisor.dev/docs/user_guide/install/), "
        "use --engine podman (rootless), or pass --allow-runc to accept plain container isolation.")


def _podman_runtime(requested: str, allow_runc: bool) -> Runtime:
    info = _cli("podman", "info", "--format", "json", text=True)
    if info.returncode != 0:
        raise SandboxError("podman is installed but not working: " + info.stderr.strip()[-300:])
    data = json.loads(info.stdout or "{}")
    rootless = bool(((data.get("host") or {}).get("security") or {}).get("rootless"))
    runsc, krun = shutil.which("runsc"), shutil.which("krun")
    if requested in ("auto", "runsc") and runsc:
        return Runtime(runsc, "gVisor (runsc) via podman", "podman")
    if requested == "runsc":
        raise SandboxError("runsc is not on PATH for podman to use")
    if requested in ("auto", "krun") and krun:
        return Runtime("krun", "libkrun microVM via podman", "podman")
    if rootless:
        return Runtime("", "rootless podman (user namespace, no gVisor)", "podman")
    if allow_runc or requested == "runc":
        return Runtime("", "podman on the host kernel (weaker: no gVisor)", "podman")
    raise SandboxError("rootful podman without gVisor or krun: run podman rootless, install runsc, or pass --allow-runc")


def _apple_runtime() -> Runtime:
    res = _cli("container", "system", "status", text=True)
    if res.returncode != 0:
        raise SandboxError("Apple container is installed but not running: run `container system start`")
    return Runtime("", "Apple container (a lightweight VM per sandbox)", "container")


def pick_runtime(requested: str, allow_runc: bool, engine: str = "auto") -> Runtime:
    """Strongest boundary available: a VM per sandbox, then gVisor, then a desktop VM, then rootless."""
    if engine == "docker":
        return _docker_runtime(requested, allow_runc)
    if engine == "podman":
        return _podman_runtime(requested, allow_runc)
    if engine == "container":
        return _apple_runtime()
    errors = []
    for name, fn in (("container", _apple_runtime),
                     ("docker", lambda: _docker_runtime(requested, allow_runc)),
                     ("podman", lambda: _podman_runtime(requested, allow_runc))):
        if not shutil.which(name):
            continue
        try:
            return fn()
        except SandboxError as e:
            errors.append(str(e))
    if errors:
        raise SandboxError("; ".join(errors))
    raise SandboxError(
        "no sandbox engine found. Install one of: Docker (with gVisor on Linux), Podman (rootless, no daemon), "
        "or Apple container on macOS 26+. Or run with --static-only, which needs none.")


def _sandbox_dir() -> Path:
    return Path(str(resources.files("honeyrun") / "sandbox"))


def image_tag() -> str:
    h = hashlib.sha256()
    for name in ("Dockerfile", "agent.py"):
        h.update((_sandbox_dir() / name).read_bytes())
    return f"honeyrun-sandbox:{h.hexdigest()[:12]}"


def ensure_image(quiet: bool = False, engine: str = "docker") -> str:
    tag = image_tag()
    if _cli(engine, "image", "inspect", tag).returncode == 0:
        return tag
    if not quiet:
        print(f"building sandbox image {tag} (first run only)...", flush=True)
    res = _cli(engine, "build", "-t", tag, str(_sandbox_dir()), text=True)
    if res.returncode != 0:
        raise SandboxError("image build failed:\n" + res.stderr[-2000:])
    return tag


# Files that hold real credentials: never shipped unless git tracks them (then they are the repo).
SECRET_NAMES = (".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*", ".npmrc",
                ".pypirc", ".netrc", "credentials.json", "*.p12", "*.pfx", "*.jks", "*.keystore", ".git-credentials",
                ".htpasswd", ".dockercfg", "kubeconfig", "*.tfvars", "terraform.tfstate*", "service-account*.json")
SECRET_DIRS = {".ssh", ".gnupg"}                                   # everything below these
SECRET_IN_DIR = {".aws": ("credentials", "config"), ".docker": ("config.json",)}
GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
GIT_HARDEN = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]
MAX_TRACE = 1536 * 1024 * 1024    # container stdout, on disk
MAX_MEMBER = 512 * 1024 * 1024    # one trace file, in memory


def _is_secret(rel: str) -> bool:
    parts = rel.split("/")
    if SECRET_DIRS & set(parts[:-1]) or (len(parts) > 1 and parts[-1] in SECRET_IN_DIR.get(parts[-2], ())):
        return True
    return "secrets" in parts[:-1] or any(fnmatch.fnmatch(parts[-1], pat) for pat in SECRET_NAMES)


def _git_files(src: Path, *flags: str) -> list[str] | None:
    try:
        res = subprocess.run([*GIT_HARDEN, "-C", str(src), "ls-files", *flags, "-z"], capture_output=True,
                             env={**os.environ, **GIT_ENV}, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0:
        return None
    return [p for p in res.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def _walk_files(src: Path) -> list[str]:
    out = []
    for d, dirs, files in os.walk(src):
        dirs[:] = [x for x in dirs if x != ".git"]
        rel_d = os.path.relpath(d, src)
        for n in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
            if n != ".git":
                out.append(n if rel_d == "." else f"{rel_d}/{n}")
    return out


def _inside(root: str, p: str) -> bool:
    return (p + os.sep).startswith(root + os.sep)


def _add(tf: tarfile.TarFile, src: Path, root: str, rel: str) -> None:
    path = src / rel
    # A symlinked parent directory (d -> ~/.ssh) would make d/id_rsa a read from outside the tree.
    if not _inside(root, os.path.realpath(path.parent)):
        return
    is_link = os.path.islink(path)
    if is_link and not _inside(root, os.path.realpath(path)):
        return   # points outside the source tree
    try:
        tf.inodes.clear()   # hard links must travel as plain files: the agent drops link members
        info = tf.gettarinfo(str(path), arcname="./" + rel)
        if info.isdev() or info.isdir():   # gitlinks and sockets
            return
        if info.isreg():
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as f:
                tf.addfile(info, f)
        else:
            tf.addfile(info)
    except OSError:
        pass


def pack(src: Path) -> bytes:
    """The repo travels into the sandbox as a tar on stdin: no host path is ever mounted.

    .git never goes in (a checkout leaves its token in .git/config). In a git work tree only
    tracked and unignored files go; credential-looking files go only if git tracks them.
    """
    root = os.path.realpath(src)
    tracked = _git_files(src, "--cached") if (src / ".git").exists() else None
    files = _git_files(src, "--cached", "--others", "--exclude-standard") if tracked is not None else None
    if files is None:
        tracked, files = [], _walk_files(src)
    tracked = set(tracked)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in sorted(set(files)):
            parts = rel.split("/")
            if ".." in parts or rel.startswith("/") or parts[0] == ".git":
                continue
            if rel not in tracked and _is_secret(rel):
                continue
            _add(tf, src, root, rel)
    return buf.getvalue()


def run_job(src: Path, job: dict, runtime: Runtime, image: str, timeout: int,
            memory: str = "2g", cpus: str = "2") -> dict[str, bytes]:
    name = f"honeyrun-{uuid.uuid4().hex[:10]}"
    tmp = Path(tempfile.mkdtemp(prefix="honeyrun-"))
    if runtime.engine == "container":
        return _run_apple(src, job, runtime, image, timeout, memory, cpus, name, tmp)
    args = [
        "run", "--rm", "-i", "--name", name,
        *(["--runtime", runtime.name] if runtime.name else []),
        "--hostname", "devbox",
        "--read-only",
        "--cap-drop", "ALL",
        # Root agent only: plant bait, drop to `runner`, trace it, kill it, bind :53/:80/:443,
        # and read (never write) the runner's files for the before/after snapshot.
        # The workload runs as uid 1001 and holds none of these.
        "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "DAC_READ_SEARCH",
        "--cap-add", "SYS_PTRACE", "--cap-add", "KILL", "--cap-add", "NET_BIND_SERVICE",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", memory, "--cpus", cpus,
        "--tmpfs", "/workspace:rw,exec,size=2g",
        "--tmpfs", "/home/runner:rw,exec,size=512m",
        "--tmpfs", "/tmp:rw,exec,size=512m",
        "--tmpfs", "/trace:rw,size=512m,mode=0700",
        # Small and separate, so a workload that floods /trace cannot cost us net.jsonl or meta.json.
        "--tmpfs", "/trace-meta:rw,size=32m,mode=0700",
    ]
    if job["network"] == "offline":
        (tmp / "resolv.conf").write_bytes(b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")   # LF even on Windows
        # Root writes the CA bundle here; the runner can read it but never change it.
        args += ["--tmpfs", "/run/honeyrun:rw,size=4m,mode=0755"]
        args += ["--network", "none", "-v", f"{tmp / 'resolv.conf'}:/etc/resolv.conf:ro"]
    else:
        if runtime.engine == "docker":
            args += ["--network", "bridge"]    # podman picks the right default for rootless itself
    args.append(image)
    return _execute(runtime.engine, args, name, job, src, timeout, tmp)


def _run_apple(src, job, runtime, image, timeout, memory, cpus, name, tmp: Path) -> dict[str, bytes]:
    """Apple container: every sandbox is its own VM, so the VM is the boundary and the
    container-level knobs Docker needs (pids, seccomp, tmpfs sizes) do not exist there."""
    args = ["run", "--rm", "-i", "--name", name, "--memory", memory, "--cpus", cpus, "--read-only",
            "--cap-drop", "ALL",
            "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "DAC_READ_SEARCH",
            "--cap-add", "SYS_PTRACE", "--cap-add", "KILL", "--cap-add", "NET_BIND_SERVICE"]
    for path in ("/workspace", "/home/runner", "/tmp", "/trace", "/trace-meta", "/run/honeyrun"):
        args += ["--tmpfs", path]
    if job["network"] == "offline":
        (tmp / "resolv.conf").write_bytes(b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")   # LF even on Windows
        args += ["--network", "none", "-v", f"{tmp / 'resolv.conf'}:/etc/resolv.conf:ro"]
    args.append(image)
    return _execute("container", args, name, job, src, timeout, tmp)


def _execute(engine, args, name, job, src, timeout, tmp) -> dict[str, bytes]:

    payload = json.dumps(job).encode() + b"\n" + pack(src)
    out_f = tempfile.NamedTemporaryFile(prefix="honeyrun-trace-", delete=False)
    err_f = tempfile.NamedTemporaryFile(prefix="honeyrun-err-", delete=False)
    try:
        try:
            _run_container(engine, args, name, payload, out_f, err_f, timeout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        out_f.flush()
        if os.path.getsize(out_f.name) == 0:
            raise SandboxError("sandbox produced no trace:\n" + _tail(err_f.name).decode(errors="replace")[-2000:])
        out = _read_trace(out_f.name)
        out["_agent.stderr"] = _tail(err_f.name)
        return out
    finally:
        for f in (out_f, err_f):
            f.close()
            try:
                os.unlink(f.name)
            except OSError:
                pass


def _tail(path: str, n: int = 1 << 20) -> bytes:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - n))
        return f.read()


def _run_container(engine, args, name, payload, out_f, err_f, timeout) -> None:
    proc = subprocess.Popen([engine, *args], stdin=subprocess.PIPE, stdout=out_f, stderr=err_f)

    def feed():
        try:
            proc.stdin.write(payload)
        except OSError:
            pass   # the container exited early; its stderr says why
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    threading.Thread(target=feed, daemon=True).start()
    end = time.monotonic() + timeout
    while proc.poll() is None:
        if time.monotonic() > end:
            _cli(engine, "kill", name)
            proc.kill()
            proc.wait()
            raise SandboxError(f"sandbox did not finish within {timeout}s and was killed")
        if os.fstat(out_f.fileno()).st_size > MAX_TRACE:
            _cli(engine, "kill", name)
            proc.kill()
            proc.wait()
            raise SandboxError("trace too large")
        time.sleep(0.2)


MAX_TRACE_TOTAL = 600 * 1024 * 1024    # all trace members together, in memory
MAX_TRACE_MEMBERS = 2000
_TRACE_NAME = re.compile(r"^(.+\.strace|.+\.log|.+\.mcp\.jsonl|net\.jsonl|meta\.json|files\.json)$")


def _read_trace(path: str) -> dict[str, bytes]:
    """The agent's tar, read defensively: the workload can write into /trace, so names and sizes are untrusted."""
    out: dict[str, bytes] = {}
    cut: list[str] = []
    total = seen = 0
    try:
        with tarfile.open(path, mode="r:gz") as tf:
            for member in tf:
                seen += 1
                if seen > MAX_TRACE_MEMBERS:
                    cut.append("too-many-members")
                    break
                if not member.isfile():
                    continue
                key = os.path.basename(member.name)
                if not _TRACE_NAME.match(key):
                    cut.append(f"ignored:{key[:60]}")
                    continue
                if key in out:
                    cut.append(f"duplicate:{key}")   # first one wins: a later copy could overwrite meta.json
                    continue
                f = tf.extractfile(member)
                if not f:
                    continue
                room = min(MAX_MEMBER, MAX_TRACE_TOTAL - total)
                if room <= 0:
                    cut.append(f"budget:{key}")
                    break
                out[key] = f.read(room)
                total += len(out[key])
                if member.size > len(out[key]):
                    cut.append(key)
    except (tarfile.TarError, EOFError, OSError) as e:
        if not out:
            raise SandboxError(f"trace unreadable: {e}")
        cut.append("_incomplete")
    if cut:
        out["_truncated"] = "\n".join(cut).encode()
    return out
