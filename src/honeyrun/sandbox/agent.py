#!/usr/bin/env python3
"""honeyrun sandbox agent.

Runs as root inside the container (tini is PID 1). It reads one JSON job line
and then a tar of the repository from stdin, plants bait in /home/runner, runs every phase as the unprivileged
`runner` user under strace, answers DNS and HTTP(S) on loopback when the
sandbox is offline, and finally writes a gzipped tar of /trace to stdout.

/trace is a root-only tmpfs, so the workload cannot read or rewrite its own
evidence. Nothing but the final tar may be written to stdout.
"""
import base64
import json
import os
import pwd
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import threading
import time

TRACE = "/trace"
HOME = "/home/runner"
WORK = "/workspace/repo"
SYSCALLS = (
    "execve,execveat,clone,clone3,fork,vfork,open,openat,openat2,creat,"
    "connect,sendto,sendmsg,sendmmsg"
)
STRACE = ["strace", "-f", "--seccomp-bpf", "-tt", "-xx", "-yy", "-qq", "-s", "2048", "-e", "trace=" + SYSCALLS]
MCP_PROTOCOL = "2025-06-18"


def log(msg):
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


class NetLog:
    def __init__(self, path):
        self.f = open(path, "a")
        self.lock = threading.Lock()

    def write(self, **rec):
        rec["t"] = round(time.time(), 3)
        with self.lock:
            self.f.write(json.dumps(rec) + "\n")
            self.f.flush()


# ---------------------------------------------------------------- sinkhole

def parse_qname(pkt, off=12):
    labels = []
    while off < len(pkt):
        n = pkt[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed name in query")
        labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    raise ValueError("truncated")


def dns_server(netlog):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 53))
    while True:
        pkt, peer = s.recvfrom(4096)
        try:
            qname, end = parse_qname(pkt)
            qtype = struct.unpack("!H", pkt[end:end + 2])[0]
        except Exception:
            continue
        netlog.write(kind="dns", qname=qname, qtype=qtype)
        answer = b""
        if qtype == 1:  # A -> 127.0.0.1, everything else -> empty NOERROR
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("127.0.0.1")
        header = pkt[:2] + b"\x81\x80" + b"\x00\x01" + struct.pack("!H", 1 if answer else 0) + b"\x00\x00\x00\x00"
        try:
            s.sendto(header + pkt[12:end + 4] + answer, peer)
        except OSError:
            pass


def parse_sni(d):
    try:
        p = 5 + 4 + 2 + 32
        p += 1 + d[p]
        p += 2 + int.from_bytes(d[p:p + 2], "big")
        p += 1 + d[p]
        ext_end = p + 2 + int.from_bytes(d[p:p + 2], "big")
        p += 2
        while p + 4 <= ext_end:
            etype = int.from_bytes(d[p:p + 2], "big")
            elen = int.from_bytes(d[p + 2:p + 4], "big")
            p += 4
            if etype == 0:
                n = int.from_bytes(d[p + 3:p + 5], "big")
                return d[p + 5:p + 5 + n].decode("ascii", "replace")
            p += elen
    except Exception:
        return None
    return None


def http_complete(data):
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            try:
                return len(body) >= int(v.strip())
            except ValueError:
                return True
    return True


def handle_tcp(conn, port, netlog):
    conn.settimeout(3)
    data = b""
    try:
        while len(data) < 262144:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if data[:1] == b"\x16":
                if len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
                    break
            elif http_complete(data):
                break
    except (socket.timeout, OSError):
        pass
    rec = {"kind": "tcp", "port": port, "bytes": len(data),
           "data_b64": base64.b64encode(data[:262144]).decode()}
    is_tls = data[:1] == b"\x16"
    if is_tls:
        rec["sni"] = parse_sni(data)
    else:
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split(" ")
        if len(parts) >= 2:
            rec["method"], rec["path"] = parts[0], parts[1]
        for line in data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"host":
                rec["host"] = v.strip().decode("latin-1", "replace")
    netlog.write(**rec)
    try:
        if not is_tls and data:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        conn.close()
    except OSError:
        pass


def tcp_server(port, netlog):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_tcp, args=(conn, port, netlog), daemon=True).start()


def start_sinkhole(netlog):
    for target, args in ((dns_server, (netlog,)), (tcp_server, (80, netlog)), (tcp_server, (443, netlog))):
        threading.Thread(target=target, args=args, daemon=True).start()


# ---------------------------------------------------------------- processes

def runner_pids(uid):
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            st = os.stat(f"/proc/{name}")
        except OSError:
            continue
        if st.st_uid == uid:
            pids.append(int(name))
    return pids


def cmdline(pid):
    try:
        raw = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def proc_state(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return None


def child_of(ppid):
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            fields = open(f"/proc/{name}/stat").read().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(fields[1]) == ppid:
            return int(name)
    return None


def kill_runner(uid):
    for pid in runner_pids(uid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


# ---------------------------------------------------------------- MCP probe

def schema_args(schema):
    args = {}
    props = (schema or {}).get("properties", {}) or {}
    for name in (schema or {}).get("required", []) or []:
        t = (props.get(name) or {}).get("type")
        args[name] = {"integer": 1, "number": 1, "boolean": False, "array": [], "object": {}}.get(t, "honeyrun")
    return args


class McpProbe:
    """Speaks just enough MCP over stdio to list the tools and call each once."""

    def __init__(self, proc, out_path):
        self.proc = proc
        self.out = open(out_path, "w")
        self.tools = None
        self.done = threading.Event()
        threading.Thread(target=self.read, daemon=True).start()

    def send(self, msg):
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def read(self):
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            self.out.write(line + "\n")
            self.out.flush()
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("id") == 2 and self.tools is None:
                self.tools = ((msg.get("result") or {}).get("tools")) or []
        self.done.set()

    def run(self, deadline):
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": MCP_PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "honeyrun", "version": "0.1.0"}}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        while self.tools is None and time.time() < deadline and not self.done.is_set():
            time.sleep(0.1)
        for i, tool in enumerate((self.tools or [])[:25]):
            if not isinstance(tool, dict) or "name" not in tool:
                continue
            self.send({"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": {
                "name": tool["name"], "arguments": schema_args(tool.get("inputSchema"))}})
        settle = min(deadline, time.time() + 5)
        while time.time() < settle and not self.done.is_set():
            time.sleep(0.1)
        try:
            self.proc.stdin.close()
        except OSError:
            pass


# ---------------------------------------------------------------- phases

def run_phase(phase, env, uid):
    name = phase["name"]
    timeout = float(phase.get("timeout", 120))
    is_mcp = bool(phase.get("mcp"))
    out = open(f"{TRACE}/{name}.log", "wb")
    cmd = STRACE + ["-o", f"{TRACE}/{name}.strace", "-u", "runner", "--", "/bin/sh", "-c", phase["cmd"]]
    started = time.time()
    proc = subprocess.Popen(
        cmd, cwd=WORK, env=env, start_new_session=True,
        stdin=subprocess.PIPE if is_mcp else subprocess.DEVNULL,
        stdout=subprocess.PIPE if is_mcp else out, stderr=out,
    )
    deadline = started + timeout
    probe = McpProbe(proc, f"{TRACE}/{name}.mcp.jsonl") if is_mcp else None
    if probe:
        threading.Thread(target=probe.run, args=(deadline,), daemon=True).start()

    main_pid, main_done_at, timed_out, lingering = None, None, False, []
    while proc.poll() is None:
        now = time.time()
        if main_pid is None:
            main_pid = child_of(proc.pid)
        elif main_done_at is None and proc_state(main_pid) in (None, "Z", "X"):
            main_done_at = now
        if main_done_at is not None and now - main_done_at > 2:
            # The command itself finished but something it started is still alive.
            lingering = [{"pid": p, "cmdline": cmdline(p)} for p in runner_pids(uid)]
            kill_runner(uid)
        if now > deadline:
            timed_out = True
            kill_runner(uid)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.1)
    kill_runner(uid)
    if probe:
        probe.done.wait(2)
    return {
        "name": name, "cmd": phase["cmd"], "exit": proc.returncode,
        "seconds": round(time.time() - started, 2), "timed_out": timed_out,
        "lingering": [p for p in lingering if p["cmdline"]],
    }


def chown_tree(path, uid, gid):
    os.lchown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            try:
                os.lchown(os.path.join(root, n), uid, gid)
            except OSError:
                pass


def plant(files, uid, gid):
    for rel, item in files.items():
        dest = os.path.join(HOME, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as f:
            f.write(item["content"])
        os.chmod(dest, int(item.get("mode", "600"), 8))
    chown_tree(HOME, uid, gid)


def main():
    stdin = sys.stdin.buffer
    job = json.loads(stdin.readline())
    os.makedirs(TRACE, exist_ok=True)
    os.chmod(TRACE, 0o700)
    pw = pwd.getpwnam("runner")
    uid, gid = pw.pw_uid, pw.pw_gid

    plant(job.get("files", {}), uid, gid)
    os.makedirs(WORK)
    with tarfile.open(fileobj=stdin, mode="r|*") as tf:
        for member in tf:
            name = os.path.normpath(member.name)
            if name.startswith(("/", "..")) or member.isdev() or member.islnk():
                continue
            tf.extract(member, WORK, set_attrs=False)
    chown_tree("/workspace", uid, gid)

    netlog = NetLog(f"{TRACE}/net.jsonl")
    if job.get("network") == "offline":
        start_sinkhole(netlog)
        time.sleep(0.2)

    env = {
        "PATH": f"{HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": HOME, "USER": "runner", "LOGNAME": "runner", "SHELL": "/bin/bash",
        "LANG": "C.UTF-8", "TERM": "xterm-256color",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false", "NPM_CONFIG_FUND": "false", "NPM_CONFIG_AUDIT": "false",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_BREAK_SYSTEM_PACKAGES": "1",
    }
    env.update(job.get("env", {}))

    results = []
    for phase in job.get("phases", []):
        log(f"phase {phase['name']}: {phase['cmd']}")
        results.append(run_phase(phase, env, uid))

    with open(f"{TRACE}/meta.json", "w") as f:
        json.dump({"phases": results, "network": job.get("network")}, f)
    netlog.f.close()
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as tf:
        tf.add(TRACE, arcname="trace")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
