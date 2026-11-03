#!/usr/bin/env python3
"""honeyrun sandbox agent.

Runs as root inside the container (tini is PID 1). It reads one JSON job line
and then a tar of the repository from stdin, plants bait in /home/runner, runs every phase as the unprivileged
`runner` user under strace, answers DNS and HTTP(S) on loopback when the
sandbox is offline, and finally writes a gzipped tar of /trace to stdout.

/trace and /trace-meta are root-only tmpfs mounts, so the workload cannot read or
rewrite its own evidence. /trace-meta is small and separate: the workload can fill
/trace with syscalls, but the sinkhole log and meta.json must still fit. Nothing
but the final tar may be written to stdout.
"""
import base64
import glob
import json
import os
import pwd
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time

TRACE = "/trace"
META = "/trace-meta"          # net.jsonl, meta.json, files.json: survives a full /trace
CA_DIR = f"{META}/ca"         # CA key lives here; never tarred out
PUB = "/run/honeyrun"         # root-owned, world-readable: the CA bundle the workload trusts
MAX_CONN = 64
DNS_LOG_CAP = 2 * 1024 * 1024    # separate budgets: a TCP flood must not hide DNS tunnelling, nor the reverse
TCP_LOG_CAP = 6 * 1024 * 1024
PAYLOAD_CAP = 32 * 1024           # stored bytes per TCP record; "bytes" keeps the true size
RING = 200                        # most recent TCP records, written at the end even past the cap
TRACE_FULL = 0.90
LINGER_WINDOW = 20          # seconds to keep watching what the command left running (or until the phase deadline)
HOME = "/home/runner"
WORK = "/workspace/repo"
SYSCALLS = (
    "execve,execveat,clone,clone3,fork,vfork,open,openat,openat2,creat,"
    "connect,sendto,sendmsg,sendmmsg,bind,listen,chdir,fchdir,"
    "io_uring_setup,io_uring_enter,io_uring_register,"
    "memfd_create,socket,ptrace,unshare,setns,mount,init_module,finit_module"
)
# Paths that change on every install and say nothing about the code: counted, not listed.
NOISE = (f"{HOME}/.npm/", f"{HOME}/.cache/", "/tmp/pip-", "/tmp/npm-", "/tmp/node-compile-cache",
         "/tmp/.npm", "/tmp/v8-compile-cache", "/tmp/tmp")
SITE = f"{HOME}/.local/lib/"
SNAP_LIMIT = 300000
STRACE = ["strace", "-f", "--seccomp-bpf", "-tt", "-xx", "-yy", "-q", "-e", "signal=none", "-s", "16384", "-e", "trace=" + SYSCALLS]
MCP_PROTOCOL = "2025-06-18"


def log(msg):
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


DEGRADED = threading.Event()   # the sinkhole lost evidence or dropped connections


def cap_payload(rec):
    """Keep the head and tail of a large payload: a flood of junk must not push the secret out,
    and the agent cannot know which bytes are the secret."""
    raw = rec.pop("_raw", None)
    if raw is None:
        return
    rec["bytes"] = rec.get("bytes", len(raw))
    if len(raw) > PAYLOAD_CAP:
        half = PAYLOAD_CAP // 2
        raw = raw[:half] + raw[-half:]
        rec["truncated"] = True
    rec["data_b64"] = base64.b64encode(raw).decode()


class NetLog:
    def __init__(self, path):
        self.f = open(path, "a")
        self.lock = threading.Lock()
        self.used = {"dns": 0, "tcp": 0}
        self.caps = {"dns": DNS_LOG_CAP, "tcp": TCP_LOG_CAP}
        self.ring = []          # (seq, line) of the latest TCP records
        self.seq = 0
        self.written = set()

    def write(self, **rec):
        rec["t"] = round(time.time(), 3)
        bucket = "dns" if rec.get("kind") == "dns" else "tcp"
        try:
            cap_payload(rec)
            line = json.dumps(rec) + "\n"
            with self.lock:
                self.seq += 1
                seq = self.seq
                if bucket == "tcp":
                    self.ring.append((seq, line))
                    del self.ring[:-RING]
                if self.used[bucket] + len(line) > self.caps[bucket]:
                    DEGRADED.set()
                    return
                self.f.write(line)
                self.f.flush()
                self.used[bucket] += len(line)
                self.written.add(seq)
        except (OSError, ValueError):
            DEGRADED.set()   # full disk must not kill the sinkhole thread

    def close(self):
        """Append the latest TCP records that the budget dropped (a flood followed by the real exfil)."""
        with self.lock:
            try:
                for seq, line in self.ring:
                    if seq not in self.written:
                        self.f.write(line)
            except OSError:
                DEGRADED.set()
            self.f.close()


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
        try:
            pkt, peer = s.recvfrom(4096)
        except OSError:
            DEGRADED.set()
            time.sleep(0.1)
            continue
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
        k, v = k.strip().lower(), v.strip().lower()
        if k == b"transfer-encoding" and b"chunked" in v:
            return body.endswith(b"0\r\n\r\n")
        if k == b"content-length":
            try:
                return len(body) >= int(v)
            except ValueError:
                return True
    return True


def read_request(conn):
    data = b""
    try:
        while len(data) < 262144:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if http_complete(data):
                break
    except (socket.timeout, OSError):
        pass
    return data


def http_fields(data):
    rec = {"bytes": len(data), "_raw": data}
    parts = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ")
    if len(parts) >= 2:
        rec["method"], rec["path"] = parts[0], parts[1]
    for line in data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"host":
            rec["host"] = v.strip().decode("latin-1", "replace")
    return rec


def reply_ok(conn):
    try:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass


def peek_hello(conn):
    """Read the ClientHello without consuming it, so TLS can still be terminated."""
    data = b""
    try:
        while len(data) < 16384:
            data = conn.recv(16384, socket.MSG_PEEK)
            if data[:1] != b"\x16" or len(data) < 5 or len(data) >= 5 + int.from_bytes(data[3:5], "big"):
                break
            time.sleep(0.05)
    except (socket.timeout, OSError):
        pass
    return data


class Mint:
    """Per-run CA (openssl CLI) that signs a leaf certificate per SNI name on demand."""

    def __init__(self):
        self.ok = False
        self.ctxs = {}
        self.lock = threading.Lock()
        self.n = 0

    @staticmethod
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=20)

    def setup(self):
        try:
            os.makedirs(CA_DIR, mode=0o700, exist_ok=True)
            self.openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                         "-keyout", f"{CA_DIR}/ca.key", "-out", f"{CA_DIR}/ca.crt", "-subj", "/CN=honeyrun sinkhole CA",
                         "-days", "3", "-addext", "basicConstraints=critical,CA:TRUE",
                         "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            bundle = open("/etc/ssl/certs/ca-certificates.crt", "rb").read() + open(f"{CA_DIR}/ca.crt", "rb").read()
            os.makedirs(PUB, exist_ok=True)
            for name, body in (("ca-bundle.crt", bundle), ("ca.crt", open(f"{CA_DIR}/ca.crt", "rb").read())):
                with open(f"{PUB}/{name}", "wb") as f:
                    f.write(body)
                os.chmod(f"{PUB}/{name}", 0o644)
            self.ok = True
        except Exception as e:
            log(f"TLS interception unavailable: {e}")

    def context(self, sni):
        # SNI is attacker-chosen: only a plain hostname may reach openssl's argv and extfile.
        name = sni if sni and len(sni) < 200 and all(c.isalnum() or c in ".-_" for c in sni) else "honeyrun.sinkhole"
        with self.lock:
            ctx = self.ctxs.get(name)
            if ctx is None:
                self.n += 1
                base = f"{CA_DIR}/leaf{self.n}"
                with open(f"{base}.ext", "w") as f:
                    f.write(f"subjectAltName=DNS:{name}\nbasicConstraints=CA:FALSE\n")
                self.openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                             "-keyout", f"{base}.key", "-out", f"{base}.csr", "-subj", f"/CN={name}")
                self.openssl("x509", "-req", "-in", f"{base}.csr", "-CA", f"{CA_DIR}/ca.crt", "-CAkey", f"{CA_DIR}/ca.key",
                             "-CAcreateserial", "-out", f"{base}.crt", "-days", "3", "-extfile", f"{base}.ext")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(f"{base}.crt", f"{base}.key")
                self.ctxs[name] = ctx
            return ctx


def handle_tls(conn, netlog, mint):
    hello = peek_hello(conn)
    sni = parse_sni(hello) if hello[:1] == b"\x16" else None
    secure = None
    if mint.ok and hello[:1] == b"\x16":
        try:
            secure = mint.context(sni).wrap_socket(conn, server_side=True)
        except Exception:
            secure = None   # pinned client rejected our CA, or minting failed
    if secure is None:
        rec = {"kind": "tcp", "port": 443, "bytes": len(hello), "_raw": hello, "sni": sni}
        netlog.write(**rec)
        return
    try:
        secure.settimeout(3)
        rec = {"kind": "tcp", "port": 443, **http_fields(read_request(secure)), "sni": sni, "tls": True}
        netlog.write(**rec)
        reply_ok(secure)
        secure.close()
    except OSError:
        pass


def handle_tcp(conn, port, netlog, mint, slots):
    try:
        conn.settimeout(3)
        if port == 443:
            handle_tls(conn, netlog, mint)
        else:
            data = read_request(conn)
            netlog.write(kind="tcp", port=port, **http_fields(data))
            if data:
                reply_ok(conn)
    except Exception:
        DEGRADED.set()
    finally:
        slots.release()
        try:
            conn.close()
        except OSError:
            pass


def tcp_server(port, netlog, mint):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    slots = threading.BoundedSemaphore(MAX_CONN)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            DEGRADED.set()
            time.sleep(0.1)
            continue
        if not slots.acquire(timeout=1):
            DEGRADED.set()
            conn.close()
            continue
        try:
            threading.Thread(target=handle_tcp, args=(conn, port, netlog, mint, slots), daemon=True).start()
        except Exception:   # pids limit
            DEGRADED.set()
            slots.release()
            conn.close()


def start_sinkhole(netlog, mint):
    for target, args in ((dns_server, (netlog,)), (tcp_server, (80, netlog, mint)), (tcp_server, (443, netlog, mint))):
        threading.Thread(target=target, args=args, daemon=True).start()


def agent_socket(path, kind, netlog):
    """A decoy ssh-agent / gpg-agent socket: anything that connects is after the user's keys.

    World-connectable (the workload runs as another user), accepts, records, never answers."""
    try:
        os.unlink(path)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o666)
    srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                time.sleep(0.1)
                continue
            netlog.write(kind="agent-socket", sock=kind)
            conn.settimeout(1)
            try:
                conn.recv(256)
            except OSError:
                pass
            conn.close()

    threading.Thread(target=serve, daemon=True).start()


def start_agent_sockets(netlog):
    """Returns the env vars that point the workload at the decoys."""
    env = {}
    if not os.path.isdir(PUB):
        return env
    try:
        ssh, gpg = f"{PUB}/ssh-agent.sock", f"{PUB}/S.gpg-agent"
        agent_socket(ssh, "ssh", netlog)
        agent_socket(gpg, "gpg", netlog)
        env = {"SSH_AUTH_SOCK": ssh, "GPG_AGENT_INFO": f"{gpg}:0:1"}
    except OSError as e:
        log(f"decoy agent sockets: {e}")
    return env


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


def describe(pid):
    """A process with no cmdline (kernel-style or already exec'd away) is still worth naming."""
    info = {"pid": pid, "cmdline": cmdline(pid)}
    for key, path, fn in (("comm", f"/proc/{pid}/comm", lambda p: open(p).read().strip()),
                          ("exe", f"/proc/{pid}/exe", os.readlink)):
        try:
            info[key] = fn(path)
        except OSError:
            info[key] = ""
    return info


def trace_usage():
    try:
        st = os.statvfs(TRACE)
        return 1 - st.f_bavail / st.f_blocks if st.f_blocks else 0
    except OSError:
        return 0


def kill_runner(uid):
    for pid in runner_pids(uid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


# ---------------------------------------------------------------- MCP probe

SIMPLE = {"integer": 1, "number": 1, "boolean": False, "array": [], "object": {}}


def arg_value(spec):
    if not isinstance(spec, dict):
        return "honeyrun"
    if isinstance(spec.get("enum"), list) and spec["enum"]:
        return spec["enum"][0]
    if "default" in spec:
        return spec["default"]
    if isinstance(spec.get("examples"), list) and spec["examples"]:
        return spec["examples"][0]
    t = spec.get("type")
    if isinstance(t, list):   # ["string", "null"]
        t = next((x for x in t if isinstance(x, str) and x != "null"), None)
    if t in SIMPLE:
        return SIMPLE[t]
    if spec.get("format") in ("url", "uri"):
        return "http://honeyrun.example.net/"
    return "honeyrun"


def schema_args(schema):
    """Arguments for the required fields only; a malformed schema yields {}."""
    if not isinstance(schema, dict):
        return {}
    props, required = schema.get("properties"), schema.get("required")
    if not isinstance(props, dict) or not isinstance(required, list):
        return {}
    return {n: arg_value(props.get(n)) for n in required if isinstance(n, str)}


class McpProbe:
    """Speaks just enough MCP over stdio to list the tools and call each once."""

    def __init__(self, proc, out_path):
        self.proc = proc
        self.out = open(out_path, "w")
        self.tools = None
        self.status = {"tools_listed": None, "calls_sent": 0, "error": None}
        self.done = threading.Event()
        threading.Thread(target=self.read, daemon=True).start()

    def send(self, msg):
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError, ValueError):
            return False

    def read(self):
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            try:
                self.out.write(line + "\n")
                self.out.flush()
            except OSError:
                pass
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("id") == 2 and self.tools is None:
                tools = (msg.get("result") or {}).get("tools") if isinstance(msg.get("result"), dict) else None
                if isinstance(tools, list):
                    self.tools = tools
                    self.status["tools_listed"] = len(tools)
        self.done.set()

    def call_all(self, deadline):
        for i, tool in enumerate(self.tools):
            if time.time() >= deadline:
                self.status["error"] = "deadline reached before every tool was called"
                break
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            try:
                args = schema_args(tool.get("inputSchema"))
            except Exception:
                args = {}
            if self.send({"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                          "params": {"name": tool["name"], "arguments": args}}):
                self.status["calls_sent"] += 1

    def run(self, deadline):
        try:
            self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": MCP_PROTOCOL, "capabilities": {},
                "clientInfo": {"name": "honeyrun", "version": "0.1.0"}}})
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            while self.tools is None and time.time() < deadline and not self.done.is_set():
                time.sleep(0.1)
            if self.tools is None:
                self.status["error"] = "no tools/list result"
            else:
                self.call_all(deadline)
            settle = min(deadline, time.time() + 5)
            while time.time() < settle and not self.done.is_set():
                time.sleep(0.1)
        except Exception as e:
            self.status["error"] = f"{type(e).__name__}: {e}"
        finally:
            try:
                self.proc.stdin.close()
            except (OSError, ValueError):
                pass


# ---------------------------------------------------------------- phases

def run_phase(phase, env, uid):
    name = phase["name"]
    timeout = float(phase.get("timeout", 120))
    is_mcp = bool(phase.get("mcp"))
    out = open(f"{TRACE}/{name}.log", "wb")
    shifted = False
    if isinstance(phase.get("env"), dict):
        # per-phase conditions (CI variables) layered over the job environment
        env = {**env, **{str(k): v for k, v in phase["env"].items() if isinstance(v, str)}}
    if phase.get("clock"):
        # Time bombs: the same code again with the clock moved forward (libfaketime).
        lib = next(iter(sorted(glob.glob("/usr/lib/*/faketime/libfaketime.so.1"))), None)
        if lib:
            env = {**env, "LD_PRELOAD": lib, "FAKETIME": phase["clock"], "FAKETIME_DONT_RESET": "1"}
            shifted = True
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

    main = MainExit(f"{TRACE}/{name}.strace")
    main_done_at, timed_out, lingering, truncated, next_df = None, False, [], False, 0
    while proc.poll() is None:
        now = time.time()
        if now >= next_df and not truncated:
            next_df = now + 0.5
            if trace_usage() > TRACE_FULL:
                # The workload is flooding syscalls: stop it while meta still fits.
                truncated = True
                deadline = 0
        if main_done_at is None and main.poll():
            main_done_at = now
        if main_done_at is not None and now - main_done_at > 5 and not lingering:
            # The command itself finished but something it started is still alive. Note it now but
            # keep tracing: `sleep 8; curl ...` should still be seen before it is killed.
            lingering = [describe(p) for p in runner_pids(uid)]
        if main_done_at is not None and now - main_done_at > LINGER_WINDOW:
            kill_runner(uid)
        if now > deadline:
            timed_out = not truncated
            kill_runner(uid)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.1)
    kill_runner(uid)
    if probe:
        probe.done.wait(2)
    res = {
        "name": name, "cmd": phase["cmd"], "exit": proc.returncode, "t0": round(started, 3), "t1": round(time.time(), 3),
        "seconds": round(time.time() - started, 2), "timed_out": timed_out,
        "lingering": lingering, "evidence_truncated": truncated,
    }
    if phase.get("clock"):
        res["clock_shifted"] = shifted   # False: libfaketime was missing and the real clock was used
    if probe:
        res["mcp_probe"] = probe.status
    return res


class MainExit:
    """Learns from strace's own log when the phase command (the first traced pid) has exited.

    Guessing the main process from /proc raced under load and killed live installs; strace's
    "+++ exited" line for the first pid it traced is authoritative.
    """

    def __init__(self, path):
        self.path, self.off, self.main, self.done = path, 0, None, False

    def poll(self):
        if self.done:
            return True
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off)
                chunk = f.read(8 << 20)
        except OSError:
            return False
        cut = chunk.rfind(b"\n")
        if cut < 0:
            return False
        self.off += cut + 1
        for line in chunk[:cut].split(b"\n"):
            head = line.split(None, 1)[0] if line.strip() else b""
            if self.main is None and head.isdigit():
                self.main = head
            if self.main and head == self.main and (b"+++ exited with" in line or b"+++ killed by" in line):
                self.done = True
        return self.done


def chown_tree(path, uid, gid):
    # Bottom-up: root has no CAP_DAC_OVERRIDE, so it must list a directory before giving it away.
    for root, dirs, files in os.walk(path, topdown=False):
        for n in dirs + files:
            try:
                os.lchown(os.path.join(root, n), uid, gid)
            except OSError as e:
                log(f"chown {n}: {e}")
    os.lchown(path, uid, gid)


def snapshot():
    """Size, mtime, mode and magic bytes of every file the workload could touch."""
    snap = {}
    for root in (HOME, "/tmp", WORK):
        for d, dirs, files in os.walk(root):
            if d.startswith(WORK) and os.path.basename(d) in ("node_modules", ".git"):
                dirs[:] = []
                continue
            for n in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
                path = os.path.join(d, n)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                head = b""
                if stat.S_ISREG(st.st_mode) and st.st_size >= 4:
                    try:
                        with open(path, "rb") as f:
                            head = f.read(4)
                    except OSError:
                        pass
                snap[path] = (st.st_size, st.st_mtime_ns, st.st_mode, head.hex())
                if len(snap) >= SNAP_LIMIT:
                    return snap
    return snap


def diff(before, after):
    out = {"created": [], "modified": [], "deleted": [], "counts": {"noise": 0, "workspace_created": 0}}

    def keep(path, meta):
        if path.startswith(NOISE):
            out["counts"]["noise"] += 1
            return False
        if path.startswith(SITE) and not path.endswith(".pth") and meta[3] not in ("7f454c46",):
            out["counts"]["noise"] += 1
            return False
        return True

    for path, meta in after.items():
        old = before.get(path)
        if old is None:
            if path.startswith(WORK + "/"):
                out["counts"]["workspace_created"] += 1
                if meta[3] != "7f454c46":
                    continue
            if keep(path, meta):
                out["created"].append([path, meta[0], oct(meta[2]), meta[3]])
        elif old[:3] != meta[:3] and keep(path, meta):
            out["modified"].append([path, meta[0], oct(meta[2]), meta[3]])
    for path, meta in before.items():
        if path not in after and keep(path, meta):
            out["deleted"].append([path, meta[0], oct(meta[2]), meta[3]])
    out["counts"]["workspace_files_before"] = sum(1 for p in before if p.startswith(WORK + "/"))
    out["truncated"] = len(after) >= SNAP_LIMIT
    for key in ("created", "modified", "deleted"):
        out["counts"][key] = len(out[key])
        out[key] = sorted(out[key])[:3000]
    return out


def unsafe_member(name):
    """Absolute or `..` as a path component; a name like `..config` is fine."""
    return name.startswith("/") or ".." in name.split("/")


def extract_repo(stream, uid, gid):
    root = os.path.realpath(WORK)
    with tarfile.open(fileobj=stream, mode="r|*") as tf:
        for member in tf:
            if unsafe_member(member.name) or member.isdev() or member.islnk():
                continue
            name = os.path.normpath(member.name)
            target = os.path.join(WORK, name)
            # Running as root: extracting over a symlink member planted earlier would write through it,
            # and chmod follows links. Drop a pre-existing link first; never touch through one.
            if os.path.islink(target):
                os.unlink(target)
            # An earlier symlink member must not redirect a later one out of the repo.
            parent = os.path.realpath(os.path.dirname(target))
            if not (parent + "/").startswith(root + "/"):
                continue
            tf.extract(member, WORK, set_attrs=False)
            if not member.issym() and not os.path.islink(target):
                os.chmod(target, 0o755 if member.isdir() or member.mode & 0o111 else 0o644)
    chown_tree("/workspace", uid, gid)


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
    for d in (TRACE, META):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    if os.path.isdir(PUB):
        os.chmod(PUB, 0o755)   # some engines cannot set tmpfs modes themselves
    pw = pwd.getpwnam("runner")
    uid, gid = pw.pw_uid, pw.pw_gid

    plant(job.get("files", {}), uid, gid)
    os.makedirs(WORK)
    extract_repo(stdin, uid, gid)

    netlog = NetLog(f"{META}/net.jsonl")
    mint = Mint()
    if job.get("network") == "offline":
        mint.setup()
        start_sinkhole(netlog, mint)
        time.sleep(0.2)

    env = {
        "PATH": f"{HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": HOME, "USER": "runner", "LOGNAME": "runner", "SHELL": "/bin/bash",
        "LANG": "C.UTF-8", "TERM": "xterm-256color",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false", "NPM_CONFIG_FUND": "false", "NPM_CONFIG_AUDIT": "false",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_BREAK_SYSTEM_PACKAGES": "1",
    }
    env.update(start_agent_sockets(netlog))
    env.update(job.get("env", {}))
    if mint.ok:   # offline only: make the workload trust the sinkhole CA
        bundle = f"{PUB}/ca-bundle.crt"
        env.update({"NODE_EXTRA_CA_CERTS": f"{PUB}/ca.crt", "SSL_CERT_FILE": bundle, "REQUESTS_CA_BUNDLE": bundle,
                    "CURL_CA_BUNDLE": bundle, "PIP_CERT": bundle, "GIT_SSL_CAINFO": bundle})

    before = snapshot()
    results = []
    for phase in job.get("phases", []):
        log(f"phase {phase['name']}: {phase['cmd']}")
        results.append(run_phase(phase, env, uid))
    kill_runner(uid)
    with open(f"{META}/files.json", "w") as f:
        json.dump(diff(before, snapshot()), f)

    with open(f"{META}/meta.json", "w") as f:
        json.dump({"phases": results, "phases_requested": len(job.get("phases", [])), "network": job.get("network"), "sinkhole_degraded": DEGRADED.is_set()}, f)
    netlog.close()
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as tf:
        tf.add(TRACE, arcname="trace")
        for n in os.listdir(META):
            if n != "ca":   # the CA key stays behind
                tf.add(os.path.join(META, n), arcname=f"trace/{n}")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
