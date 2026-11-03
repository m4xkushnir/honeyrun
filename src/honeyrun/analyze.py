"""Turn strace output, sinkhole logs and MCP transcripts into findings."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field

from .deobf import payloads
from .bait import Bait, bait_needles

HOME = "/home/runner"
PROBE_HOST = "honeyrun.example.net"
SEARCH_SUFFIXES = (".internal.cloudapp.net", ".internal", ".local", ".lan", ".home.arpa")
WORK = "/workspace"
SEVERITIES = ("info", "medium", "high", "critical")

# package registries and code hosts an install is expected to talk to
EXPECTED_HOSTS = (
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "nodejs.org",
    "pypi.org", "files.pythonhosted.org", "pypi.python.org", "pypi.io",
    "github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
    "api.github.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com",
    # browser, engine and model downloads that setup scripts legitimately fetch
    "cdn.playwright.dev", "playwright.azureedge.net", "playwright.download.prss.microsoft.com",
    "binaries.prisma.sh", "storage.googleapis.com", "cdn.jsdelivr.net", "unpkg.com",
    "huggingface.co", "cdn-lfs.huggingface.co", "electronjs.org",
    "proxy.golang.org", "sum.golang.org", "crates.io", "static.crates.io", "index.crates.io",
    "deb.debian.org",
)

# reads by a package manager of its own config file are normal
# extension modules and auditwheel's bundled libraries; anything else native in site-packages is odd
SITE_NATIVE_OK = re.compile(r"(\.so(\.\d+)*$|\.abi3\.so$|-linux-gnu\.so$|/[^/]+\.libs/[^/]+$)")

EXPECTED_READERS = {".npmrc": ("npm", "npx", "yarn", "pnpm")}

# paths that infostealers probe; touching them is the signal even when they don't exist
PROBE_PATTERNS = [
    (re.compile(p), label) for p, label in (
        (r"/\.config/(google-chrome|chromium|BraveSoftware|microsoft-edge)/", "browser profile"),
        (r"/\.mozilla/firefox/", "browser profile"),
        (r"Login Data|/Cookies$|/Local State$", "browser credential store"),
        (r"nkbihfbeogaeaoehlefnkodbefgpgknn|ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask extension storage"),
        (r"/\.(electrum|bitcoin|ethereum|monero)/|/Exodus/|/atomic/Local Storage", "crypto wallet"),
        (r"^/etc/shadow$|^/etc/sudoers", "system credential file"),
        (r"^/proc/1/environ$", "another process's environment"),
        (r"/run/secrets/|/var/run/secrets/kubernetes", "container secrets mount"),
        (r"/\.(bash|zsh)_history$", "shell history"),
        (r"/\.gnupg/", "GPG keyring"),
        (r"/\.password-store/|/\.local/share/keyrings/", "password store"),
    )
]

PERSISTENCE = [
    (re.compile(p), label) for p, label in (
        (r"/\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv)$", "shell startup file"),
        (r"/\.ssh/authorized_keys", "SSH authorized_keys"),
        (r"/\.config/autostart/|/\.config/systemd/user/|^/etc/systemd/", "autostart / systemd unit"),
        (r"^/etc/cron|^/var/spool/cron", "cron"),
        (r"/\.claude\.json$|/\.claude/settings|/\.claude/hooks", "Claude Code configuration"),
        (r"/\.cursor/mcp\.json$|/\.config/Claude/claude_desktop_config\.json$", "another agent's MCP configuration"),
        (r"/\.codex/(config\.toml|hooks)|/\.gemini/settings\.json$|/\.continue/config|/\.codeium/windsurf/", "AI agent configuration"),
        (r"/\.vscode(-server)?/extensions/|/\.cursor/extensions/|/\.config/Code/User/", "editor extensions or settings"),
        (r"/\.npmrc$|/\.config/pip/pip\.conf$|/\.pip/pip\.conf$|/\.pypirc$", "package registry configuration"),
        (r"/\.ssh/(config|rc)$", "SSH client configuration"),
        (r"/\.local/share/applications/|/\.config/environment\.d/", "desktop autostart / session environment"),
        (r"/\.gitconfig$|/\.config/git/", "global git configuration"),
    )
]

# reads that only make sense when checking whether you are being watched
SANDBOX_PROBES = re.compile(r"^/\.dockerenv$|^/proc/1/cgroup$|^/proc/1/sched$|^/sys/class/dmi/id/(product_name|sys_vendor|board_vendor)$|"
                            r"^/proc/scsi/scsi$|^/sys/hypervisor/|^/proc/sys/kernel/yama/")
MINER = re.compile(r"stratum\+(tcp|ssl)://|\bxmrig\b|--donate-level|cryptonight|randomx|"
                   r"(supportxmr|nanopool|hashvault|minexmr|moneroocean|2miners|f2pool|nicehash|ethermine|herominers)\.", re.I)
# names malware borrows so `ps` looks normal; real ones live under /usr, /bin or /sbin
DISGUISE = re.compile(r"^(kworker|kthreadd|ksoftirqd|systemd|systemd-\w+|sshd|dbus-daemon|crond?|rsyslogd|"
                      r"udevd|init|launchd|mds|WindowServer|svchost(\.exe)?|lsass(\.exe)?|explorer\.exe)\b")
ESCAPE_SYSCALLS = {"setns": "high", "mount": "high", "init_module": "high", "finit_module": "high",
                   "unshare": "medium", "ptrace": "medium"}
EXECUTABLE_MAGIC = {"7f454c46": "ELF", "cffaedfe": "Mach-O", "cefaedfe": "Mach-O", "4d5a9000": "PE"}

STRONG_INJECTION = [re.compile(p, re.I) for p in (
    r"<\s*/?\s*(important|system|instructions?|secret)\s*>",
    r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts|rules)",
    r"(do not|don'?t|never) (tell|mention|inform|reveal|show)\b",
    r"(~|\$HOME|home)/\.(ssh|aws|cursor|claude|config|kube|docker)",
    r"\bid_(rsa|ed25519|ecdsa)\b",
    r"mcp\.json|claude_desktop_config|\.claude\.json",
    r"before (using|calling|invoking) (this|any|the) tool",
    r"(send|forward|upload|post) (it|them|the [a-z ]+) to https?://",
)]
HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
# probe labels whose patterns can legitimately match files inside a repo (test fixtures, bundled profiles)
REPO_NOISY = {"browser credential store", "MetaMask extension storage", "crypto wallet", "browser profile"}
PROC_ENVIRON = re.compile(r"^/proc/(self|thread-self|\d+)/environ$")
PROC_FOREIGN = re.compile(r"^/proc/(\d+)/(root|cwd|mem|maps)(/|$)")
# untrusted text must never reach a terminal or a Markdown table raw
CONTROL = re.compile("[\x00-\x1f\x7f-\x9f]")


def clean(s: object) -> str:
    """Strip control and invisible characters and collapse whitespace so evidence is safe to print."""
    s = re.sub(r"[\r\n\t\v\f]+", " ", str(s))
    s = HIDDEN_CHARS.sub("", CONTROL.sub("", s))
    return re.sub(r" {2,}", " ", s).strip()

def scrub(s: object) -> str:
    """clean(), then mask tokens and URL passwords, and never show the real home directory."""
    from .installed import mask      # lazy: installed imports this module
    out = mask(clean(s))
    home = os.path.expanduser("~")
    return out.replace(home, "~") if home not in ("", "/") else out


LINE = re.compile(r"^(\d+)\s+\S+\s+(.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?|0x[0-9a-f]+)(?:<[^>]*>)?(?:\s+([A-Z0-9_]+))?")
UNFINISHED = re.compile(r"^(\w+)\((.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
STR = re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
DIRFD = re.compile(r"^\s*(?:AT_FDCWD|\d+)<([^>]*)>")
INET_ADDR = re.compile(r'inet_addr\("((?:[^"\\]|\\.)*)"\)')
INET_PTON = re.compile(r'inet_pton\(AF_INET6, "((?:[^"\\]|\\.)*)"')
SUN_PATH = re.compile(r'sun_path=@?"((?:[^"\\]|\\.)*)"')
HEXRUN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
DECOR_PORT = re.compile(r"(?:UDP|TCP|UDPv6|TCPv6):\[[^\]]*->[^\]]*:(\d+)\]")


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.replace("\\x", ""))


def text(s: str) -> str:
    return unhex(s).decode("utf-8", "replace")


def unescape(s: str) -> str:
    """strace prints with -xx as \\x..; older or partial output is plain text. Accept both."""
    return HEXRUN.sub(lambda m: text(m.group(0)), s)


def norm(path: str) -> str:
    path = os.path.normpath(path)
    return "/" + path.lstrip("/") if path.startswith("/") else path


def sock_addr(args: str, fam: str) -> str:
    """Address from the inet_addr()/inet_pton() argument, hex-escaped or plain."""
    if fam == "unix":
        m = SUN_PATH.search(args)
        return unescape(m.group(1)) if m else ""
    m = (INET_PTON if fam == "inet6" else INET_ADDR).search(args)
    return unescape(m.group(1)) if m else ""


@dataclass
class Proc:
    pid: int
    exe: str = "?"
    argv: list[str] = field(default_factory=list)
    parent: int | None = None

    @property
    def name(self) -> str:
        return os.path.basename(self.exe)

    def label(self, width: int = 72) -> str:
        cmd = re.sub(r"\s+", " ", " ".join(self.argv) if self.argv else self.exe).strip()
        cmd = cmd.replace(HOME, "~")
        return cmd if len(cmd) <= width else cmd[:width - 3] + "..."


@dataclass
class Event:
    phase: str
    kind: str          # exec | open | connect | send | dns
    pid: int
    proc: Proc
    data: dict


@dataclass
class Finding:
    severity: str
    rule: str
    title: str
    detail: str = ""
    phase: str = ""
    file: str = ""      # repo-relative path, when the finding is about one file

    def __post_init__(self):
        # Masked at the source so no output (terminal, JSON, SARIF, abuse report) can carry a token.
        self.title, self.detail = scrub(self.title), scrub(self.detail)
        self.phase = clean(self.phase)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def parse_dns_query(pkt: bytes) -> str | None:
    if len(pkt) < 17 or pkt[2] & 0x80 or int.from_bytes(pkt[4:6], "big") != 1:
        return None
    labels, off = [], 12
    while off < len(pkt):
        n = pkt[off]
        if n == 0:
            name = ".".join(labels)
            return name if name and all(32 < ord(c) < 127 for c in name) else None
        if n > 63:
            return None
        labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return None


def parse_strace(raw: str, phase: str) -> list[Event]:
    procs: dict[int, Proc] = {}
    pending: dict[int, tuple[str, str]] = {}
    events: list[Event] = []
    first_pid = None

    def proc(pid: int) -> Proc:
        if pid not in procs:
            procs[pid] = Proc(pid, "/bin/sh", ["sh", "-c"])
        return procs[pid]

    for line in raw.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if first_pid is None:
            first_pid = pid
        u = UNFINISHED.match(rest)
        if u:
            pending[pid] = (u.group(1), u.group(2))
            continue
        r = RESUMED.match(rest)
        if r:
            name, args0 = pending.pop(pid, (r.group(1), ""))
            rest = f"{name}({args0}{r.group(2)}"
        c = CALL.match(rest)
        if not c:
            continue
        name, args, ret, err = c.group(1), c.group(2), c.group(3), c.group(4)
        ok = ret not in ("?",) and not ret.startswith("-")
        strings = STR.findall(args)
        p = proc(pid)

        if name in ("clone", "clone3", "fork", "vfork") and ok and ret.isdigit():
            child = int(ret)
            procs[child] = Proc(child, p.exe, list(p.argv), pid)
        elif name in ("execve", "execveat") and strings:
            path = text(strings[0])
            if path.startswith("/"):
                path = norm(path)
            argv = [text(s) for s in strings[1:]]
            if ok:
                procs[pid] = p = Proc(pid, path, argv, p.parent)
            events.append(Event(phase, "exec", pid, p, {"path": path, "argv": argv, "ok": ok}))
        elif name in ("open", "openat", "openat2", "creat") and strings:
            path = text(strings[0])
            if not path.startswith("/"):
                # relative to whichever directory fd the call names (AT_FDCWD or an fd decorated by -yy)
                base = DIRFD.match(args) if name in ("openat", "openat2") else None
                cwd = unescape(base.group(1)) if base else WORK
                if not cwd.startswith("/"):
                    cwd = WORK
                path = os.path.join(cwd, path)
            path = norm(path)
            write = name == "creat" or bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", args))
            events.append(Event(phase, "open", pid, p, {"path": path, "write": write, "ok": ok, "err": err}))
        elif name == "connect":
            fam = "unix" if "AF_UNIX" in args else "inet6" if "AF_INET6" in args else "inet" if "AF_INET" in args else None
            if not fam:
                continue
            port = PORT.search(args)
            addr = sock_addr(args, fam) or (text(strings[-1]) if fam == "unix" and strings else "")
            events.append(Event(phase, "connect", pid, p, {
                "family": fam, "addr": addr, "port": int(port.group(1)) if port else None, "ok": ok, "err": err}))
        elif name == "bind" and ("AF_INET" in args):
            port = PORT.search(args)
            addr = sock_addr(args, "inet6" if "AF_INET6" in args else "inet")
            if port and int(port.group(1)) and ok:
                events.append(Event(phase, "bind", pid, p, {"addr": addr, "port": int(port.group(1))}))
        elif name == "memfd_create":
            events.append(Event(phase, "memfd", pid, p, {"name": text(strings[0]) if strings else "", "ok": ok}))
        elif name in ESCAPE_SYSCALLS:
            events.append(Event(phase, "kernel", pid, p, {"call": name, "args": args[:80], "ok": ok}))
        elif name in ("sendto", "sendmsg", "sendmmsg"):
            port = PORT.search(args) or DECOR_PORT.search(args)
            dport = int(port.group(1)) if port else None
            for s in strings:
                buf = unhex(s)
                q = parse_dns_query(buf) if (dport == 53 or dport is None) else None
                if q:
                    events.append(Event(phase, "dns", pid, p, {"qname": q}))
                elif buf:
                    events.append(Event(phase, "send", pid, p, {"buf": buf, "port": dport}))
    return events


def host_expected(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == PROBE_HOST:
        return True     # the URL honeyrun itself hands to MCP tools as a test argument
    # Only a resolver search domain may follow it: honeyrun.example.net.evil.com must not hide.
    if host.startswith(PROBE_HOST + ".") and host.endswith(SEARCH_SUFFIXES):
        return True
    return any(host == h or host.endswith("." + h) for h in EXPECTED_HOSTS)


def is_remote_ip(addr: str) -> bool:
    """Offline, every name resolves to loopback, so any other address was hard-coded."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


@dataclass
class Analysis:
    findings: list[Finding]
    hosts: list[dict]
    processes: int
    files_opened: int
    tools: list[dict]
    phases: list[dict]
    tree: list[dict] = field(default_factory=list)
    files: dict = field(default_factory=dict)


def analyze(trace: dict[str, bytes], baits: list[Bait], network: str) -> Analysis:
    meta = json.loads(trace.get("meta.json", b"{}") or b"{}")
    phases = meta.get("phases", [])
    events: list[Event] = []
    for ph in phases:
        raw = trace.get(f"{ph['name']}.strace", b"").decode("utf-8", "replace")
        events += parse_strace(raw, ph["name"])

    findings: dict[tuple, Finding] = {}

    def add(sev, rule, key, title, detail="", phase=""):
        k = (rule, key)
        if k not in findings or SEVERITIES.index(sev) > SEVERITIES.index(findings[k].severity):
            findings[k] = Finding(sev, rule, title, detail, phase)

    bait_by_path = {f"{HOME}/{b.path}": b for b in baits if b.path}
    needle_map = {n: b for b in baits for n in bait_needles(b)}

    # -------------------------------------------------- file access
    files_opened = 0
    for ev in (e for e in events if e.kind == "open"):
        path = ev.data["path"]
        files_opened += 1
        b = bait_by_path.get(path)
        if b and ev.data["write"]:
            add("high", "bait-tamper", path, f"modifies credential file {path.replace(HOME, '~')}",
                f"by {ev.proc.label()}", ev.phase)
            continue
        if SANDBOX_PROBES.search(path):
            add("medium", "sandbox-detection", path, "checks whether it is running in a sandbox or under a debugger",
                f"{path} by {ev.proc.label()}", ev.phase)
        if b and not ev.data["write"]:
            rel = path.replace(HOME, "~")
            readers = EXPECTED_READERS.get(b.path, ())
            reader = next((r for r in readers for a in [ev.proc.exe, *ev.proc.argv[:2]]
                           if os.path.basename(a) == r or f"/{r}-cli" in a), None)
            if reader:
                add("info", "bait-read-expected", rel, f"{rel} read by {reader} (its own config)", phase=ev.phase)
            else:
                add("high", "bait-read", rel, f"{b.label} opened: {rel}", f"by {ev.proc.label()}", ev.phase)
            continue
        pm = PROC_FOREIGN.match(path)
        if pm and int(pm.group(1)) != ev.proc.pid:
            add("high", "credential-probe", f"proc-{pm.group(2)}", f"inspects another process via /proc/{pm.group(1)}/{pm.group(2)}",
                f"by {ev.proc.label()}", ev.phase)
            continue
        if PROC_ENVIRON.match(path) and path != "/proc/1/environ":
            add("medium", "credential-probe", "environ", f"reads process environment: {path}",
                f"by {ev.proc.label()}", ev.phase)
            continue
        if ev.data["write"]:
            for rx, label in PERSISTENCE:
                if rx.search(path):
                    add("high", "persistence", path, f"writes to {label}: {path.replace(HOME, '~')}",
                        f"by {ev.proc.label()}", ev.phase)
                    break
            continue
        for rx, label in PROBE_PATTERNS:
            if rx.search(path) and not (label in REPO_NOISY and path.startswith(WORK + "/")):
                add("high", "credential-probe", label, f"probes {label}: {path.replace(HOME, '~')}",
                    f"by {ev.proc.label()}" + ("" if ev.data["ok"] else f" ({ev.data['err'] or 'failed'})"), ev.phase)
                break

    # -------------------------------------------------- processes
    execs = [e for e in events if e.kind == "exec"]
    seen_pids = {e.pid for e in execs if e.data["ok"]}
    for ev in execs:
        argv = ev.data["argv"]
        joined = " ".join(argv)
        base = os.path.basename(ev.data["path"])
        script = argv[2] if len(argv) >= 3 and argv[1] == "-c" else ""
        if re.search(r"/dev/(tcp|udp)/", joined) or (base in ("nc", "ncat", "netcat") and re.search(r"\s-[ec]\s", f" {joined} ")) \
                or (base == "socat" and "exec:" in joined.lower()):
            add("high", "reverse-shell", joined[:60], "reverse shell pattern", joined[:160], ev.phase)
        elif re.search(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^|;&]*\|\s*python", script):
            add("high", "remote-script", script[:60], "downloads a script and pipes it to a shell", script[:160], ev.phase)
        elif base in ("curl", "wget") and ev.data["ok"]:
            add("medium", "downloader", base, f"runs {base} during {ev.phase}", joined[:160], ev.phase)
        if (base == "base64" and ("-d" in argv or "--decode" in argv)) or re.search(r"base64\s+(-d|--decode)", script) \
                or (base.startswith("python") and "-c" in argv and re.search(r"b64decode|exec\(|marshal", joined)
                    and "<pip-setuptools-caller>" not in joined) \
                or (base == "node" and "-e" in argv and re.search(r"eval\(|Buffer\.from\([^)]*base64", joined)):
            add("medium", "obfuscation", base, "decodes and runs an inline payload", joined[:160], ev.phase)
            for decoded in payloads(joined)[:1]:
                add("info", "decoded-payload", decoded[:30], "decoded the inline payload", decoded[:300], ev.phase)
        name0 = argv[0] if argv else ""
        if ev.data["ok"] and (name0.startswith("[") or (DISGUISE.match(os.path.basename(name0) or base)
                                                       and not ev.data["path"].startswith(("/usr/", "/bin/", "/sbin/", "/lib")))):
            add("high", "disguised-process", name0[:40] or base,
                f"runs a process disguised as a system process: {name0[:40] or base}", f"{ev.data['path']} {joined[:120]}", ev.phase)
        if MINER.search(joined):
            add("high", "crypto-miner", base, "starts a cryptocurrency miner", joined[:160], ev.phase)
        if re.match(r"^(/proc/self/fd/|/proc/\d+/fd/|/dev/shm/|/memfd:|/run/user/)", ev.data["path"]):
            add("high", "fileless-exec", ev.data["path"][:40], "executes a file from memory or /dev/shm",
                ev.data["path"], ev.phase)
        if ev.data["ok"] and base in ("sudo", "su", "nsenter", "docker", "mount", "setcap", "chroot"):
            add("medium", "privilege", base, f"tries to run {base}", joined[:160], ev.phase)

    for ev in events:
        if ev.kind == "memfd":
            add("medium", "fileless-exec", "memfd", "creates an anonymous in-memory file (memfd_create)",
                f"{ev.data['name']} by {ev.proc.label()}", ev.phase)
        elif ev.kind == "kernel":
            call = ev.data["call"]
            if call == "ptrace" and "PTRACE_TRACEME" in ev.data["args"]:
                add("medium", "sandbox-detection", "traceme", "checks for a debugger (ptrace TRACEME)",
                    f"by {ev.proc.label()}", ev.phase)
            else:
                add(ESCAPE_SYSCALLS[call], "escape-attempt", call, f"calls {call}() (namespace, mount or kernel primitive)",
                    f"{ev.data['args']} by {ev.proc.label()}", ev.phase)
        elif ev.kind == "bind" and ev.phase == "install" and not ev.data["addr"].startswith(("127.", "::1")):
            add("medium", "listener", str(ev.data["port"]), f"opens a listening port {ev.data['port']} during install",
                f"by {ev.proc.label()}", ev.phase)

    # -------------------------------------------------- network
    hosts: dict[str, dict] = {}

    def note_host(name: str, phase: str, how: str, proc: Proc | None = None):
        h = hosts.setdefault(name, {"host": name, "phases": set(), "how": set(), "by": ""})
        h["phases"].add(phase)
        h["how"].add(how)
        if proc and not h["by"]:
            h["by"] = proc.label(60)

    for ev in events:
        if ev.kind == "dns":
            note_host(ev.data["qname"].lower().rstrip("."), ev.phase, "dns", ev.proc)
        elif ev.kind == "connect":
            d = ev.data
            if d["family"] == "unix" and "docker.sock" in d["addr"]:
                add("high", "docker-socket", "docker.sock", "tries to reach the Docker socket", d["addr"], ev.phase)
            elif d["family"] != "unix" and d["port"] != 53 and is_remote_ip(d["addr"]) and network == "offline":
                note_host(f"{d['addr']}:{d['port']}", ev.phase, "direct-ip", ev.proc)

    egress: list[tuple[str, bytes, str]] = []   # (where, payload, phase)
    for line in trace.get("net.jsonl", b"").decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "dns":
            note_host(rec["qname"].lower().rstrip("."), "?", "dns")
        elif rec.get("kind") == "tcp":
            payload = base64.b64decode(rec.get("data_b64", ""))
            host = rec.get("host") or rec.get("sni") or f"127.0.0.1:{rec['port']}"
            host = host.split(":")[0] if rec.get("host") else host
            proto = "https" if rec.get("sni") is not None or payload[:1] == b"\x16" else "http"
            where = (f"{rec.get('method', '')} {proto}://{host}{rec.get('path', '')}".strip()
                     if rec.get("method") or proto == "http" else f"TLS to {host} (handshake refused, body not seen)")
            note_host(host.lower(), "?", proto)
            hosts[host.lower()]["requests"] = hosts[host.lower()].get("requests", []) + [where]
            egress.append((where, payload, ""))

    for name in hosts:
        if MINER.search(name):
            add("high", "crypto-miner", name, f"contacts a mining pool {name}", "", ",".join(sorted(hosts[name]["phases"])))
    for name, data in trace.items():
        if name.endswith((".log", ".mcp.jsonl")):
            egress.append((f"its own output ({name})", data, name.split(".")[0]))
    for ev in (e for e in events if e.kind == "send"):
        egress.append((f"socket send to port {ev.data['port']} by {ev.proc.label(50)}", ev.data["buf"], ev.phase))
    # DNS tunnelling splits data across labels and across lookups: rebuild it per parent domain
    # (lookups resolve in parallel, so try both arrival order and name order)
    # Rebuild from the ordered lookup sequence, not the deduplicated host list: a secret whose
    # chunks repeat would otherwise lose the repeats.
    seq: list[str] = []
    for line in trace.get("net.jsonl", b"").decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("kind") == "dns" and rec.get("qtype", 1) == 1 and isinstance(rec.get("qname"), str):
            seq.append(rec["qname"].lower().rstrip("."))
    if not seq:
        for ev in (e for e in events if e.kind == "dns"):
            name = ev.data["qname"].lower().rstrip(".")
            if not seq or seq[-1] != name:   # A and AAAA go out back to back
                seq.append(name)
    for name in hosts:
        egress.append((f"DNS lookup {name}", name.encode() + name.replace(".", "").encode(), ""))
    by_parent: dict[str, list[str]] = {}
    for name in seq:
        labels = name.split(".")
        if len(labels) > 2:
            by_parent.setdefault(".".join(labels[-2:]), []).append(name)
    for parent, names in by_parent.items():
        for order in (names, sorted(names, key=lambda n: [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in n.split(".")])):
            joined = "".join(l for n in order for l in n.split(".")[:-2] if len(l) >= 4)
            if len(joined) >= 16:
                egress.append((f"DNS lookups under {parent}", joined.encode(), ""))

    for where, payload, phase in egress:
        hay = payload.decode("latin-1")
        low = hay.lower()
        for needle, b in needle_map.items():
            if needle in hay or (needle.islower() and needle in low):
                if where.startswith("its own output"):
                    add("high", "secret-in-output", b.label, f"prints {b.label} to its output",
                        f"{where}: anything that logs this run (CI) now holds the secret", phase)
                else:
                    add("critical", "canary-exfil", b.label, f"{b.label} left the sandbox", where, phase)

    # phases with unknown hosts
    phase_order = {p["name"]: i for i, p in enumerate(phases)}
    for name, h in hosts.items():
        h["phases"] = sorted(x for x in h["phases"] if x != "?") or ["?"]
        h["how"] = sorted(h["how"])
        h["expected"] = host_expected(name)
        if h["expected"]:
            continue
        sev = "medium"
        what = "connects to a hard-coded IP" if "direct-ip" in h["how"] else "contacts"
        add(sev, "network", name, f"{what} {name}",
            "; ".join(h.get("requests", [])[:2]) or (f"by {h['by']}" if h["by"] else ""), ",".join(h["phases"]))

    # -------------------------------------------------- lingering processes
    for ph in phases:
        if ph["name"] == "install" and ph.get("lingering"):
            cmds = ", ".join(p["cmdline"][:60] for p in ph["lingering"][:3])
            add("medium", "lingering-process", ph["name"], "leaves a process running after install", cmds, ph["name"])

    # -------------------------------------------------- MCP tools
    tools: list[dict] = []
    for ph in phases:
        listed = False
        for line in trace.get(f"{ph['name']}.mcp.jsonl", b"").decode("utf-8", "replace").splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            mid = msg.get("id")
            if mid == 2 and not listed and isinstance((msg.get("result") or {}).get("tools"), list):
                # the first list is what a client would have shown; a later clean one must not replace it
                listed = True
                known = {json.dumps(t, sort_keys=True) for t in tools}
                tools += [t for t in msg["result"]["tools"] if isinstance(t, dict)
                          and json.dumps(t, sort_keys=True) not in known]   # the later pass lists them again
            elif isinstance(mid, int) and not isinstance(mid, bool) and mid >= 100 and ("result" in msg or "error" in msg):
                blob = json.dumps({"result": msg.get("result"), "error": msg.get("error")}, ensure_ascii=False)
                if HIDDEN_CHARS.search(blob) or any(rx.search(unicodedata.normalize("NFKC", blob)) for rx in STRONG_INJECTION):
                    shown = HIDDEN_CHARS.sub("", re.sub(r"\s+", " ", blob))[:140]
                    add("high", "mcp-result-injection", str(mid), "an MCP tool result carries instructions aimed at the model",
                        shown, ph["name"])
    for t in tools:
        blob = json.dumps(t, ensure_ascii=False)
        desc = unicodedata.normalize("NFKC", blob)
        hits = [rx.pattern for rx in STRONG_INJECTION if rx.search(desc)]
        if HIDDEN_CHARS.search(blob):
            add("high", "mcp-hidden-text", t.get("name", "?"), f"MCP tool '{t.get('name')}' hides invisible characters in its description",
                phase="run")
        if hits:
            snippet = re.sub(r"\s+", " ", str(t.get("description", "")))[:140]
            add("high", "mcp-tool-poisoning", t.get("name", "?"),
                f"MCP tool '{t.get('name')}' carries instructions aimed at the model", snippet, "run")

    # -------------------------------------------------- incomplete runs must not look clean
    for ph in phases:
        name = ph["name"]
        if name == "install" and (ph.get("timed_out") or ph.get("exit") not in (0, None)):
            how = "timed out" if ph.get("timed_out") else f"exited {ph.get('exit')}"
            add("medium", "incomplete", "install", f"install failed ({how}): the code after the failure point was not observed",
                ph.get("cmd", "")[:120], name)
        probe = ph.get("mcp_probe", ph.get("probe"))
        if (ph.get("mcp") or isinstance(probe, dict)) and isinstance(probe, dict) and probe.get("tools_listed") is None:
            add("medium", "incomplete", f"probe-{name}", "the MCP server never answered tools/list: its tools were not exercised",
                str(probe.get("error") or ""), name)
        if name.startswith("later") and ph.get("clock_shifted") is False:
            add("medium", "incomplete", f"clock-{name}",
                "the clock could not be moved ahead, so time bombs were not tested", "", name)
        if ph.get("evidence_truncated"):
            add("high", "incomplete", f"truncated-{name}", "evidence truncated: part of the trace was dropped, so activity may be missing",
                "", name)
    if meta.get("evidence_truncated") and not any(f.title.startswith("evidence truncated") for f in findings.values()):
        add("high", "incomplete", "truncated", "evidence truncated: part of the trace was dropped, so activity may be missing")
    if trace.get("_truncated") or trace.get("_incomplete"):
        add("high", "incomplete", "host-truncated", "evidence truncated: the trace was too large to read in full",
            (trace.get("_truncated") or trace.get("_incomplete") or b"").decode("utf-8", "replace")[:120])
    if meta.get("sinkhole_degraded"):
        add("medium", "incomplete", "sinkhole", "the network sinkhole degraded during the run: some traffic may not have been recorded")

    # -------------------------------------------------- filesystem changes (before/after snapshot)
    files = json.loads(trace.get("files.json", b"{}") or b"{}")
    bait_paths = set(bait_by_path)
    outside: list[str] = []
    for kind in ("created", "modified", "deleted"):
        for path, size, mode, head in files.get(kind, []):
            short = path.replace(HOME, "~")
            if path in bait_paths:
                add("high", "bait-tamper", path, f"{'deletes' if kind == 'deleted' else 'modifies'} credential file {short}",
                    kind)
                continue
            persist = next((label for rx, label in PERSISTENCE if rx.search(path)), None)
            if persist and kind != "deleted":
                add("high", "persistence", path, f"writes to {persist}: {short}", f"{kind} file")
                continue
            if kind != "deleted" and head in EXECUTABLE_MAGIC and not path.startswith(WORK):
                if re.match(rf"{HOME}/\.local/lib/python[\d.]+/site-packages/", path):
                    if SITE_NATIVE_OK.search(path):
                        continue    # compiled extensions from wheels land here on every pip install
                    add("medium", "dropped-binary", path, "native executable inside site-packages",
                        f"{short} ({size} bytes)")
                    continue
                if path.startswith(f"{HOME}/.local/bin/"):
                    add("info", "native-entry-point", path, f"installs a native executable on PATH: {short}", "")
                    continue
                add("high", "dropped-binary", path, f"drops a {EXECUTABLE_MAGIC[head]} executable outside the workspace",
                    f"{short} ({size} bytes)")
                continue
            if path.endswith(".pth") and kind != "deleted" and not re.search(r"distutils-precedence|__editable__", path):
                add("high", "auto-exec", path, f"installs {short}, which Python runs at every start", "")
                continue
            if not path.startswith(WORK) and not path.startswith(f"{HOME}/.local/"):
                outside.append(f"{kind[0]} {short}")
    if outside:
        add("medium", "outside-workspace", "home", f"changes {len(outside)} file(s) outside the workspace",
            ", ".join(outside[:4]) + (" ..." if len(outside) > 4 else ""))
    counts = files.get("counts", {})
    before_n = counts.get("workspace_files_before", 0)
    gone = sum(1 for e in files.get("deleted", []) if e[0].startswith(WORK + "/"))
    changed = sum(1 for e in files.get("modified", []) if e[0].startswith(WORK + "/"))
    if before_n >= 5 and (gone >= max(5, before_n * 0.3) or changed >= max(10, before_n * 0.5)):
        add("high", "wiper", "workspace", "deletes or rewrites most of the repository's own files (wiper / ransomware)",
            f"{gone} deleted, {changed} rewritten of {before_n}")
    if files.get("truncated"):
        add("medium", "incomplete", "snapshot", "too many files to compare; the change list is partial")

    # -------------------------------------------------- process tree (for reports and AI review)
    tree, seen = [], set()
    for ev in (e for e in events if e.kind == "exec" and e.data["ok"]):
        key = (ev.phase, " ".join(ev.data["argv"])[:200])
        if key in seen:
            continue
        seen.add(key)
        tree.append({"phase": ev.phase, "pid": ev.pid, "parent": ev.proc.parent,
                     "cmd": re.sub(r"\s+", " ", " ".join(ev.data["argv"]))[:200].replace(HOME, "~")})

    # -------------------------------------------------- time bombs
    # The "later" phase repeats the last phase with the clock 45 days ahead. Anything that shows up
    # only there was waiting for a date.
    # (any phase named later*, including the install-time replay "later-install")
    for f in [f for f in findings.values() if f.phase and all(x.startswith("later") for x in f.phase.split(",")) and f.severity != "info"
              and f.rule != "incomplete"]:
        add("high", "delayed-activation", f.rule + f.title,
            f"only acts when the clock is 45 days ahead: {f.title}", f.detail, f.phase)

    out = sorted(findings.values(), key=lambda f: (-SEVERITIES.index(f.severity), f.rule, f.title))
    return Analysis(out, sorted(hosts.values(), key=lambda h: h["host"]), len(seen_pids), files_opened, tools, phases,
                    tree[:300], files)


def verdict(findings: list[Finding]) -> str:
    worst = max((SEVERITIES.index(f.severity) for f in findings), default=0)
    return "FAIL" if worst >= 2 else "WARN" if worst == 1 else "PASS"
