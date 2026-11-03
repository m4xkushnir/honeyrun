"""Turn strace output, sinkhole logs and MCP transcripts into findings."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field

from .bait import Bait, needles

HOME = "/home/runner"
WORK = "/workspace"
SEVERITIES = ("info", "medium", "high", "critical")

# package registries and code hosts an install is expected to talk to
EXPECTED_HOSTS = (
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "nodejs.org",
    "pypi.org", "files.pythonhosted.org", "pypi.python.org",
    "github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
    "api.github.com", "release-assets.githubusercontent.com",
)

# reads by a package manager of its own config file are normal
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
        (r"^/proc/1/environ$|^/proc/\d+/environ$", "another process's environment"),
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
        (r"/\.codex/|/\.gemini/settings\.json$|/\.continue/config", "AI agent configuration"),
        (r"/\.gitconfig$|/\.config/git/", "global git configuration"),
    )
]

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

LINE = re.compile(r"^(\d+)\s+\S+\s+(.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?|0x[0-9a-f]+)(?:<[^>]*>)?(?:\s+([A-Z0-9_]+))?")
UNFINISHED = re.compile(r"^(\w+)\((.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
STR = re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
HEXESC = re.compile(r"\\x([0-9a-f]{2})")
FDCWD = re.compile(r"AT_FDCWD<([^>]*)>")
PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
DECOR_PORT = re.compile(r"(?:UDP|TCP|UDPv6|TCPv6):\[[^\]]*->[^\]]*:(\d+)\]")


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.replace("\\x", ""))


def text(s: str) -> str:
    return unhex(s).decode("utf-8", "replace")


@dataclass
class Proc:
    pid: int
    exe: str = "?"
    argv: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return os.path.basename(self.exe)

    def label(self, width: int = 72) -> str:
        cmd = " ".join(self.argv) if self.argv else self.exe
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
            procs[child] = Proc(child, p.exe, list(p.argv))
        elif name in ("execve", "execveat") and strings:
            path = text(strings[0])
            argv = [text(s) for s in strings[1:]]
            if ok:
                procs[pid] = p = Proc(pid, path, argv)
            events.append(Event(phase, "exec", pid, p, {"path": path, "argv": argv, "ok": ok}))
        elif name in ("open", "openat", "openat2", "creat") and strings:
            path = text(strings[0])
            if not path.startswith("/"):
                base = FDCWD.search(args)
                cwd = HEXESC.sub(lambda x: chr(int(x.group(1), 16)), base.group(1)) if base else WORK
                path = os.path.normpath(os.path.join(cwd, path))
            write = name == "creat" or bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", args))
            events.append(Event(phase, "open", pid, p, {"path": path, "write": write, "ok": ok, "err": err}))
        elif name == "connect":
            fam = "unix" if "AF_UNIX" in args else "inet6" if "AF_INET6" in args else "inet" if "AF_INET" in args else None
            if not fam:
                continue
            port = PORT.search(args)
            addr = text(strings[-1]) if strings else ""
            events.append(Event(phase, "connect", pid, p, {
                "family": fam, "addr": addr, "port": int(port.group(1)) if port else None, "ok": ok, "err": err}))
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
    needle_map = {n: b for b in baits for n in needles(b.secret)}

    # -------------------------------------------------- file access
    files_opened = 0
    for ev in (e for e in events if e.kind == "open"):
        path = ev.data["path"]
        files_opened += 1
        b = bait_by_path.get(path)
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
        if ev.data["write"]:
            for rx, label in PERSISTENCE:
                if rx.search(path):
                    add("high", "persistence", path, f"writes to {label}: {path.replace(HOME, '~')}",
                        f"by {ev.proc.label()}", ev.phase)
                    break
            continue
        for rx, label in PROBE_PATTERNS:
            if rx.search(path) and not path.startswith(WORK):
                if label == "another process's environment" and ev.proc.pid and path == f"/proc/{ev.proc.pid}/environ":
                    break
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
        elif base in ("curl", "wget") and ev.data["ok"] and ev.phase == "install":
            add("medium", "downloader", base, f"runs {base} during install", joined[:160], ev.phase)
        if (base == "base64" and ("-d" in argv or "--decode" in argv)) or re.search(r"base64\s+(-d|--decode)", script) \
                or (base.startswith("python") and "-c" in argv and re.search(r"b64decode|exec\(|marshal", joined)
                    and "<pip-setuptools-caller>" not in joined) \
                or (base == "node" and "-e" in argv and re.search(r"eval\(|Buffer\.from\([^)]*base64", joined)):
            add("medium", "obfuscation", base, "decodes and runs an inline payload", joined[:160], ev.phase)
        if base in ("sudo", "su", "nsenter", "docker", "mount", "setcap", "chroot"):
            add("medium", "privilege", base, f"tries to run {base}", joined[:160], ev.phase)

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
            where = f"{rec.get('method', '')} {proto}://{host}{rec.get('path', '')}".strip() if proto == "http" else f"TLS to {host}"
            note_host(host.lower(), "?", proto)
            hosts[host.lower()]["requests"] = hosts[host.lower()].get("requests", []) + [where]
            egress.append((where, payload, ""))

    for ev in (e for e in events if e.kind == "send"):
        egress.append((f"socket send to port {ev.data['port']} by {ev.proc.label(50)}", ev.data["buf"], ev.phase))
    # DNS tunnelling splits data across labels and across lookups: rebuild it per parent domain
    # (lookups resolve in parallel, so try both arrival order and name order)
    by_parent: dict[str, list[str]] = {}
    for name in hosts:
        egress.append((f"DNS lookup {name}", name.encode() + name.replace(".", "").encode(), ""))
        labels = name.split(".")
        if len(labels) > 2:
            by_parent.setdefault(".".join(labels[-2:]), []).append(name)
    for parent, names in by_parent.items():
        for order in (names, sorted(names, key=lambda n: [int(x) if x.isdigit() else x for x in n.split(".")])):
            joined = "".join(l for n in order for l in n.split(".")[:-2] if len(l) >= 8)
            egress.append((f"DNS lookups under {parent}", joined.encode(), ""))

    for where, payload, phase in egress:
        hay = payload.decode("latin-1")
        low = hay.lower()
        for needle, b in needle_map.items():
            if needle in hay or (needle.islower() and needle in low):
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
        for line in trace.get(f"{ph['name']}.mcp.jsonl", b"").decode("utf-8", "replace").splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("id") == 2:
                tools = [t for t in ((msg.get("result") or {}).get("tools") or []) if isinstance(t, dict)]
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

    out = sorted(findings.values(), key=lambda f: (-SEVERITIES.index(f.severity), f.rule, f.title))
    return Analysis(out, sorted(hosts.values(), key=lambda h: h["host"]), len(seen_pids), files_opened, tools, phases)


def verdict(findings: list[Finding]) -> str:
    worst = max((SEVERITIES.index(f.severity) for f in findings), default=0)
    return "FAIL" if worst >= 2 else "WARN" if worst == 1 else "PASS"
