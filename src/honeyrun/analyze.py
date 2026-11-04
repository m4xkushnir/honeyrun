"""Turn strace output, sinkhole logs and MCP transcripts into findings."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import posixpath
import re
import unicodedata
from dataclasses import dataclass, field

from .deobf import payloads
from .bait import Bait, bait_needles

HOME = "/home/runner"
PROBE_HOST = "honeyrun.example.net"
SEARCH_SUFFIXES = (".internal.cloudapp.net", ".internal", ".local", ".lan", ".home.arpa")
WORK = "/workspace"
REPO = WORK + "/repo"
SEVERITIES = ("info", "medium", "high", "critical")

# package registries and code hosts an install is expected to talk to
EXPECTED_HOSTS = (
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "nodejs.org",
    "pypi.org", "files.pythonhosted.org", "pypi.python.org", "pypi.io",
    "github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
    "api.github.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com",
    # browser, engine and model downloads that setup scripts legitimately fetch (some also accept
    # uploads: a request with a body to any host here is still flagged as "upload")
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
        (r"^/var/lib/cloud/|^/etc/cloud/|^/run/cloud-init/", "cloud-init user data"),
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
        # chat and dev apps keep live session tokens in plain files
        (r"/\.config/(discord|Slack|Signal|Element)/|/\.local/share/TelegramDesktop/|/Local Storage/leveldb", "chat app session store"),
        (r"/\.steam/.*ssfn|/ssfn\d+$", "Steam session"),
        (r"/\.config/filezilla/|/FileZilla/(recentservers|sitemanager)\.xml$", "FileZilla saved logins"),
        (r"/\.config/gcloud/", "Google Cloud credentials"),
        (r"/\.azure/", "Azure credentials"),
        (r"/\.config/doctl/", "DigitalOcean token"),
        (r"/\.terraform\.d/credentials\.tfrc\.json$", "Terraform Cloud token"),
        (r"/\.vault-token$", "Vault token"),
        (r"/\.config/hub$", "hub (GitHub) token"),
        (r"\.kdbx$", "KeePass database"),
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
REPO_NOISY = {"browser credential store", "MetaMask extension storage", "crypto wallet", "browser profile",
              "chat app session store", "KeePass database"}
# commands that, planted earlier in PATH, run instead of the real tool
COMMON_CMDS = ("git", "ssh", "sudo", "npm", "node", "python", "python3", "pip", "curl", "ls", "docker", "kubectl",
               "claude", "codex", "gemini", "code")
SHADOW_PATH = re.compile(rf"^{HOME}/(\.local/bin|bin)/({'|'.join(COMMON_CMDS)})$")
HOOKS_PATH = re.compile(rf"/\.git/hooks/|^{HOME}/(\.config/git|\.git-templates?|\.githooks?)/")
INPUT_DEV = re.compile(r"^/dev/(input/|uinput$)")
SCREEN_TOOLS = {"xinput", "xdotool", "xclip", "xsel", "wl-copy", "wl-paste", "pbcopy", "pbpaste", "scrot",
                "gnome-screenshot", "import", "screencapture", "grim"}
SELF_SCRIPT = re.compile(r"^(pre|post)?(install|setup|prepare|bootstrap|hook)[\w.-]*\.(js|mjs|cjs|py|sh)$", re.I)
HISTORY = re.compile(r"/\.(bash|zsh|python|node_repl|sh)_history$|/\.zsh_sessions/")
HISTORY_WIPE = re.compile(r"\b(rm|shred|truncate|unlink)\b[^;|&]*_history|>\s*\S*_history|\bhistory\s+-[cw]\b")
# cloud instance metadata: where a cloud VM hands out its role credentials
IMDS_ADDR = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "169.254.170.2"}
IMDS_NAME = re.compile(r"(^|\.)(metadata\.google\.internal|metadata\.goog|metadata\.azure\.com|metadata\.tencentyun\.com|"
                       r"instance-data)(\.|$)|169\.254\.169\.254|fd00:ec2")
# pastes, webhooks, file drops and tunnels: the usual places stolen data is dropped
EXFIL_SERVICE = re.compile(
    r"(^|\.)(pastebin\.com|paste\.ee|hastebin\.com|hastebin\.skyra\.pw|ghostbin\.\w+|transfer\.sh|file\.io|0x0\.st|"
    r"discord\.com|discordapp\.com|api\.telegram\.org|hooks\.slack\.com|webhook\.site|requestbin\.(com|net)|"
    r"requestcatcher\.com|pipedream\.net|ngrok\.io|ngrok-free\.app|ngrok\.app|ngrok\.dev|trycloudflare\.com|"
    r"serveo\.net|loca\.lt|interact\.sh|interactsh\.com|burpcollaborator\.net|oastify\.com|"
    r"oast\.(pro|live|site|online|fun|me)|dnslog\.(cn|link|pw)|ceye\.io|eyes\.sh|beeceptor\.com|"
    r"canarytokens\.(com|org)|hookbin\.com|bxss\.me|xss\.ht|requestinspector\.com|onion(\.\w+)?)(\.|$)")
# "what is my IP" services: payloads use them to fingerprint the victim before reporting home
IP_LOOKUP = re.compile(r"(^|\.)(ipinfo\.io|api\.ipify\.org|ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com|"
                       r"ipapi\.co|ip-api\.com|ipecho\.net|myexternalip\.com|wtfismyip\.com|ident\.me)(\.|$)")
# commands that describe the machine; harmless alone, a fingerprint when followed by a report home
RECON = re.compile(r"^(whoami|hostname|uname|id|ifconfig|ip|arp|netstat|ss|ps|env|printenv|groups|w|who|last|lsb_release|"
                   r"hostnamectl|getent|nproc|lscpu|df|mount)$")
AGENT_SOCKS = ("/run/honeyrun/ssh-agent", "/run/honeyrun/S.gpg-agent")
FORK_BOMB = 300
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
    path = posixpath.normpath(path)
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
        return posixpath.basename(self.exe)

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
    q = parse_dns_question(pkt)
    return q[0] if q else None


def parse_dns_question(pkt: bytes) -> tuple[str, int] | None:
    """(name, qtype) of a single-question DNS query."""
    if len(pkt) < 17 or pkt[2] & 0x80 or int.from_bytes(pkt[4:6], "big") != 1:
        return None
    labels, off = [], 12
    while off < len(pkt):
        n = pkt[off]
        if n == 0:
            name = ".".join(labels)
            if not (name and all(32 < ord(c) < 127 for c in name)) or len(pkt) < off + 3:
                return None
            return name, int.from_bytes(pkt[off + 1:off + 3], "big")
        if n > 63:
            return None
        labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return None


def parse_strace(raw: str, phase: str) -> list[Event]:
    return parse_strace_counted(raw, phase)[0]


def parse_strace_counted(raw: str, phase: str) -> tuple[list[Event], int]:
    """Events plus the number of processes (not threads) the phase created."""
    spawned = 0
    procs: dict[int, Proc] = {}
    pending: dict[int, tuple[str, str]] = {}
    events: list[Event] = []
    first_pid = None
    # the workload starts in the repo; chdir/fchdir move a process, fork copies it to the child
    cwds: dict[int, str] = {}

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
            spawned += "CLONE_THREAD" not in args
            procs[child] = Proc(child, p.exe, list(p.argv), pid)
            cwds[child] = cwds.get(pid, REPO)
        elif name in ("chdir", "fchdir") and ok:
            if name == "fchdir":
                d = DIRFD.match(args)
                new = unescape(d.group(1)) if d else ""
            else:
                new = text(strings[0]) if strings else ""
                if new and not new.startswith("/"):
                    new = posixpath.join(cwds.get(pid, REPO), new)
            if new.startswith("/"):
                cwds[pid] = norm(new)
        elif name == "io_uring_setup":
            events.append(Event(phase, "iouring", pid, p, {"ok": ok}))
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
                # strace's own decoration wins; otherwise the cwd we tracked for this pid
                cwd = unescape(base.group(1)) if base else cwds.get(pid, REPO)
                if not cwd.startswith("/"):
                    cwd = cwds.get(pid, REPO)
                path = posixpath.join(cwd, path)
            path = norm(path)
            write = name == "creat" or bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", args))
            events.append(Event(phase, "open", pid, p, {"path": path, "write": write, "ok": ok, "err": err,
                                                         "trunc": name == "creat" or "O_TRUNC" in args}))
        elif name == "socket" and (("AF_PACKET" in args) or (re.search(r"AF_INET6?\b", args) and "SOCK_RAW" in args)):
            events.append(Event(phase, "rawsock", pid, p, {"args": args[:60], "ok": ok}))
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
                q = parse_dns_question(buf) if (dport == 53 or dport is None) else None
                if q:
                    events.append(Event(phase, "dns", pid, p, {"qname": q[0], "qtype": q[1]}))
                elif buf:
                    events.append(Event(phase, "send", pid, p, {"buf": buf, "port": dport}))
    return events, spawned


# A credential sent to the service it belongs to is how package managers work (npm sends the
# ~/.npmrc token to the npm registry on every install). Anywhere else it is theft.
OWN_SERVICE = {
    "npm token": ("registry.npmjs.org", "registry.yarnpkg.com"),
    "git credential": ("github.com", "codeload.github.com"),
    "GitHub CLI token": ("github.com", "api.github.com"),
    "GITHUB_TOKEN env": ("github.com", "api.github.com", "uploads.github.com"),
    "Docker registry auth": ("index.docker.io", "registry-1.docker.io", "auth.docker.io"),
}


def _own_service(label: str, where: str) -> bool:
    m = re.match(r"^[A-Z]+ https://([^/:\s]+)", where)
    host = (m.group(1) if m else "").lower()
    return any(host == h or host.endswith("." + h) for h in OWN_SERVICE.get(label, ()))


def host_expected(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == PROBE_HOST:
        return True     # the URL honeyrun itself hands to MCP tools as a test argument
    # Only a resolver search domain may follow it: honeyrun.example.net.evil.com must not hide.
    if host.startswith(PROBE_HOST + ".") and host.endswith(SEARCH_SUFFIXES):
        return True
    return any(host == h or host.endswith("." + h) for h in EXPECTED_HOSTS)


TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_public_ip(addr: str) -> bool:
    """A routable address (documentation ranges count: honeyrun's own fixtures use them)."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.version == 4 and any(ip in n for n in TEST_NETS):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast
                or ip.is_reserved)


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
    try:
        meta = json.loads(trace.get("meta.json", b"{}") or b"{}")
    except ValueError:
        meta = None
    if not isinstance(meta, dict):
        meta = {}
        meta_bad = True
    else:
        meta_bad = False
    phases = meta.get("phases", [])
    if not isinstance(phases, list):
        phases = []
    events: list[Event] = []
    spawned: dict[str, int] = {}
    for ph in phases:
        raw = trace.get(f"{ph['name']}.strace", b"").decode("utf-8", "replace")
        evs, spawned[ph["name"]] = parse_strace_counted(raw, ph["name"])
        events += evs

    def phase_at(t) -> str:
        """The sinkhole logs wall-clock times; the agent records when each phase ran."""
        if isinstance(t, (int, float)) and not isinstance(t, bool):
            # exact containment first: adjacent phases would otherwise both claim the slack at their edges
            for slack in (0.0, 1.5):
                for ph in phases:
                    t0, t1 = ph.get("t0"), ph.get("t1")
                    if isinstance(t0, (int, float)) and isinstance(t1, (int, float)) and t0 <= t <= t1 + slack:
                        return ph["name"]
        return "?"

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
                           if posixpath.basename(a) == r or f"/{r}-cli" in a), None)
            if reader:
                add("info", "bait-read-expected", rel, f"{rel} read by {reader} (its own config)", phase=ev.phase)
            else:
                add("high", "bait-read", rel, f"{b.label} opened: {rel}", f"by {ev.proc.label()}", ev.phase)
            continue
        if INPUT_DEV.match(path):
            add("high", "input-capture", path, "opens keyboard/input devices (keylogging or keystroke injection)",
                f"{path} by {ev.proc.label()}", ev.phase)
            continue
        if ev.data["write"]:
            sm = SHADOW_PATH.match(path)
            if sm:
                add("high", "path-shadow", path, f"puts a fake {sm.group(2)} earlier in PATH: {path.replace(HOME, '~')}",
                    f"by {ev.proc.label()}", ev.phase)
                continue
            if path == "/etc/ld.so.preload":
                add("high", "loader-hijack", path, "writes /etc/ld.so.preload (injects a library into every program)",
                    f"by {ev.proc.label()}", ev.phase)
                continue
            if HOOKS_PATH.search(path) and not path.startswith(WORK + "/repo/.git/"):
                add("high", "hook-hijack", path, f"writes a git hook outside the repository: {path.replace(HOME, '~')}",
                    f"by {ev.proc.label()}", ev.phase)
                continue
            if HISTORY.search(path) and ev.data.get("trunc"):
                add("medium", "anti-forensics", path, "deletes its own traces (truncates shell history)",
                    f"{path.replace(HOME, '~')} by {ev.proc.label()}", ev.phase)
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
        base = posixpath.basename(ev.data["path"])
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
        # an interpreter that renames itself in argv[0] (python as "systemd") is hiding in `ps`
        renamed = bool(name0) and posixpath.basename(name0) != base and not DISGUISE.match(base) \
            and bool(DISGUISE.match(posixpath.basename(name0)))
        if ev.data["ok"] and (name0.startswith("[") or renamed or (DISGUISE.match(posixpath.basename(name0) or base)
                                                       and not ev.data["path"].startswith(("/usr/", "/bin/", "/sbin/", "/lib")))):
            add("high", "disguised-process", name0[:40] or base,
                f"runs a process disguised as a system process: {name0[:40] or base}", f"{ev.data['path']} {joined[:120]}", ev.phase)
        if ev.data["ok"] and base in SCREEN_TOOLS:
            add("medium", "input-capture", base, "reads or writes the clipboard / screen", joined[:160], ev.phase)
        if script and re.search(r"LD_PRELOAD\s*=|ld\.so\.preload", script) \
                and re.search(r"(\.bashrc|\.profile|\.zshrc|\.bash_profile|ld\.so\.preload|/etc/environment)", script):
            add("high", "loader-hijack", "ldpreload-" + script[:30], "persists an LD_PRELOAD library", script[:160], ev.phase)
        if script and HISTORY_WIPE.search(script) or (base in ("rm", "shred", "truncate") and any(HISTORY.search(a) for a in argv[1:])):
            add("medium", "anti-forensics", "history-" + base, "deletes its own traces (shell history)", joined[:160], ev.phase)
        if MINER.search(joined):
            add("high", "crypto-miner", base, "starts a cryptocurrency miner", joined[:160], ev.phase)
        if re.match(r"^(/proc/self/fd/|/proc/\d+/fd/|/dev/shm/|/memfd:|/run/user/)", ev.data["path"]):
            add("high", "fileless-exec", ev.data["path"][:40], "executes a file from memory or /dev/shm",
                ev.data["path"], ev.phase)
        if ev.data["ok"] and base in ("sudo", "su", "nsenter", "docker", "mount", "setcap", "chroot"):
            add("medium", "privilege", base, f"tries to run {base}", joined[:160], ev.phase)

    for ev in events:
        if ev.kind == "iouring":
            # Many runtimes probe io_uring at startup, and the sandboxes refuse it (gVisor has no io_uring,
            # Docker's default seccomp blocks it). It can only hide I/O when the ring is actually granted.
            sev = "medium" if ev.data["ok"] and ev.proc.name not in ("node", "nodejs") else "info"
            add(sev, "io-uring", "io_uring", "uses io_uring (can do I/O that strace cannot see)",
                f"by {ev.proc.label()}", ev.phase)
        elif ev.kind == "memfd":
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
        elif ev.kind == "rawsock":
            add("high", "raw-socket", "rawsock", "opens a raw/packet socket (ICMP or custom-protocol channel)",
                f"{ev.data['args']} by {ev.proc.label()}" + ("" if ev.data["ok"] else " (blocked)"), ev.phase)
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

    dns_phases: set[str] = set()    # events arrive in order, so this is "a lookup came earlier in the phase"
    for ev in events:
        if ev.kind == "dns":
            dns_phases.add(ev.phase)
            note_host(ev.data["qname"].lower().rstrip("."), ev.phase, "dns", ev.proc)
        elif ev.kind == "connect":
            d = ev.data
            if d["family"] == "unix" and "docker.sock" in d["addr"]:
                add("high", "docker-socket", "docker.sock", "tries to reach the Docker socket", d["addr"], ev.phase)
            elif d["family"] == "unix" and d["addr"].startswith(AGENT_SOCKS):
                gpg = "gpg" in d["addr"]
                add("high", "agent-hijack", "gpg" if gpg else "ssh",
                    "talks to your GPG agent (could sign or decrypt as you)" if gpg
                    else "talks to your SSH agent (could sign in to your servers)", d["addr"], ev.phase)
            elif d["family"] != "unix" and d["addr"] in IMDS_ADDR:
                # offline the connect fails; the attempt is the signal
                add("high", "imds", "imds", "tries to read cloud instance credentials (IMDS)",
                    f"{d['addr']}:{d['port']} by {ev.proc.label()}", ev.phase)
            elif d["family"] != "unix" and d["port"] != 53 and is_remote_ip(d["addr"]) and network == "offline":
                note_host(f"{d['addr']}:{d['port']}", ev.phase, "direct-ip", ev.proc)
            elif d["family"] != "unix" and d["port"] != 53 and network == "open" and is_public_ip(d["addr"]):
                # Open mode resolves for real, and we cannot map an address back to a name. A connect
                # with no lookup before it in the phase was certainly hard-coded; after lookups it is probably resolved.
                note_host(f"{d['addr']}:{d['port']}", ev.phase,
                          "ip-after-dns" if ev.phase in dns_phases else "direct-ip", ev.proc)

    egress: list[tuple[str, bytes, str]] = []   # (where, payload, phase)
    uploads: dict[str, tuple[str, str]] = {}
    for line in trace.get("net.jsonl", b"").decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "dns":
            note_host(rec["qname"].lower().rstrip("."), phase_at(rec.get("t")), "dns")
        elif rec.get("kind") == "tcp":
            payload = base64.b64decode(rec.get("data_b64", ""))
            sni = rec.get("sni") if isinstance(rec.get("sni"), str) and rec.get("sni") else None
            is_tls = rec.get("sni") is not None or bool(rec.get("tls")) or payload[:1] == b"\x16"
            hdr = (rec.get("host") or "").split(":")[0].lower() or None
            # Over TLS the destination is the SNI: the Host header is inside the encrypted body and
            # the client controls it. Over plain HTTP anyone can claim any Host.
            host = (sni or hdr or f"127.0.0.1:{rec['port']}") if is_tls else (hdr or f"127.0.0.1:{rec['port']}")
            host = host.lower()
            rec_phase = phase_at(rec.get("t"))
            # only a TLS request whose SNI exists can count as "sent to that service"
            scheme = "https" if sni else "https-nosni" if is_tls else "http"
            where = (f"{rec.get('method', '')} {scheme}://{host}{rec.get('path', '')}".strip()
                     if rec.get("method") or not is_tls else f"TLS to {host} (handshake refused, body not seen)")
            if is_tls and sni and hdr and hdr != sni.lower():
                add("high", "host-mismatch", f"{sni}|{hdr}", f"TLS to {sni} but Host header says {hdr} (domain fronting or spoofed Host)",
                    where, rec_phase if rec_phase != "?" else "")
            note_host(host, rec_phase, "https" if is_tls else "http")
            hosts[host]["requests"] = hosts[host].get("requests", []) + [where]
            head, sep, body = payload.partition(b"\r\n\r\n")
            declared = max(rec.get("bytes", 0) - len(head) - 4, 0) if sep else 0
            if rec.get("method") and (rec["method"].upper() in ("POST", "PUT", "PATCH") or max(len(body), declared) > 2048):
                uploads.setdefault(host, (where, "" if rec_phase == "?" else rec_phase))
            egress.append((where, payload, "" if rec_phase == "?" else rec_phase))

    for host, (where, ph) in uploads.items():
        add("medium", "upload", host, f"uploads data to {host}", where, ph)

    for ph_name, n in spawned.items():
        if n > FORK_BOMB:
            add("high", "fork-bomb", ph_name, "spawns hundreds of processes (fork bomb or resource abuse)",
                f"{n} processes in {ph_name}", ph_name)
    for ev in (e for e in events if e.kind == "dns" and e.data.get("qtype") == 16):
        n = ev.data["qname"].lower().rstrip(".")
        if not host_expected(n):
            add("medium", "dns-txt", n, "DNS TXT lookup (a common command-and-control channel)", n, ev.phase)
    for line in trace.get("net.jsonl", b"").decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("kind") == "dns" and rec.get("qtype") == 16 and isinstance(rec.get("qname"), str) \
                and not host_expected(rec["qname"].lower().rstrip(".")):
            n = rec["qname"].lower().rstrip(".")
            add("medium", "dns-txt", n, "DNS TXT lookup (a common command-and-control channel)", n, phase_at(rec.get("t")))
        elif rec.get("kind") == "agent-socket":
            add("high", "agent-hijack", str(rec.get("sock")), "talks to your SSH agent (could sign in to your servers)"
                if rec.get("sock") != "gpg" else "talks to your GPG agent (could sign or decrypt as you)",
                "connected to the decoy agent socket", phase_at(rec.get("t")))
    for name in hosts:
        seen_in = ",".join(sorted(x for x in hosts[name]["phases"] if x != "?"))
        if IMDS_NAME.search(name):
            add("high", "imds", "imds", "tries to read cloud instance credentials (IMDS)", name, seen_in)
        if EXFIL_SERVICE.search(name.split(":")[0]):
            add("high", "exfil-service", name, "sends to a paste/webhook/tunnel service often used for exfiltration",
                name, seen_in)
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
                if b.kind == "identity":
                    # printing your own hostname is normal; sending it somewhere is a fingerprint
                    if not where.startswith("its own output") and not _own_service(b.label, where):
                        add("high", "identity-exfil", "hostname", "sends this machine's hostname out (victim fingerprinting)",
                            where, phase)
                elif where.startswith("its own output"):
                    add("high", "secret-in-output", b.label, f"prints {b.label} to its output",
                        f"{where}: anything that logs this run (CI) now holds the secret", phase)
                elif _own_service(b.label, where):
                    add("info", "credential-to-own-service", b.label,
                        f"{b.label} was sent to its own service (normal for an install)", where, phase)
                else:
                    add("critical", "canary-exfil", b.label, f"{b.label} left the sandbox", where, phase)

    # fingerprinting: describe the machine, then report to somewhere unexpected
    recon_by_phase: dict[str, set[str]] = {}
    for ev in (e for e in events if e.kind == "exec" and e.data["ok"]):
        b = posixpath.basename(ev.data["path"])
        if RECON.match(b) or (b in ("cat", "head", "less") and any(a in ("/etc/passwd", "/etc/hostname", "/etc/os-release")
                                                                  for a in ev.data["argv"][1:])):
            recon_by_phase.setdefault(ev.phase, set()).add(b)
    for name, h in hosts.items():
        if IP_LOOKUP.search(name.split(":")[0]):
            add("medium", "recon", name, f"looks up this machine's public IP ({name})", "", ",".join(sorted(h["phases"])))
        if host_expected(name) or set(h["how"]) == {"ip-after-dns"}:
            continue    # an IP reached after a DNS lookup is that name's address, judged by the name
        # one finding per host across all phases: per-phase findings would make the replay passes
        # look like new behaviour and trip delayed-activation
        hit_phases, cmds = [], set()
        for ph in h["phases"]:
            seen = recon_by_phase.get(ph) or (set().union(*recon_by_phase.values()) if ph == "?" else None)
            if seen:
                hit_phases.append(ph)
                cmds |= seen
        if hit_phases:
            add("high", "recon-beacon", name, f"fingerprints this machine ({', '.join(sorted(cmds))}) and contacts {name}",
                "typical of dependency-confusion payloads", ",".join(sorted(hit_phases)))

    # phases with unknown hosts
    phase_order = {p["name"]: i for i, p in enumerate(phases)}
    for name, h in hosts.items():
        h["phases"] = sorted(x for x in h["phases"] if x != "?") or ["?"]
        h["how"] = sorted(h["how"])
        h["expected"] = host_expected(name)
        if h["expected"]:
            continue
        if set(h["how"]) == {"ip-after-dns"}:
            add("info", "network", name, f"connects to {name} (address from an earlier lookup)", f"by {h['by']}" if h["by"] else "",
                ",".join(h["phases"]))
            continue
        sev = "medium"
        what = "connects to a hard-coded IP" if "direct-ip" in h["how"] else "contacts"
        add(sev, "network", name, f"{what} {name}",
            "; ".join(h.get("requests", [])[:2]) or (f"by {h['by']}" if h["by"] else ""), ",".join(h["phases"]))

    # -------------------------------------------------- lingering processes
    # Every phase, not only install: a delayed `sleep 8; curl ...` or a daemon started by `run` is the same
    # behaviour. MCP phases are servers by design and excluded.
    linger = [ph for ph in phases if ph.get("lingering") and not ph.get("mcp")]
    if linger:
        cmds = ", ".join(p.get("cmdline", "")[:60] for p in linger[0]["lingering"][:3])
        names = ",".join(ph["name"] for ph in linger)
        after = "install" if names == "install" else "the command finished"
        add("medium", "lingering-process", "linger", f"leaves a process running after {after}", cmds, names)

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
        if any(not h["expected"] for h in hosts.values()):
            add("high", "incomplete", "sinkhole", "the network sinkhole lost traffic while the code contacted unexpected hosts: "
                "the record of what it sent is incomplete")
        else:
            add("medium", "incomplete", "sinkhole", "the network sinkhole degraded during the run: some traffic may not have been recorded")
    # A trace with content but no usable phase list must not read as a clean run. analyze({}) is the static-only case.
    # (the agent says how many phases it was asked to run, so a repo with nothing to run is not an error)
    if trace and (meta_bad or (not phases and meta.get("phases_requested", 1) > 0)):
        add("high", "incomplete", "no-meta", "incomplete: the sandbox returned no usable record of the run")

    # -------------------------------------------------- filesystem changes (before/after snapshot)
    files = json.loads(trace.get("files.json", b"{}") or b"{}")
    bait_paths = set(bait_by_path)
    # files the workload ran: the binary itself and script arguments such as `node scripts/setup.js`
    executed: set[str] = set()
    for ev in execs:
        for a in [ev.data["path"], *ev.data["argv"][1:4]]:
            if a and not a.startswith("-") and len(a) < 300:
                executed.add(norm(a if a.startswith("/") else posixpath.join(WORK, "repo", a)))
    outside: list[str] = []
    for kind in ("created", "modified", "deleted"):
        for path, size, mode, head in files.get(kind, []):
            short = path.replace(HOME, "~")
            if path in bait_paths:
                add("high", "bait-tamper", path, f"{'deletes' if kind == 'deleted' else 'modifies'} credential file {short}",
                    kind)
                continue
            if kind != "deleted":
                sm = SHADOW_PATH.match(path)
                if sm:
                    add("high", "path-shadow", path, f"puts a fake {sm.group(2)} earlier in PATH: {short}", f"{kind} file")
                    continue
                if path == "/etc/ld.so.preload" or (HOOKS_PATH.search(path) and not path.startswith(WORK + "/repo/.git/")
                                                    and not path.startswith(WORK + "/")):
                    rule, what = (("loader-hijack", "writes /etc/ld.so.preload") if path.startswith("/etc/")
                                  else ("hook-hijack", "writes a git hook outside the repository"))
                    add("high", rule, path, f"{what}: {short}", f"{kind} file")
                    continue
                if re.search(r"\.so(\.\d+)*$", path) and path.startswith(HOME + "/") \
                        and not re.search(r"/site-packages/|/\.cache/|/\.npm/|/node_modules/", path):
                    add("high" if head in EXECUTABLE_MAGIC else "medium", "loader-hijack", path,
                        f"drops a shared library in the home directory: {short}", f"{kind} file ({size} bytes)")
            if kind == "deleted" and HISTORY.search(path):
                add("medium", "anti-forensics", path, f"deletes its own traces ({short})", "shell history removed")
                continue
            if kind == "deleted" and path.startswith(WORK + "/") and (
                    path in executed or SELF_SCRIPT.search(posixpath.basename(path)) or "/.husky/" in path):
                add("medium", "anti-forensics", path, f"deletes its own traces ({path.replace(WORK + '/repo/', '')})",
                    "a script that ran during the phases was removed afterwards")
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

    # Deep mode replays the last phase under CI variables and three times in a row.
    for f in [f for f in findings.values() if f.phase and f.severity != "info" and f.rule != "incomplete"]:
        in_phases = set(f.phase.split(","))
        if in_phases == {"ci"}:
            add("high", "ci-triggered", f.rule + f.title, f"only acts inside CI (targets CI secrets): {f.title}", f.detail, f.phase)
        elif in_phases == {"repeat"}:
            add("high", "delayed-activation", "repeat" + f.rule + f.title,
                f"only acts after repeated runs: {f.title}", f.detail, f.phase)

    out = sorted(findings.values(), key=lambda f: (-SEVERITIES.index(f.severity), f.rule, f.title))
    return Analysis(out, sorted(hosts.values(), key=lambda h: h["host"]), len(seen_pids), files_opened, tools, phases,
                    tree[:300], files)


def verdict(findings: list[Finding]) -> str:
    worst = max((SEVERITIES.index(f.severity) for f in findings), default=0)
    return "FAIL" if worst >= 2 else "WARN" if worst == 1 else "PASS"
