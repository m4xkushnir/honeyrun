"""Look inside committed artifacts (archives, binaries, images, packed blobs) without extracting or running them.

Everything is read in memory with strict limits: archives are listed, never unpacked to disk; binaries are
streamed for printable strings; images are checked for data after their end marker. Nothing here executes
repo code, imports it, or follows a link out of the repo.
"""
from __future__ import annotations

import collections
import gzip
import io
import json
import math
import re
import tarfile
import zipfile
from pathlib import Path
from typing import NamedTuple

from . import deobf

TOTAL_BUDGET = 300 * 1024 * 1024      # bytes read across all artifacts in one scan
ARCHIVE_MAX_TOTAL = 200 * 1024 * 1024  # declared uncompressed size per archive
ARCHIVE_MAX_MEMBERS = 5000
ARCHIVE_MAX_RATIO = 100
ARCHIVE_MAX_DEPTH = 2
ARCHIVE_MAX_FILE = 100 * 1024 * 1024
NESTED_MAX = 10 * 1024 * 1024         # a nested archive is read into memory only up to this size
BINARY_MAX = 20 * 1024 * 1024
BINARY_MAX_FILES = 50
ENTROPY_MIN, ENTROPY_THRESHOLD, ENTROPY_SAMPLE, ENTROPY_MAX_FILES = 4096, 7.5, 1024 * 1024, 300
IMAGE_MAX = 20 * 1024 * 1024
TAIL_MIN = 64

ZIP_EXT = (".zip", ".jar", ".whl", ".vsix", ".apk", ".nupkg", ".xpi")
TAR_EXT = (".tgz", ".tar.gz", ".tar")
BIN_EXT = {".node", ".so", ".dll", ".dylib", ".wasm", ".exe"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg"}
# text-like files are never opened here: source scanning already reads them, and prose never has entropy 7.5
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".rb", ".go", ".rs", ".java", ".php", ".ps1",
            ".bat", ".cmd", ".pl", ".json", ".toml", ".yaml", ".yml", ".md", ".txt", ".rst", ".html", ".htm", ".css",
            ".scss", ".less", ".lock", ".map", ".csv", ".tsv", ".xml", ".ini", ".cfg", ".conf", ".c", ".h", ".cc",
            ".cpp", ".hpp", ".cs", ".kt", ".swift", ".lua", ".vue", ".svelte", ".ipynb", ".sql", ".proto", ".gradle",
            ".properties", ".mk", ".cmake", ".tex", ".bib", ".pem", ".gitignore", ".npmrc", ".env", ".in", ".rc",
            ".po", ".pot", ".mjml", ".graphql", ".gql", ".log", ".diff", ".patch", ".pyi", ".pyx", ".d.ts", ".sum",
            ".mod", ".cjsx", ".coffee", ".ex", ".exs", ".erl", ".hs", ".ml", ".scala", ".clj", ".dart", ".r", ".jl"}
EXEC_NAMES = ("exe", "dll", "sys", "scr")

_RELEVANT = re.compile(rb"[\x20-\x7e]{6,}")
_URL = re.compile(r"(?:https?|wss?|ftp|stratum\+tcp|stratum\+ssl)://[^\s\"'<>\\)\]]{3,}", re.I)
_IP = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w]|\.\d)")
# a small allowlist of hosts that binaries legitimately embed (toolchains, licences, schemas, registries)
_URL_OK = re.compile(r"(?:^|\.)(github\.com|githubusercontent\.com|npmjs\.(org|com)|yarnpkg\.com|pypi\.org|python\.org|"
                     r"pythonhosted\.org|googleapis\.com|google\.com|w3\.org|mozilla\.org|microsoft\.com|apache\.org|"
                     r"openssl\.org|gnu\.org|golang\.org|go\.dev|rust-lang\.org|llvm\.org|nodejs\.org|unicode\.org|"
                     r"ietf\.org|xmlsoap\.org|openxmlformats\.org|sqlite\.org|zlib\.net|apple\.com|mit\.edu|"
                     r"gstatic\.com|crates\.io|rubygems\.org|maven\.org|sourceforge\.net|example\.(com|org))$", re.I)
_INDICATORS = {
    "dev-tcp": re.compile(r"/dev/(?:tcp|udp)/"),
    "curl": re.compile(r"\bcurl "),
    "wget": re.compile(r"\bwget "),
    "powershell": re.compile(r"powershell", re.I),
    "stratum": re.compile(r"stratum\+(?:tcp|ssl)"),
}
_CRED = re.compile(r"~/\.ssh|\.ssh/(?:id_|authorized)|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|"
                   r"\.kube/config|/etc/shadow|\.gnupg|\.docker/config", re.I)
_WALLET = re.compile(r"wallet\.dat|Login Data|key4\.db|logins\.json|cookies\.sqlite|nkbihfbeogaeaoehlefnkodbefgpgknn|"
                     r"\.electrum|google-chrome/|Chrome/User Data|Application Support/(?:Google|Firefox)|exodus", re.I)
_B64_LONG = re.compile(r"[A-Za-z0-9+/=]{200,}")


class Hit(NamedTuple):
    severity: str
    rule: str
    key: str
    title: str
    detail: str = ""


class Budget:
    def __init__(self, total: int | None = None):
        self.total, self.used, self.incomplete = TOTAL_BUDGET if total is None else total, 0, False

    def take(self, n: int) -> bool:
        if self.used + n > self.total:
            self.incomplete = True
            return False
        self.used += n
        return True


def _bump(sev: str, hooked: bool) -> str:
    """Anything an install hook points at is at least medium."""
    return "medium" if hooked and sev == "info" else sev


def _read_head(p: Path, n: int = 16) -> bytes:
    try:
        with open(p, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def exec_magic(b: bytes, name: str = "") -> str | None:
    """ELF / PE / Mach-O / wasm by at most 4 leading bytes. CAFEBABE is skipped: Java classes share it."""
    if b[:4] == b"\x7fELF":
        return "ELF"
    if b[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    if b[:4] == b"\x00asm":
        return "wasm"
    if b[:2] == b"MZ" and name.lower().rsplit(".", 1)[-1] in EXEC_NAMES:
        return "PE"
    return None


# magic of formats that are compressed or media by design: high entropy there is expected
_KNOWN_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"wOFF", b"wOF2",
                b"\x00\x01\x00\x00", b"OTTO", b"ID3", b"\xff\xfb", b"\xff\xf3", b"\x00\x00\x01\x00", b"7z\xbc\xaf",
                b"\xfd7zXZ", b"BZh", b"\x28\xb5\x2f\xfd", b"Rar!", b"OggS", b"fLaC", b"\x1a\x45\xdf\xa3", b"BM")


def known_format(h: bytes) -> bool:
    if h.startswith(_KNOWN_MAGIC):
        return True
    return (h[:4] == b"RIFF" and h[8:12] in (b"WEBP", b"WAVE", b"AVI ")) or h[4:8] == b"ftyp"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())


# ---------------------------------------------------------------- archives

class _TooBig(Exception):
    pass


class _Capped(io.RawIOBase):
    """Decompressed stream that refuses to hand out more than the cap, or more than ratio x what was read raw."""

    def __init__(self, inner, raw, limit=ARCHIVE_MAX_TOTAL):
        self.inner, self.raw, self.limit, self.n = inner, raw, limit, 0

    def readable(self):
        return True

    def readinto(self, b):
        data = self.inner.read(len(b))
        self.n += len(data)
        if self.n > self.limit:
            raise _TooBig("declared size")
        if self.n > 4 * 1024 * 1024 and self.n > ARCHIVE_MAX_RATIO * max(self.raw.tell(), 1):
            raise _TooBig("ratio")
        b[:len(data)] = data
        return len(data)


def _bad_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or bool(re.match(r"^[A-Za-z]:", n)) or ".." in n.split("/")


_LIFE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
_FETCH_EXEC = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|/dev/(tcp|udp)/|base64\s+(-d|--decode)|"
                         r"\beval\s*\(|powershell|Invoke-Expression", re.I)


def _is_archive_name(n: str) -> bool:
    n = n.lower()
    return n.endswith(ZIP_EXT + TAR_EXT + (".gz", ".7z"))


class _Walk:
    """Collects what one archive (and anything nested in it) contains."""

    def __init__(self, label: str, hooked: bool, budget: Budget):
        self.label, self.hooked, self.budget = label, hooked, budget
        self.hits: list[Hit] = []
        self.execs: list[str] = []
        self.scripts: list[tuple[str, str, str]] = []  # severity, text, member
        self.traversal: list[str] = []
        self.pth: list[str] = []
        self.links: list[str] = []
        self.total = 0
        self.members = 0
        self.suspicious: str | None = None

    def member(self, name: str, size: int, head: bytes, read_text) -> None:
        self.members += 1
        base = name.rsplit("/", 1)[-1]
        if _bad_name(name):
            self.traversal.append(name)
        kind = exec_magic(head, base)
        if kind:
            self.execs.append(f"{name} ({kind})")
        if base.endswith(".pth"):
            self.pth.append(name)
        elif base == "setup.py":
            self.scripts.append(("medium", "runs Python at install time", name))
        elif base == "package.json" and size <= 1_000_000:
            try:
                pkg = json.loads(read_text() or "null")
            except (ValueError, RecursionError):
                pkg = None
            scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
            for hook in _LIFE:
                cmd = scripts.get(hook) if isinstance(scripts, dict) else None
                if isinstance(cmd, str):
                    sev = "high" if _FETCH_EXEC.search(cmd) else "medium"
                    self.scripts.append((sev, f"has a {hook} script: {cmd[:100]}", name))

    def report(self) -> list[Hit]:
        L, out = self.label, self.hits
        if self.suspicious:
            out.append(Hit("medium", "archive", L + "big", f"archive too large/suspicious to inspect: {L}",
                           f"{self.suspicious}; not opened further"))
        for name in self.traversal[:3]:
            out.append(Hit("medium", "archive", L + "trav" + name, f"{L} has a member with a path-traversal name",
                           name))
        if self.pth:
            out.append(Hit("medium", "archive", L + "pth", f"{L} carries .pth files (run at every Python start)",
                           ", ".join(self.pth[:5])))
        for sev, text, name in self.scripts[:3]:
            out.append(Hit(sev, "archive", L + "script" + name, f"{L} contains {name}, which {text.split(':')[0]}",
                           text))
        if self.execs:
            out.append(Hit(_bump("info", self.hooked), "archive", L + "exec",
                           f"{L} contains {len(self.execs)} executable file(s)", ", ".join(self.execs[:5])))
        if self.links:
            out.append(Hit("info", "archive", L + "link", f"{L} contains symlink members", ", ".join(self.links[:5])))
        if self.hooked and not out:
            out.append(Hit("medium", "archive", L + "hook", f"archive {L} is referenced by an install hook",
                           "the archive is opened at install time; its contents were listed and look ordinary"))
        elif self.hooked:
            out.append(Hit("medium", "archive", L + "hook", f"archive {L} is referenced by an install hook", L))
        return out


def _zip_entry_count(f) -> int | None:
    """Total entries from the end-of-central-directory record, read before zipfile allocates anything."""
    try:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65557))
        tail = f.read()
    except OSError:
        return None
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or len(tail) < i + 22:
        return None
    n = int.from_bytes(tail[i + 10:i + 12], "little")
    return 1 << 30 if n == 0xFFFF else n


def _walk_zip(f, w: _Walk, depth: int) -> None:
    n = _zip_entry_count(f)
    if n is not None and n > ARCHIVE_MAX_MEMBERS:
        w.suspicious = f"more than {ARCHIVE_MAX_MEMBERS} members"
        return
    try:
        zf = zipfile.ZipFile(f)
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        return
    with zf:
        infos = zf.infolist()
        if len(infos) > ARCHIVE_MAX_MEMBERS:
            w.suspicious = f"more than {ARCHIVE_MAX_MEMBERS} members"
            return
        reads = 0
        for zi in infos:
            w.total += zi.file_size
            if w.total > ARCHIVE_MAX_TOTAL:
                w.suspicious = "declared uncompressed size above 200 MB"
                return
            if zi.file_size > 1024 * 1024 and zi.file_size > ARCHIVE_MAX_RATIO * max(zi.compress_size, 1):
                w.suspicious = f"compression ratio above {ARCHIVE_MAX_RATIO} ({zi.filename[:60]})"
                return
            if zi.is_dir():
                continue
            if (zi.external_attr >> 16) & 0o170000 == 0o120000:
                w.links.append(zi.filename)
            head = b""
            if reads < 500 and zi.file_size >= 4 and not zi.flag_bits & 1:
                reads += 1
                try:
                    with zf.open(zi) as mf:
                        head = mf.read(4)
                except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
                    head = b""
            w.member(zi.filename, zi.file_size, head, lambda zi=zi: _zip_text(zf, zi))
            if _is_archive_name(zi.filename):
                if depth + 1 > ARCHIVE_MAX_DEPTH:
                    w.suspicious = f"archives nested more than {ARCHIVE_MAX_DEPTH} deep"
                    return
                if 0 < zi.file_size <= NESTED_MAX and w.budget.take(zi.file_size):
                    try:
                        inner = zf.read(zi)
                    except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
                        continue
                    _walk_bytes(inner, zi.filename, w, depth + 1)
                    if w.suspicious:
                        return


def _zip_text(zf, zi) -> str:
    try:
        with zf.open(zi) as mf:
            return mf.read(1_000_001).decode("utf-8", "replace")
    except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        return ""


def _walk_tar(stream, w: _Walk, depth: int, mode: str) -> None:
    try:
        tf = tarfile.open(fileobj=stream, mode=mode)
    except (tarfile.TarError, OSError, EOFError):
        return
    with tf:
        try:
            for m in tf:
                if w.members >= ARCHIVE_MAX_MEMBERS:
                    w.suspicious = f"more than {ARCHIVE_MAX_MEMBERS} members"
                    return
                w.total += max(m.size, 0)
                if w.total > ARCHIVE_MAX_TOTAL:
                    w.suspicious = "declared uncompressed size above 200 MB"
                    return
                if _bad_name(m.name):
                    w.traversal.append(m.name)
                if m.issym() or m.islnk():
                    w.links.append(f"{m.name} -> {m.linkname}")
                    if _bad_name(m.linkname):
                        w.traversal.append(f"{m.name} -> {m.linkname}")
                    continue
                if not m.isfile():
                    continue
                base = m.name.rsplit("/", 1)[-1]
                nested = _is_archive_name(m.name) and 0 < m.size <= NESTED_MAX
                # one read per member: a streamed tar cannot be rewound
                want = m.size if nested or (base == "package.json" and m.size <= 1_000_000) else min(m.size, 4)
                fh = tf.extractfile(m) if m.size >= 4 else None
                data = fh.read(want) if fh is not None else b""
                head = data[:4]
                text = data.decode("utf-8", "replace") if base == "package.json" else ""
                w.member(m.name, m.size, head, lambda t=text: t)
                if _is_archive_name(m.name):
                    if depth + 1 > ARCHIVE_MAX_DEPTH:
                        w.suspicious = f"archives nested more than {ARCHIVE_MAX_DEPTH} deep"
                        return
                    if nested and w.budget.take(m.size):
                        _walk_bytes(data, m.name, w, depth + 1)
                        if w.suspicious:
                            return
        except _TooBig as e:
            w.suspicious = f"decompressed {e}"
        except (tarfile.TarError, OSError, EOFError, zlib_error):
            return


try:
    from zlib import error as zlib_error
except ImportError:  # pragma: no cover
    zlib_error = OSError


def _walk_bytes(data: bytes, name: str, w: _Walk, depth: int) -> None:
    f = io.BytesIO(data)
    n = name.lower()
    if n.endswith(ZIP_EXT) or data[:4] == b"PK\x03\x04":
        _walk_zip(f, w, depth)
    elif n.endswith((".tgz", ".tar.gz", ".gz")) or data[:2] == b"\x1f\x8b":
        _walk_gz(f, w, depth)
    elif n.endswith(".tar"):
        _walk_tar(f, w, depth, "r|")


def _walk_gz(raw, w: _Walk, depth: int) -> None:
    try:
        gz = gzip.GzipFile(fileobj=raw)
        peek = gz.peek(512)[:512] if hasattr(gz, "peek") else b""
    except (OSError, EOFError, zlib_error):
        return
    capped = io.BufferedReader(_Capped(gz, raw))
    if peek[257:262] == b"ustar" or w.label.lower().endswith((".tgz", ".tar.gz")):
        _walk_tar(capped, w, depth, "r|")
    else:
        # a single gzipped file: only its magic matters
        kind = exec_magic(peek[:4], "")
        if kind:
            w.execs.append(f"{w.label[:-3] if w.label.endswith('.gz') else w.label} ({kind})")
        w.members += 1


def inspect_archive(p: Path, rel: str, size: int, hooked: bool, budget: Budget) -> list[Hit]:
    low = rel.lower()
    if low.endswith(".7z"):
        return [Hit(_bump("info", hooked), "archive", rel + "7z", f"{rel} is a 7z archive (not inspected)",
                    "7z contents are not listed; open it yourself before trusting it")]
    if size > ARCHIVE_MAX_FILE:
        return [Hit("medium", "archive", rel + "big", f"archive too large/suspicious to inspect: {rel}",
                    f"{size} bytes on disk")]
    if not budget.take(min(size, 4 * 1024 * 1024)):
        return []
    w = _Walk(rel, hooked, budget)
    try:
        with open(p, "rb") as f:
            if low.endswith(ZIP_EXT):
                _walk_zip(f, w, 0)
            elif low.endswith(".tar"):
                _walk_tar(f, w, 0, "r|")
            else:
                _walk_gz(f, w, 0)
    except OSError:
        return []
    return w.report()


# ---------------------------------------------------------------- binaries

def _private_ip(ip: str) -> bool:
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(o) != 4 or any(x > 255 for x in o):
        return True
    a, b = o[0], o[1]
    return (a in (0, 10, 127) or a >= 224 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
            or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127))


def binary_strings(p: Path) -> dict[str, list[str]]:
    """Indicators found in the printable strings of a file, streamed in 1 MB chunks."""
    found: dict[str, list[str]] = collections.defaultdict(list)

    def note(kind: str, val: str):
        if len(found[kind]) < 5 and val not in found[kind]:
            found[kind].append(val[:100])

    def look(s: str):
        for m in _URL.finditer(s):
            url = m.group(0)
            host = re.sub(r"^[a-z+]+://([^/:?#]*).*$", r"\1", url, flags=re.I).rsplit("@", 1)[-1]
            if not _URL_OK.search(host):
                note("url", url)
        for m in _IP.finditer(s):
            if not _private_ip(m.group(1)):
                note("ip", m.group(1))
        for kind, rx in _INDICATORS.items():
            if rx.search(s):
                note(kind, s)
        if _CRED.search(s):
            note("cred", s)
        if _WALLET.search(s):
            note("wallet", s)
        if _B64_LONG.search(s):
            note("base64", s[:40] + "...")

    carry = b""
    try:
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                data = carry + chunk
                carry = b""
                ms = list(_RELEVANT.finditer(data))
                if ms and ms[-1].end() == len(data) and len(ms[-1].group(0)) < 1024 * 1024:
                    carry = ms.pop().group(0)
                for m in ms:
                    look(m.group(0).decode("ascii"))
            if carry:
                look(carry.decode("ascii"))
    except OSError:
        pass
    return found


def judge_binary(rel: str, found: dict[str, list[str]], kind: str, hooked: bool, entry: bool) -> list[Hit]:
    out: list[Hit] = []
    cred = found.get("cred") or found.get("wallet")
    desc = "; ".join(f"{k}: {', '.join(v[:2])}" for k, v in found.items())[:280]
    named = hooked or entry
    if cred and found.get("url"):
        out.append(Hit("high", "binary-strings", rel, f"{rel} ({kind}) mentions credential paths and a remote URL", desc))
    elif found:
        out.append(Hit("medium" if named else "info", "binary-strings", rel,
                       f"{rel} ({kind}) embeds network or credential strings", desc))
    elif named:
        out.append(Hit("medium", "binary-strings", rel,
                       f"{rel} ({kind}) is a compiled binary run by {'an install hook' if hooked else 'the package entry point'}",
                       "no suspicious strings; the code itself was not analysed"))
    return out


# ---------------------------------------------------------------- images

def _png_end(f, size: int) -> int | None:
    if f.read(8) != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    for _ in range(100000):
        f.seek(pos)
        h = f.read(8)
        if len(h) < 8:
            return None
        ln, typ = int.from_bytes(h[:4], "big"), h[4:]
        pos += 12 + ln
        if typ == b"IEND":
            return pos
        if pos > size:
            return None
    return None


def _gif_end(data: bytes) -> int | None:
    if data[:3] != b"GIF" or len(data) < 14:
        return None
    pos = 13 + (3 * 2 ** ((data[10] & 7) + 1) if data[10] & 0x80 else 0)

    def skip_blocks(i: int) -> int:
        while i < len(data) and data[i]:
            i += data[i] + 1
        return i + 1

    while pos < len(data):
        b = data[pos]
        if b == 0x3B:
            return pos + 1
        if b == 0x21:
            pos = skip_blocks(pos + 2)
        elif b == 0x2C:
            if pos + 10 > len(data):
                return None
            flags = data[pos + 9]
            pos += 10 + (3 * 2 ** ((flags & 7) + 1) if flags & 0x80 else 0)
            pos = skip_blocks(pos + 1)
        else:
            return None
    return None


def _excerpt(tail: bytes) -> str:
    """Short readable view of appended bytes: a decoded payload if it is base64/hex, else its printable strings."""
    runs = sorted((m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e\r\n]{12,}", tail[:8192])), key=len,
                  reverse=True)
    for run in runs[:3]:
        dec = deobf._decode(run.strip())
        if dec:
            return "decoded: " + dec[:150].replace("\n", " ")
    return " | ".join(r.replace("\n", " ")[:80] for r in runs[:2]) or "binary data"


_SVG_ACTIVE = re.compile(r"<\s*script\b|<[^>]+\son[a-z]{3,}\s*=|javascript\s*:", re.I)


def inspect_image(p: Path, rel: str, size: int, budget: Budget) -> list[Hit]:
    ext = p.suffix.lower()
    if ext == ".svg":
        if size > 2 * 1024 * 1024 or not budget.take(size):
            return []
        try:
            m = _SVG_ACTIVE.search(p.read_text(errors="replace"))
        except OSError:
            return []
        if m:
            return [Hit("medium", "image-payload", rel, f"SVG {rel} carries script, event handlers or javascript: URLs",
                        m.group(0)[:100])]
        return []
    if size > IMAGE_MAX or not budget.take(size if ext != ".png" else min(size, 65536)):
        return []
    end = None
    try:
        with open(p, "rb") as f:
            head = f.read(12)
            f.seek(0)
            if head[:4] == b"\x89PNG":
                end = _png_end(f, size)
            elif head[:3] == b"\xff\xd8\xff":
                data = f.read()
                i = data.rfind(b"\xff\xd9")
                end = i + 2 if i >= 0 else None
            elif head[:3] == b"GIF":
                end = _gif_end(f.read())
            elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
                end = int.from_bytes(head[4:8], "little") + 8
            elif head[:2] == b"BM" and ext == ".bmp":
                f.seek(2)
                end = int.from_bytes(f.read(4), "little")
            if end is None or size - end <= TAIL_MIN:
                return []
            f.seek(end)
            tail = f.read(8192)
    except OSError:
        return []
    return [Hit("medium", "image-payload", rel, f"image {rel} carries hidden appended data",
                f"{size - end} bytes after the image end: {_excerpt(tail)}")]


# ---------------------------------------------------------------- driver

class Scanner:
    """One per static scan. Holds the shared byte budget and the sets of files that install hooks and entry points name."""

    def __init__(self, hooked: set[str], entries: set[str]):
        self.hooked, self.entries = hooked, entries
        self.budget = Budget()
        self.binaries = 0
        self.entropy_files = 0

    def wants(self, name: str) -> bool:
        return Path(name).suffix.lower() not in TEXT_EXT

    def scan_file(self, p: Path, rel: str, size: int) -> list[Hit]:
        ext = p.suffix.lower()
        name = p.name.lower()
        hooked, entry = rel in self.hooked, rel in self.entries
        head = _read_head(p)
        if name.endswith(ZIP_EXT + TAR_EXT + (".gz", ".7z")):
            return inspect_archive(p, rel, size, hooked, self.budget)
        if ext in IMG_EXT:
            return inspect_image(p, rel, size, self.budget)
        kind = exec_magic(head, name) or ("native module" if ext in BIN_EXT else None)
        if kind:
            return self._binary(p, rel, size, kind, hooked, entry)
        if size > ENTROPY_MIN and not known_format(head) and ext not in (".pyc",):
            return self._entropy(p, rel, size, hooked)
        return []

    def _binary(self, p, rel, size, kind, hooked, entry) -> list[Hit]:
        self.binaries += 1
        if size > BINARY_MAX or self.binaries > BINARY_MAX_FILES:
            return [Hit("medium" if hooked or entry else "info", "binary-strings", rel,
                        f"{rel} ({kind}) was not inspected ({'over 20 MB' if size > BINARY_MAX else 'more than 50 binaries'})",
                        f"{size} bytes")]
        if not self.budget.take(size):
            return []
        return judge_binary(rel, binary_strings(p), kind, hooked, entry)

    def _entropy(self, p, rel, size, hooked) -> list[Hit]:
        self.entropy_files += 1
        if self.entropy_files > ENTROPY_MAX_FILES or not self.budget.take(min(size, ENTROPY_SAMPLE)):
            return []
        try:
            with open(p, "rb") as f:
                sample = f.read(ENTROPY_SAMPLE)
        except OSError:
            return []
        e = entropy(sample)
        if e <= ENTROPY_THRESHOLD:
            return []
        return [Hit("medium" if hooked else "info", "packed-data", rel,
                    f"{rel} looks encrypted or packed ({e:.2f} bits/byte)",
                    "its contents cannot be read statically; an encrypted payload only shows once the code decrypts it "
                    "at run time, which the sandbox run covers")]
