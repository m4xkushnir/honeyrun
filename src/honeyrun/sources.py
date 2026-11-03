"""Fetch targets that are not git repositories: npm and PyPI packages, and local archives.

    npm:left-pad            npm:@scope/name@1.2.3
    pypi:requests           pypi:requests==2.32.3
    ./package.tgz  ./tool.whl  ./ext.vsix  ./src.zip

Nothing here runs package code: registry metadata comes from the JSON APIs, the archive
is downloaded with urllib, its published checksum is verified, and it is unpacked with
strict limits (no links, no absolute or '..' paths, size and count caps). Never `npm pack`
or `pip download`: pip runs setup.py just to read an sdist's metadata.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .sandbox import SandboxError

MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_UNPACKED = 500 * 1024 * 1024
MAX_MEMBERS = 20000
ARCHIVE_EXT = (".tgz", ".tar.gz", ".tar", ".zip", ".whl", ".vsix", ".crate", ".nupkg", ".jar")
UA = {"User-Agent": "honeyrun (+https://github.com/m4xkushnir/honeyrun)"}


def is_package_spec(target: str) -> bool:
    return target.startswith(("npm:", "pypi:"))


def is_archive(path: Path) -> bool:
    return path.is_file() and path.name.lower().endswith(ARCHIVE_EXT)


def _get(url: str, limit: int = MAX_DOWNLOAD, timeout: int = 60) -> bytes:
    if not url.startswith("https://"):
        raise SandboxError(f"refusing a non-https download: {url}")
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(limit + 1)
    except OSError as e:
        raise SandboxError(f"download failed: {url}: {e}")
    if len(data) > limit:
        raise SandboxError(f"download larger than {limit // (1024 * 1024)} MB: {url}")
    return data


def _safe_name(name: str) -> str | None:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        return None
    return "/".join(parts)


def unpack(data: bytes, dest: Path, strip_top: bool = False) -> None:
    """Unpack a tar or zip held in memory: regular files and directories only, within limits."""
    total, count = 0, 0

    def place(name: str) -> Path | None:
        safe = _safe_name(name)
        if safe and strip_top:
            safe = safe.split("/", 1)[1] if "/" in safe else None
        return dest / safe if safe else None

    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                count += 1
                total += info.file_size
                if count > MAX_MEMBERS or total > MAX_UNPACKED:
                    raise SandboxError("archive too large to unpack safely")
                target = place(info.filename)
                if target is None or info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue    # skip directories (made on demand) and symlinks
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    out.write(src.read(MAX_UNPACKED))
                if (info.external_attr >> 16) & 0o111:
                    os.chmod(target, 0o755)
        return
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as e:
        raise SandboxError(f"not a tar or zip archive: {e}")
    with tf:
        for m in tf:
            count += 1
            total += max(m.size, 0)
            if count > MAX_MEMBERS or total > MAX_UNPACKED:
                raise SandboxError("archive too large to unpack safely")
            if not m.isfile():
                continue    # no links, devices or fifos; directories come from parents
            target = place(m.name)
            if target is None:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                out.write(f.read(MAX_UNPACKED))
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)


def _npm(spec: str) -> tuple[bytes, str, str, str]:
    name, _, version = spec.rpartition("@") if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, "", "")
    meta = json.loads(_get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), 64 * 1024 * 1024))
    version = version or (meta.get("dist-tags") or {}).get("latest", "")
    info = (meta.get("versions") or {}).get(version)
    if not info:
        raise SandboxError(f"npm package {name}@{version or '?'} not found")
    dist = info.get("dist") or {}
    data = _get(dist.get("tarball", ""))
    integrity = dist.get("integrity", "")
    if integrity.startswith("sha512-"):
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != integrity[7:]:
            raise SandboxError("npm tarball does not match its published sha512")
    elif dist.get("shasum") and hashlib.sha1(data).hexdigest() != dist["shasum"]:
        raise SandboxError("npm tarball does not match its published shasum")
    return data, name, version, "npm"


def _pypi(spec: str) -> tuple[bytes, str, str, str]:
    name, _, version = spec.partition("==")
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version) + '/' if version else ''}json"
    meta = json.loads(_get(url, 32 * 1024 * 1024))
    version = version or (meta.get("info") or {}).get("version", "")
    files = meta.get("urls") or []
    pick = next((f for f in files if f.get("packagetype") == "sdist"), None) or next(iter(files), None)
    if not pick:
        raise SandboxError(f"PyPI project {name}=={version} has no downloadable files")
    data = _get(pick["url"])
    want = (pick.get("digests") or {}).get("sha256")
    if want and hashlib.sha256(data).hexdigest() != want:
        raise SandboxError("PyPI file does not match its published sha256")
    return data, name, version, "PyPI"


def fetch_package(target: str) -> tuple[Path, str, Path, dict]:
    """Download and unpack npm:/pypi: targets. Returns (dir, label, cleanup_dir, package info)."""
    kind, spec = target.split(":", 1)
    data, name, version, ecosystem = (_npm if kind == "npm" else _pypi)(spec.strip())
    tmp = Path(tempfile.mkdtemp(prefix="honeyrun-pkg-"))
    dest = tmp / "pkg"
    dest.mkdir()
    is_wheel = ecosystem == "PyPI" and zipfile.is_zipfile(io.BytesIO(data))
    unpack(data, dest, strip_top=not is_wheel)
    return dest, f"{kind}:{name}@{version}", tmp, {"ecosystem": ecosystem, "name": name, "version": version}


def fetch_archive(path: Path) -> tuple[Path, str, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="honeyrun-archive-"))
    dest = tmp / "pkg"
    dest.mkdir()
    data = path.read_bytes() if path.stat().st_size <= MAX_DOWNLOAD else b""
    if not data:
        raise SandboxError("archive larger than 200 MB")
    unpack(data, dest)
    # npm tarballs and most sdists wrap everything in one top directory: run from inside it
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        dest = entries[0]
    return dest, path.name, tmp
