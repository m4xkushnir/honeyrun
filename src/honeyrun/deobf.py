"""Unwrap encoded payloads without running them.

Malware in repos hides behind base64/hex inside eval(), exec(), Function(), atob()
or a `node -e`/`python -c` one-liner. Decoding is plain string work: nothing here
executes, imports or evaluates the payload. The decoded text goes into the report
(and, only if the user asked for --review, to their own AI to explain it).
"""
from __future__ import annotations

import base64
import binascii
import re

B64 = re.compile(r"['\"`]([A-Za-z0-9+/_-]{40,}={0,2})['\"`]|(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/])")
HEX = re.compile(r"['\"`]((?:[0-9a-fA-F]{2}){24,})['\"`]|((?:\\x[0-9a-fA-F]{2}){16,})")
SINK = re.compile(r"eval\s*\(|new\s+Function\s*\(|Function\s*\(|exec\s*\(|execSync|spawn|atob\s*\(|"
                  r"Buffer\.from\s*\(|b64decode|bytes\.fromhex|unhexlify|marshal\.loads|zlib\.decompress|"
                  r"base64\s+(-d|--decode)|\|\s*(ba)?sh\b", re.I)
MAX_OUT = 600


def _printable(b: bytes) -> str | None:
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(t) < 12:
        return None
    good = sum(ch.isprintable() or ch in "\n\r\t" for ch in t)
    return t if good / len(t) > 0.92 else None


def _decode(token: str) -> str | None:
    if token.startswith("\\x"):
        try:
            return _printable(bytes.fromhex(token.replace("\\x", "")))
        except ValueError:
            return None
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
        try:
            return _printable(bytes.fromhex(token))
        except ValueError:
            pass
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return _printable(dec(token + "=" * (-len(token) % 4)))
        except (binascii.Error, ValueError):
            continue
    return None


def payloads(text: str, require_sink: bool = True, depth: int = 2) -> list[str]:
    """Decoded strings from `text`, unwrapped up to `depth` layers.

    With require_sink, only blobs in text that also calls something that could run
    them (eval, exec, Function, a shell pipe) count, which keeps fonts, images and
    test vectors out.
    """
    if require_sink and not SINK.search(text):
        return []
    found: list[str] = []
    for rx in (B64, HEX):
        for m in rx.finditer(text):
            token = next(g for g in m.groups() if g)
            decoded = _decode(token)
            if not decoded:
                continue
            found.append(decoded[:MAX_OUT])
            if depth > 1:
                found += payloads(decoded, require_sink=False, depth=depth - 1)
            if len(found) >= 5:
                return found
    return found
