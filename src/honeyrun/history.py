"""A small local memory of past checks, so an update can be compared with what you already checked.

One JSON file per target in the user's cache directory, last 10 checks each. It keeps
fingerprints, not content: finding rules and titles (already masked), contacted hosts,
install hooks and MCP tool definitions as short hashes. Nothing leaves the machine.
--no-history turns it off.

The most useful comparison is for MCP servers: a tool whose description changes after
you approved it is the classic "rug pull", where a server turns hostile after it gained trust.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

from .analyze import Finding

KEEP = 10


def _cache_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "honeyrun" / "history"


def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


def target_key(label: str) -> str:
    """Same repo at a new commit maps to the same file: drop the ' @ <rev>' suffix."""
    return _h(label.split(" @ ")[0].strip().lower())


def snapshot(label: str, verdict: str, findings: list[Finding], hosts: list[dict], tools: list[dict],
             lifecycle: dict[str, str]) -> dict:
    rev = label.split(" @ ")[1].split()[0] if " @ " in label else ""
    return {
        "when": time.strftime("%Y-%m-%d %H:%M", time.localtime()),
        "rev": rev,
        "verdict": verdict,
        "findings": sorted({f"{f.rule}|{f.title}" for f in findings if f.severity != "info"}),
        "hosts": sorted(h["host"] for h in hosts if not h.get("expected")),
        "tools": {str(t.get("name")): _h([t.get("description"), t.get("inputSchema")]) for t in tools},
        "hooks": {k: _h(v) for k, v in lifecycle.items()},
    }


def load(label: str) -> list[dict]:
    try:
        return json.loads((_cache_dir() / f"{target_key(label)}.json").read_text(encoding="utf-8")).get("runs", [])
    except (OSError, ValueError, AttributeError):
        return []


def save(label: str, snap: dict) -> None:
    path = _cache_dir() / f"{target_key(label)}.json"
    runs = (load(label) + [snap])[-KEEP:]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"target": label.split(" @ ")[0], "runs": runs}, indent=1), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass   # history is a convenience; never fail a check over it


def compare(prev: dict, cur: dict) -> list[Finding]:
    """What changed since the last check of the same target."""
    out: list[Finding] = []
    since = f"since the last check ({prev.get('when', '?')}" + (f", {prev['rev']}" if prev.get("rev") else "") + ")"
    pt, ct = prev.get("tools", {}), cur.get("tools", {})
    for name in sorted(set(pt) & set(ct)):
        if pt[name] != ct[name]:
            out.append(Finding("high", "mcp-rug-pull", f"MCP tool '{name}' changed its description or inputs {since}",
                               "re-read what it now asks the model to do before you keep using it", "history"))
    added = sorted(set(ct) - set(pt))
    if pt and added:
        out.append(Finding("medium", "mcp-new-tools", f"new MCP tools {since}: {', '.join(added[:6])}", "", "history"))
    for hook in sorted(set(cur.get("hooks", {})) | set(prev.get("hooks", {}))):
        a, b = prev.get("hooks", {}).get(hook), cur.get("hooks", {}).get(hook)
        if a != b and b:
            out.append(Finding("medium", "hook-changed", f"install hook '{hook}' {'added' if not a else 'changed'} {since}", "",
                               "history"))
    new_hosts = sorted(set(cur.get("hosts", [])) - set(prev.get("hosts", [])))
    if new_hosts and prev.get("hosts") is not None:
        out.append(Finding("medium", "new-hosts", f"contacts new hosts {since}: {', '.join(new_hosts[:5])}", "", "history"))
    new_findings = sorted(set(cur.get("findings", [])) - set(prev.get("findings", [])))
    if prev.get("verdict") == "PASS" and cur.get("verdict") != "PASS" and new_findings:
        out.append(Finding("high", "regressed", f"was LOOKS SAFE {since}, now it is not",
                           "; ".join(x.split("|", 1)[1] for x in new_findings[:3]), "history"))
    if not out:
        out.append(Finding("info", "unchanged", f"same behaviour as the last check ({prev.get('when', '?')})", "", "history"))
    return out
