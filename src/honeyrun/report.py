"""Render an Analysis for a terminal, as JSON, or as Markdown."""
from __future__ import annotations

import json
import os
import sys

from .analyze import Analysis, verdict

COLORS = {"critical": "1;97;41", "high": "1;31", "medium": "33", "info": "2", "PASS": "1;32", "WARN": "1;33",
          "FAIL": "1;31", "dim": "2", "bold": "1", "accent": "36"}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or stream.isatty()


def terminal(a: Analysis, ctx: dict, stream=sys.stdout, show_info: bool = False) -> None:
    color = _use_color(stream)

    def c(key: str, s: str) -> str:
        return f"\033[{COLORS[key]}m{s}\033[0m" if color else s

    w = stream.write
    w(f"{c('bold', 'honeyrun')}  {ctx['target']}\n")
    w(c("dim", f"sandbox   {ctx['runtime']}, network {ctx['network']}, {ctx['baits']} fake credentials planted\n"))
    if ctx.get("mcp"):
        n = len(a.tools)
        w(c("dim", f"mcp       {n} tool{'s' if n != 1 else ''} listed and called once each\n"))
    w("\n")
    for ph in a.phases:
        status = "timeout" if ph["timed_out"] else f"exit {ph['exit']}"
        cmd = ph["cmd"] if len(ph["cmd"]) <= 46 else ph["cmd"][:43] + "..."
        w(f"{c('accent', ph['name'].ljust(9))} {cmd:<47} {status:<8} {ph['seconds']:>5.1f}s\n")
    if not a.phases:
        w(c("dim", "no install or run command detected; pass --install / --run\n"))
    w("\n")

    shown = [f for f in a.findings if show_info or f.severity != "info"]
    for f in shown:
        label = f.severity.upper()
        pad = " " * (9 - len(label))
        w(f"{c(f.severity, label)}{pad}{f.title}\n")
        if f.detail:
            detail = f.detail if len(f.detail) <= 88 else f.detail[:85] + "..."
            w(c("dim", f"         {detail}\n"))
    if shown:
        w("\n")

    v = verdict(a.findings)
    counts = {s: sum(1 for f in a.findings if f.severity == s) for s in ("critical", "high", "medium")}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "nothing suspicious observed"
    w(f"{c(v, v)}  {summary}\n")
    w(c("dim", f"          {a.processes} processes, {a.files_opened} file opens, {len(a.hosts)} host{'s' if len(a.hosts) != 1 else ''} contacted\n"))


def to_json(a: Analysis, ctx: dict) -> str:
    return json.dumps({
        "target": ctx["target"], "runtime": ctx["runtime"], "network": ctx["network"],
        "verdict": verdict(a.findings), "findings": [f.to_dict() for f in a.findings],
        "phases": a.phases, "hosts": a.hosts, "mcp_tools": [t.get("name") for t in a.tools],
        "stats": {"processes": a.processes, "file_opens": a.files_opened},
    }, indent=2, default=list)


def to_markdown(a: Analysis, ctx: dict) -> str:
    v = verdict(a.findings)
    lines = [f"## honeyrun: {v}", "", f"`{ctx['target']}` in {ctx['runtime']}, network {ctx['network']}", ""]
    lines += ["| Phase | Command | Result | Time |", "|---|---|---|---|"]
    for ph in a.phases:
        res = "timeout" if ph["timed_out"] else f"exit {ph['exit']}"
        lines.append(f"| {ph['name']} | `{ph['cmd']}` | {res} | {ph['seconds']}s |")
    lines.append("")
    if a.findings:
        lines += ["| Severity | Finding | Evidence |", "|---|---|---|"]
        for f in a.findings:
            detail = f.detail.replace("|", "\\|")
            lines.append(f"| {f.severity} | {f.title} | {detail} |")
    else:
        lines.append("Nothing suspicious observed.")
    return "\n".join(lines) + "\n"
