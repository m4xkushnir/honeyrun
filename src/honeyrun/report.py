"""Render an Analysis for a terminal, as JSON, or as Markdown."""
from __future__ import annotations

import json
import os
import sys

from .analyze import Analysis, scrub as clean, verdict

__all__ = ["terminal", "agent", "to_json", "to_markdown", "verdict"]

COLORS = {"critical": "1;97;41", "high": "1;31", "medium": "33", "info": "2", "PASS": "1;32", "WARN": "1;33",
          "FAIL": "1;31", "dim": "2", "bold": "1", "accent": "36"}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or stream.isatty()


def note_text(note: str | None) -> str:
    """The AI reviewer's answer, line by line: control characters stripped and secrets masked."""
    return "\n".join(clean(line) for line in str(note or "").splitlines() if line.strip())


def terminal(a: Analysis, ctx: dict, stream=sys.stdout, show_info: bool = False) -> None:
    color = _use_color(stream)

    def c(key: str, s: str) -> str:
        return f"\033[{COLORS[key]}m{s}\033[0m" if color else s

    w = stream.write
    w(f"{c('bold', 'honeyrun')}  {clean(ctx['target'])}\n")
    if ctx.get("network") != "not run":
        w(c("dim", f"sandbox   {ctx['runtime']}, network {ctx['network']}, {ctx['baits']} fake credentials planted\n"))
    if ctx.get("mcp"):
        n = len(a.tools)
        w(c("dim", f"mcp       {n} tool{'s' if n != 1 else ''} listed and called once each\n"))
    w("\n")
    for ph in a.phases:
        status = "timeout" if ph["timed_out"] else f"exit {ph['exit']}"
        cmd = clean(ph["cmd"])
        cmd = cmd if len(cmd) <= 46 else cmd[:43] + "..."
        w(f"{c('accent', clean(ph['name']).ljust(9))} {cmd:<47} {status:<8} {ph['seconds']:>5.1f}s\n")
    if not a.phases and ctx.get("network") == "not run":
        w(c("dim", "static scan only: nothing was executed\n"))
    elif not a.phases:
        w(c("dim", "no install or run command detected; pass --install / --run\n"))
    w("\n")

    shown = [f for f in a.findings if show_info or f.severity != "info"]
    for f in shown:
        label = f.severity.upper()
        pad = " " * (9 - len(label))
        w(f"{c(f.severity, label)}{pad}{clean(f.title)}\n")
        if f.detail:
            detail = clean(f.detail)
            detail = detail if len(detail) <= 88 else detail[:85] + "..."
            w(c("dim", f"         {detail}\n"))
    if shown:
        w("\n")

    v = verdict(a.findings)
    counts = {s: sum(1 for f in a.findings if f.severity == s) for s in ("critical", "high", "medium")}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "nothing suspicious observed"
    word, advice = PLAIN[v]
    advice = ctx.get("advice", {}).get(v, advice)
    w(f"{c(v, word)}  {advice}\n")
    w(c("dim", f"          {summary}\n"))
    if ctx.get("network") != "not run":
        w(c("dim", f"          {a.processes} processes, {a.files_opened} file opens, {len(a.hosts)} host{'s' if len(a.hosts) != 1 else ''} contacted\n"))


PLAIN = {
    "FAIL": ("NOT SAFE", "Do not install or run this."),
    "WARN": ("UNCLEAR", "Read the findings above before you install it."),
    "PASS": ("LOOKS SAFE", "Nothing suspicious in this run. No sandbox run can prove safety."),
}

NEXT = {
    "FAIL": "Do not install or run this. Show the findings to the user.",
    "WARN": "Ask the user before installing; name the findings above.",
    "PASS": "Nothing suspicious observed in this run. Not proof of safety.",
}


def agent(a: Analysis, ctx: dict, note: str | None = None, stream=sys.stdout, limit: int = 8) -> None:
    """A dozen plain lines for a coding agent to read: verdict first, evidence second, next step last."""
    v = verdict(a.findings)
    shown = [f for f in a.findings if f.severity != "info"]
    w = stream.write
    w(f"honeyrun {v} {PLAIN[v][0]}: {clean(ctx['target'])} (sandbox: {ctx['runtime']}, network: {ctx['network']})\n")
    for f in shown[:limit]:
        detail = f" | {clean(f.detail)[:100]}" if f.detail else ""
        w(f"- {f.severity} {f.rule}: {clean(f.title)[:110]}{detail}\n")
    if len(shown) > limit:
        w(f"- ...and {len(shown) - limit} more (use --json for all)\n")
    for ph in a.phases:
        if ph["timed_out"] or ph["exit"] not in (0, None):
            w(f"- note: {clean(ph['name'])} {'timed out' if ph['timed_out'] else 'exited ' + str(ph['exit'])}; behaviour after that point was not observed\n")
    if note:
        w(f"- AI review (advisory): {clean(note)[:300]}\n")
    w(f"next: {NEXT[v]}\n")


def to_json(a: Analysis, ctx: dict, note: str | None = None) -> str:
    phases = [{**p, "cmd": clean(p.get("cmd", "")), "name": clean(p.get("name", ""))} for p in a.phases]
    hosts = [{**h, "host": clean(h.get("host", ""))} for h in a.hosts]
    tree = [{**t, "cmd": clean(t.get("cmd", ""))} for t in a.tree]
    return json.dumps({
        "target": clean(ctx["target"]), "runtime": ctx["runtime"], "network": ctx["network"],
        "verdict": verdict(a.findings), "findings": [f.to_dict() for f in a.findings],
        "phases": phases, "hosts": hosts, "mcp_tools": [clean(t.get("name")) for t in a.tools],
        "stats": {"processes": a.processes, "file_opens": a.files_opened},
        "process_tree": tree, "file_changes": a.files, "ai_review": note_text(note) if note else None,
    }, indent=2, default=list)


def _md(s: object) -> str:
    """Escape for a Markdown table cell: no pipes, backticks, HTML or line breaks."""
    return (clean(s).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
            .replace("<", "&lt;").replace(">", "&gt;"))


def _code(s: object) -> str:
    """Inline code span that cannot be closed early: backticks are swapped for a lookalike."""
    return "`" + clean(s).replace("`", "'").replace("|", "\\|").replace("<", "&lt;") + "`"


def to_markdown(a: Analysis, ctx: dict) -> str:
    v = verdict(a.findings)
    lines = [f"## honeyrun: {v}", "", f"{_code(ctx['target'])} in {_md(ctx['runtime'])}, network {_md(ctx['network'])}", ""]
    lines += ["| Phase | Command | Result | Time |", "|---|---|---|---|"]
    for ph in a.phases:
        res = "timeout" if ph["timed_out"] else f"exit {ph['exit']}"
        lines.append(f"| {_md(ph['name'])} | {_code(ph['cmd'])} | {res} | {ph['seconds']}s |")
    lines.append("")
    if a.findings:
        lines += ["| Severity | Finding | Evidence |", "|---|---|---|"]
        for f in a.findings:
            lines.append(f"| {_md(f.severity)} | {_md(f.title)} | {_md(f.detail)} |")
    else:
        lines.append("Nothing suspicious observed.")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- abuse report

REPORT_TO = (
    "GitHub: https://github.com/contact/report-abuse (choose: malware or exploits)",
    "npm: https://www.npmjs.com/support (or 'Report malware' on the package page)",
    "PyPI: https://pypi.org/security/ (or 'Report project as malware' on the project page)",
)


def abuse(a: Analysis, ctx: dict, version: str) -> str:
    """A short, factual report a person can paste into a registry's or GitHub's abuse form.

    Built from the findings only: no local paths beyond the sandbox's own, no real secrets
    (the credentials involved were fake ones planted by honeyrun), no guesses about intent.
    """
    serious = [f for f in a.findings if f.severity in ("critical", "high")][:6]
    if not serious:
        return ""
    if ctx["network"] == "not run":
        how = (f"contains the following, found by reading its files with honeyrun {version} "
               "(nothing was executed).")
    else:
        how = (f"did the following when installed and run in an isolated sandbox (honeyrun {version}, "
               f"{ctx['runtime']}, network {ctx['network']}). The credentials it touched were fake ones planted for the test.")
    lines = [f"Subject: Malicious behaviour in {clean(ctx['target'])}", "", f"{clean(ctx['target'])} {how}", ""]
    for f in serious:
        lines.append(f"- {clean(f.title)}" + (f" ({clean(f.detail)[:140]})" if f.detail else ""))
    lines += ["", f"To reproduce: pipx install git+https://github.com/m4xkushnir/honeyrun && honeyrun {clean(ctx['target'])}",
              "", "Report it to:"] + [f"  {x}" for x in REPORT_TO]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- SARIF (GitHub code scanning and friends)

def to_sarif(a: Analysis, ctx: dict, version: str) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "info": "note"}
    rules = sorted({f.rule for f in a.findings})
    fallback = ctx.get("manifest") or "README.md"
    results = []
    for f in a.findings:
        uri = clean(getattr(f, "file", "") or fallback)
        results.append({
            "ruleId": f.rule, "level": level[f.severity],
            "message": {"text": clean(f.title) + (f" ({clean(f.detail)[:200]})" if f.detail else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}],
            "properties": {"severity": f.severity, "phase": f.phase},
        })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "honeyrun", "version": version,
                                "informationUri": "https://github.com/m4xkushnir/honeyrun",
                                "rules": [{"id": r, "shortDescription": {"text": r.replace("-", " ")}} for r in rules]}},
            "results": results,
            "properties": {"verdict": verdict(a.findings), "target": clean(ctx["target"]), "sandbox": ctx["runtime"]},
        }],
    }, indent=2)


# ----------------------------------------------------------------- what to do now

ROTATE = {
    "SSH": "SSH keys: make a new key, replace it on GitHub/GitLab/servers, delete the old one",
    "AWS": "AWS keys: deactivate them in IAM and create new ones",
    "GitHub": "GitHub tokens: revoke at github.com/settings/tokens and sign out other sessions",
    "npm": "npm tokens: revoke with `npm token revoke` or at npmjs.com/settings/tokens",
    "Docker": "Docker registry logins: `docker logout`, revoke the access token",
    "Kubernetes": "Kubernetes: rotate the service-account token / kubeconfig credentials",
    "wallet": "Crypto wallets: move funds to a new wallet with a new seed phrase",
    "API_KEY": "AI API keys (OpenAI, Anthropic, Gemini): revoke and reissue in each provider's console",
    "Claude": "Claude Code / Claude Desktop: sign out and back in, check ~/.claude/settings.json hooks",
    "Codex": "Codex: sign out and back in, check ~/.codex/config.toml",
    "Cursor": "Cursor: check ~/.cursor/mcp.json and the keys in it",
    "browser": "Browsers: sign out of important sites everywhere and change those passwords",
}
PERSIST_CHECK = ("~/.bashrc, ~/.zshrc, ~/.profile", "crontab -l", "~/.config/systemd/user (Linux), ~/Library/LaunchAgents (macOS)",
                 "~/.claude/settings.json hooks, ~/.cursor/mcp.json, ~/.codex/config.toml", "~/.npmrc, pip config, ~/.gitconfig",
                 "your editor's extensions")


def remediation(findings, ctx: dict) -> list[str]:
    """Concrete next steps for a NOT SAFE (or UNCLEAR) result, in the order they matter."""
    v = verdict(findings)
    if v == "PASS":
        return []
    serious = [f for f in findings if f.severity in ("critical", "high")]
    text = " ".join(f"{f.title} {f.detail}" for f in serious)
    steps: list[str] = []
    if not ctx.get("local"):
        if v == "FAIL":
            steps.append("Nothing was run on your machine: this came from reading its files." if ctx.get("network") == "not run"
                         else "It ran only inside the sandbox: your real files and keys were not exposed by this check.")
            steps.append("Don't install it. If you already did, run `honeyrun <that project dir> --installed` and follow the steps it gives.")
            if any(f.rule in ("known-malware", "canary-exfil", "bait-read", "persistence", "mcp-tool-poisoning") for f in serious):
                steps.append("Report it so others are protected: rerun with --abuse-report report.txt and paste it into the form it names.")
        else:
            steps.append("Read the findings above. If they don't match what this project says it does, don't install it.")
        return steps
    # It was found on this machine: assume it already ran here.
    if v == "FAIL":
        steps.append("Stop using it now: remove the flagged package (`npm uninstall <name>` / `pip uninstall <name>`) "
                     "or delete the flagged entry from the agent config shown above, then restart that agent or editor.")
        keys = [msg for k, msg in ROTATE.items() if k.lower() in text.lower()]
        steps.append("Assume what it could read is exposed. Rotate, from a clean device if you can: " +
                     ("; ".join(keys) if keys else "SSH keys, cloud keys, registry tokens, AI API keys, browser sessions") + ".")
        steps.append("Look for anything it left behind: " + "; ".join(PERSIST_CHECK) + ".")
        steps.append("If it touched work systems, tell your security team now and keep the honeyrun report as evidence.")
    else:
        steps.append("Check each flagged entry: you should recognise it and know why it runs. Remove what you don't.")
    return steps
