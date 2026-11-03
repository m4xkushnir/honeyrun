"""Check what is already on this machine, without running any of it.

--installed DIR   a project whose dependencies are already installed: every package in
                  node_modules and every .pth in its virtualenvs.
--agent-configs   the MCP servers and hooks your coding agents (Claude Code, Claude
                  Desktop, Codex, Cursor, Gemini CLI, Windsurf, VS Code) will start.

Privacy: both only read local files and print nothing but names, commands and
findings. Environment values and anything that looks like a token are masked;
nothing is sent anywhere.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

from . import deobf
from .analyze import Finding
from .static import ACTS, DATE_GATE, HOT, LIFECYCLE, LONG_TIMER, WARM, _typosquat, safe_rel, source_injection

# prefixed tokens: keep the 4-char prefix so the report still says what kind of secret it was
_TOKEN_PREFIXED = re.compile(r"(?<![A-Za-z0-9])(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_\w{8,}|xox[abpr]-[\w-]{8,}|"
                             r"AKIA[A-Z0-9]{12,}|glpat-[\w-]{8,}|npm_[A-Za-z0-9]{8,}|hf_[A-Za-z0-9]{8,}|"
                             r"eyJ[\w-]{10,}\.[\w-]{10,}(?:\.[\w-]*)?)")
_LONG_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{32,}")
_KW = r"(?:(?:password|passwd|secret|token|api[-_]?key|apikey|access[-_]?key)[\w-]*|auth(?![\w-]))"
_URL_PASS = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/@\s:]+:)[^@\s/]+@", re.I)
_BARE_URL_PASS = re.compile(r"(?<![\w/@.:-])([\w.-]+:)(?!\*{4}@)[^@\s/:]+@(?=[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b)")   # host must end in a real TLD, so "npm:pkg@1.2.3" stays readable
_BEARER = re.compile(r"\b(Bearer|Basic)(\s+)(?!\w{0,4}\*{4})([A-Za-z0-9._~+/=-]{8,})", re.I)
_AUTH_HEADER = re.compile(r"(\bAuthorization\s*[\"']?\s*[:=]\s*[\"']?)(?!(?:Bearer|Basic)\s)(?!\S{0,4}\*{4})([^\s\"',;]+)", re.I)
_KEY_VALUE = re.compile(r"(\b(?!max[-_]?tokens)[\w.-]*" + _KW + r"[\w.]*[\"']?\s*[=:]\s*)([\"']?)(?![$<{%*]|\S{0,4}\*{4})([^\s\"',;&]+)", re.I)
_FLAG_VALUE = re.compile(r"((?<![\w-])--?[\w-]*" + _KW + r"\s+)([\"']?)(?![-$<{%*]|\S{0,4}\*{4})([^\s\"',;&]+)", re.I)
# .pth files that legitimately contain import lines
KNOWN_PTH = re.compile(r"^(distutils-precedence|_virtualenv|easy-install|__editable__.*|.*-nspkg|"
                       r"_distutils_hack|coloredlogs|setuptools.*|pywin32|matplotlib|protobuf.*|google.*)\.pth$")
MAX_PACKAGES = 20000


def _hide(v: str) -> str:
    # a value named password/secret/token/key gets no hint at all: a prefix narrows a password search
    return "****"


def _run(m: re.Match) -> str:
    v = m.group(0)
    if v.startswith("/") or not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
        return v                                    # a path, or no mix of letters and digits
    if "/" in v and (v.count("/") > 3 or "-" in v or "_" in v or v.endswith("/")):
        return v                                    # AWS secrets use '/', slugs and paths use '-', '_' and more of them
    if re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)+", v):
        return v                                    # kebab or snake slug, uuid
    return v[:4] + "****"


def mask(text: str, home: Path | str | None = None) -> str:
    """Hide secrets and the real home directory in text that will be printed or shared."""
    text = str(text)
    homes = {os.path.expanduser("~")}
    if home:
        homes.add(str(home))
    for h in homes:
        if len(h.rstrip("/")) > 1:
            text = re.sub(re.escape(h.rstrip("/")) + r"(?![\w-])", "~", text)
    text = _URL_PASS.sub(r"\1****@", text)
    text = _BARE_URL_PASS.sub(r"\1****@", text)
    text = _BEARER.sub(lambda m: m.group(1) + m.group(2) + m.group(3)[:4] + "****", text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + m.group(2)[:4] + "****", text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + _hide(m.group(3)), text)
    text = _FLAG_VALUE.sub(lambda m: m.group(1) + m.group(2) + _hide(m.group(3)), text)
    text = _TOKEN_PREFIXED.sub(lambda m: m.group(0)[:4] + "****", text)
    return _LONG_RUN.sub(_run, text)


def _grade(cmd: str) -> str:
    return "high" if HOT.search(cmd) else "medium" if WARM.search(cmd) else "info"


def _read(p: Path, limit: int = 1_000_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _json(p: Path):
    try:
        return json.loads(_read(p) or "null")
    except (ValueError, RecursionError):
        return None


def _listdir(d: Path) -> list[Path]:
    try:
        return sorted(d.iterdir())
    except OSError:
        return []


def _real_dir(d: Path) -> bool:
    try:
        return d.is_dir() and not d.is_symlink()
    except OSError:
        return False


def _node_packages(root: Path, state: dict | None = None):
    """Every package.json under node_modules, including scoped, nested and pnpm-store ones.

    Only real directories are followed: pnpm's top-level entries are symlinks into
    node_modules/.pnpm/<pkg>/node_modules/<name>, so that store is walked directly.
    """
    state = state if state is not None else {}
    stack, n, seen = [root], 0, set()
    while stack:
        nm = stack.pop()
        for d in _listdir(nm):
            if d.name == ".pnpm" and _real_dir(d):
                stack += [e / "node_modules" for e in _listdir(d) if _real_dir(e / "node_modules")]
                continue
            if d.name.startswith(".") or not _real_dir(d):
                continue
            pkgs = [e for e in _listdir(d) if _real_dir(e)] if d.name.startswith("@") else [d]
            for pkg in pkgs:
                if pkg in seen or not (pkg / "package.json").is_file():
                    continue
                seen.add(pkg)
                n += 1
                state["count"] = n
                if n > MAX_PACKAGES:
                    state["truncated"] = True
                    return
                yield pkg
                if _real_dir(pkg / "node_modules"):
                    stack.append(pkg / "node_modules")


def _inside(base: Path, rel: str) -> Path | None:
    """base/rel when rel stays inside base (no .., no symlink out), else None."""
    n = safe_rel(rel)
    if not n:
        return None
    try:
        target = (base / n).resolve()
        return target if target.is_relative_to(base.resolve()) else None
    except (OSError, RuntimeError):
        return None


def scan_dependencies(root: Path) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple] = set()

    def add(sev, rule, key, title, detail=""):
        if (rule, key) not in seen:
            seen.add((rule, key))
            out.append(Finding(sev, rule, title, mask(detail)[:200], "installed"))

    def check(pkg: Path):
        meta = _json(pkg / "package.json")
        if not isinstance(meta, dict):
            return
        name = meta.get("name") if isinstance(meta.get("name"), str) else pkg.name
        twin = _typosquat(name)
        if twin:
            add("medium", "typosquat", name, f"installed dependency '{name}' imitates '{twin}'", pkg.relative_to(root).as_posix())
        scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
        for hook in LIFECYCLE:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            sev = _grade(cmd)
            add(sev, "install-hook", f"{name}:{hook}", f"dependency {name} runs a {hook} hook", cmd)
            for rel in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|sh)\b", cmd):
                path = _inside(pkg, rel)
                text = _read(path) if path else ""
                if not text:
                    continue
                if ACTS.search(text) and (DATE_GATE.search(text) or LONG_TIMER.search(text)):
                    add("medium", "delayed-activation", f"{name}:{rel}", f"dependency {name}'s {hook} script waits for a date or timer", rel)
                inj = source_injection(text)
                if inj:
                    add(inj[1], "agent-instructions", f"{name}:{rel}", f"dependency {name}'s {hook} script contains text aimed at an AI model", rel)
                for decoded in deobf.payloads(text)[:1]:
                    add("medium", "decoded-payload", f"{name}:{rel}", f"dependency {name}'s {hook} script hides an encoded payload; decoded:", decoded)

    state: dict = {}
    nm = root / "node_modules"
    if nm.is_dir():
        for pkg in _node_packages(nm, state):
            try:
                check(pkg)
            except Exception:  # one odd package must not hide the rest
                add("info", "scan-error", str(pkg), f"could not parse installed package {pkg.name}", pkg.relative_to(root).as_posix())
    if state.get("truncated"):
        add("medium", "scan-incomplete", "max-packages", f"scan incomplete: more than {MAX_PACKAGES} installed packages, the rest were not checked")
    add("info", "installed-summary", "count", f"{state.get('count', 0)} installed packages checked")

    for venv in (root / ".venv", root / "venv", root / "env", root / ".tox"):
        try:
            sites = list(venv.glob("lib/python*/site-packages")) if venv.is_dir() else []
        except OSError:
            sites = []
        for site in sites:
            try:
                pths = list(site.glob("*.pth"))
            except OSError:
                continue
            for pth in pths:
                body = _read(pth, 20000)
                if not re.search(r"^\s*import\s", body, re.M) or KNOWN_PTH.match(pth.name):
                    continue
                sev = "high" if (HOT.search(body) or re.search(r"exec\(|eval\(|b64decode|urllib|socket|subprocess|os\.system", body)) else "medium"
                add(sev, "auto-exec", str(pth), f"{pth.relative_to(root).as_posix()} runs code at every Python start", body.strip()[:150])
    return out


# ----------------------------------------------------------------- agent configs

def _agent_files(home: Path) -> list[tuple[str, Path]]:
    mac = home / "Library/Application Support"
    return [
        ("Claude Code", home / ".claude.json"),
        ("Claude Code", home / ".claude/settings.json"),
        ("Claude Desktop", mac / "Claude/claude_desktop_config.json"),
        ("Claude Desktop", home / ".config/Claude/claude_desktop_config.json"),
        ("Codex", home / ".codex/config.toml"),
        ("Cursor", home / ".cursor/mcp.json"),
        ("Gemini CLI", home / ".gemini/settings.json"),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json"),
        ("VS Code", mac / "Code/User/mcp.json"),
        ("VS Code", home / ".config/Code/User/mcp.json"),
        # Windows keeps app configs under %APPDATA%; resolved from home so a test home stays self-contained
        ("Claude Desktop", home / "AppData/Roaming/Claude/claude_desktop_config.json"),
        ("VS Code", home / "AppData/Roaming/Code/User/mcp.json"),
        ("Cursor", home / "AppData/Roaming/Cursor/User/mcp.json"),
        ("Zed", home / ".config/zed/settings.json"),
        ("Continue", home / ".continue/config.json"),
        ("Cline", mac / "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
        ("Cline", home / "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
    ]


def _servers(cfg) -> list[tuple[str, dict]]:
    """(name, spec) for mcpServers / servers / mcp_servers, including Claude Code's per-project ones."""
    out = []
    if not isinstance(cfg, dict):
        return out
    for key in ("mcpServers", "servers", "mcp_servers", "context_servers"):
        block = cfg.get(key)
        if isinstance(block, dict):
            out += [(n, s) for n, s in block.items() if isinstance(s, dict)]
    projects = cfg.get("projects")
    if isinstance(projects, dict):
        for proj, pcfg in projects.items():
            for n, s in _servers(pcfg if isinstance(pcfg, dict) else {}):
                out.append((f"{n} (project {Path(proj).name})", s))
    return out


def _hooks(cfg) -> list[str]:
    from .static import _commands
    return _commands(cfg.get("hooks") or {}) if isinstance(cfg, dict) else []


def scan_agent_configs(home: Path | None = None) -> list[Finding]:
    home = home or Path(os.path.expanduser("~"))
    out: list[Finding] = []
    for agent, path in _agent_files(home):
        if not path.is_file():
            continue
        where = "~/" + path.relative_to(home).as_posix() if path.is_relative_to(home) else str(path)
        if path.suffix == ".toml":
            try:
                cfg = tomllib.loads(_read(path))
            except (ValueError, RecursionError):
                continue
        else:
            cfg = _json(path)
        for name, spec in _servers(cfg):
            url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
            if isinstance(url, str):
                out.append(Finding("info", "configured-mcp", f"{agent}: remote MCP server '{name}'",
                                   f"{mask(re.sub(r'[?#].*', '', url), home)}  ({where})", "config"))
                continue
            args = spec.get("args") if isinstance(spec.get("args"), list) else []
            cmd = " ".join(str(x) for x in [spec.get("command", ""), *args] if x)
            env = spec.get("env")
            env_names = ", ".join(sorted(k for k in env if isinstance(k, str))) if isinstance(env, dict) else ""
            detail = mask(cmd, home) + (f"  (env: {env_names})" if env_names else "")
            sev = _grade(cmd)
            unpinned = re.search(r"\b(npx\s+(-y\s+)?|uvx\s+|pipx run\s+)[@\w./-]+(?!@\d)", cmd) and not re.search(r"@\d|==\d", cmd)
            title = f"{agent}: MCP server '{name}' starts with every session"
            if unpinned and sev == "info":
                title += " (unpinned: a new version runs without review)"
            out.append(Finding(sev, "configured-mcp", title, f"{detail}  ({where})", "config"))
        for cmd in _hooks(cfg):
            out.append(Finding(_grade(cmd), "configured-hook",
                               f"{agent}: hook runs a command automatically", f"{mask(cmd, home)}  ({where})", "config"))
    if not out:
        out.append(Finding("info", "configured-mcp", "no agent MCP servers or hooks found in the usual config files"))
    return out
