"""Static pre-scan: read the repo without running it.

Lists every place where code runs on its own (install hooks, editor tasks,
devcontainers, direnv, .pth files, agent hooks and plugins, project MCP
servers) and every file that talks to an AI agent (AGENTS.md, CLAUDE.md,
.cursorrules, tool descriptions in MCP manifests). Pure pattern matching on the
host: nothing here executes repo code and nothing here needs an AI.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .analyze import HIDDEN_CHARS, STRONG_INJECTION, Finding

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "vendor"}
MAX_FILES = 6000
MAX_BYTES = 1_000_000

# a command that fetches and runs, or hides what it runs
HOT = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|/dev/(tcp|udp)/|\bnc\s+-[a-z]*e\b|"
                 r"base64\s+(-d|--decode)|\beval\s*\(|Buffer\.from\([^)]*base64|b64decode|"
                 r"powershell|Invoke-Expression|\biex\b|\bsocat\b.*exec:", re.I)
WARM = re.compile(r"\b(curl|wget|nc|ncat|node\s+-e|python[0-9.]*\s+-c|bash\s+-c|sh\s+-c)\b|https?://", re.I)
# Phrases aimed at a model, which have no business in ordinary source (tool descriptions live there).
SOURCE_INJECTION = re.compile(r"<\s*/?\s*(important|system|instructions?)\s*>|"
                              r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts)|"
                              r"(do not|don'?t|never) (tell|mention|inform|reveal)( this)? (to )?the user|"
                              r"before (using|calling|invoking) (this|any|the) tool,? (you must |first )?(read|send|pass|include)",
                              re.I)
BIDI = re.compile("[‪-‮⁦-⁩]")
BLOB = re.compile(r"[A-Za-z0-9+/=]{3000,}")
SOURCE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".rb", ".go", ".rs", ".java",
              ".php", ".ps1", ".json", ".toml", ".yaml", ".yml"}
INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
                     ".github/copilot-instructions.md", "CONVENTIONS.md")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")


def _files(root: Path):
    n = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in SKIP_DIRS:
                    stack.append(p)
            elif p.is_file():
                n += 1
                if n > MAX_FILES:
                    return
                yield p


def _read(p: Path) -> str:
    try:
        if p.stat().st_size > MAX_BYTES:
            return ""
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _json(p: Path):
    try:
        return json.loads(_read(p) or "null")
    except ValueError:
        return None


CMD_KEYS = ("run", "script", "initializeCommand", "postCreateCommand", "postStartCommand",
            "postAttachCommand", "onCreateCommand", "updateContentCommand")


def _flat(v) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [" ".join(str(x) for x in v)]
    if isinstance(v, dict):
        return [x if isinstance(x, str) else " ".join(map(str, x)) for x in v.values() if isinstance(x, (str, list))]
    return []


def _commands(obj) -> list[str]:
    """Every command line in a JSON-ish tree: command+args pairs and the usual *Command keys."""
    out: list[str] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("command"), (str, list)):
            cmd = _flat(obj["command"])[0]
            if isinstance(obj.get("args"), list):
                cmd += " " + " ".join(map(str, obj["args"]))
            out.append(cmd.strip())
        for k in CMD_KEYS:
            out += _flat(obj.get(k))
        for k, v in obj.items():
            if k not in CMD_KEYS and k != "command" and isinstance(v, (dict, list)):
                out += _commands(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _commands(v)
    return [c for c in out if c]


def _injection(text: str) -> str | None:
    if HIDDEN_CHARS.search(text):
        return "invisible characters"
    for rx in STRONG_INJECTION:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def scan(repo: Path) -> list[Finding]:
    found: dict[tuple, Finding] = {}

    def add(sev, rule, key, title, detail=""):
        found.setdefault((rule, key), Finding(sev, rule, title, detail[:160], "static"))

    def rel(p: Path) -> str:
        return str(p.relative_to(repo))

    def judge_cmd(rule: str, where: str, cmd: str, base: str = "info"):
        if HOT.search(cmd):
            add("high", rule, where + cmd[:40], f"{where} runs a fetch-and-execute or obfuscated command", cmd)
        elif WARM.search(cmd):
            add("medium" if base != "high" else "high", rule, where + cmd[:40], f"{where} runs a command", cmd)
        else:
            add(base, rule, where + cmd[:40], f"{where} runs a command", cmd)

    for p in _files(repo):
        name, r = p.name, rel(p)

        # ---- package managers: code that runs at install
        if name == "package.json":
            pkg = _json(p) or {}
            scripts = pkg.get("scripts") or {} if isinstance(pkg, dict) else {}
            for hook in LIFECYCLE:
                if isinstance(scripts.get(hook), str):
                    judge_cmd("install-hook", f"{r} {hook}", scripts[hook])
            engines = pkg.get("engines") or {} if isinstance(pkg, dict) else {}
            if isinstance(engines, dict) and "vscode" in engines:
                events = pkg.get("activationEvents") or []
                if "*" in events or "onStartupFinished" in events:
                    add("medium", "editor-extension", r, "VS Code extension activates on every editor start", r)
                else:
                    add("info", "editor-extension", r, "VS Code extension manifest", r)
        elif name == "setup.py":
            src = _read(p)
            if re.search(r"urllib|requests\.|socket\.|subprocess|os\.system|exec\(|eval\(|b64decode|marshal", src):
                add("medium", "install-hook", r, f"{r} does network, subprocess or exec work at install time", r)
            else:
                add("info", "install-hook", r, f"{r} runs Python at install time", r)
        elif name == "pyproject.toml":
            try:
                data = tomllib.loads(_read(p))
            except ValueError:
                data = {}
            if (data.get("build-system") or {}).get("backend-path"):
                add("medium", "install-hook", r, f"{r} uses an in-tree build backend (repo code runs at install)", r)
        elif p.suffix == ".pth" or name in ("sitecustomize.py", "usercustomize.py"):
            body = _read(p)
            if name.endswith(".py") or re.search(r"^\s*import\s", body, re.M):
                add("high", "auto-exec", r, f"{r} runs code at every Python start", body.strip()[:120])
        elif name == "binding.gyp":
            add("info", "install-hook", r, f"{r} compiles native code at install", r)

        # ---- editors, shells, containers
        elif r == ".vscode/tasks.json":
            tasks = _json(p) or {}
            for t in (tasks.get("tasks") or []) if isinstance(tasks, dict) else []:
                if isinstance(t, dict) and (t.get("runOptions") or {}).get("runOn") == "folderOpen":
                    judge_cmd("auto-exec", "VS Code task that runs when the folder is opened",
                              " ".join(_commands(t)) or str(t.get("label")), base="high")
        elif r in (".devcontainer/devcontainer.json", ".devcontainer.json"):
            dc = _json(p) or {}
            if isinstance(dc, dict):
                for key in ("initializeCommand",):
                    if dc.get(key):
                        judge_cmd("auto-exec", f"devcontainer {key} (runs on the host)", " ".join(_flat(dc[key])), base="high")
                for key in ("onCreateCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
                    if dc.get(key):
                        judge_cmd("auto-exec", f"devcontainer {key}", " ".join(_flat(dc[key])))
        elif name == ".envrc":
            judge_cmd("auto-exec", ".envrc (direnv runs it on cd)", _read(p).strip()[:200], base="medium")
        elif r.startswith((".husky/", ".githooks/")) and not name.startswith("_"):
            judge_cmd("git-hook", f"git hook {r}", _read(p).strip()[:200])

        # ---- AI agents: hooks, plugins, project MCP servers, instruction files
        elif r in (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json",
                   ".cursor/hooks.json", ".codex/hooks.json") or r.endswith("hooks/hooks.json"):
            cfg = _json(p) or {}
            hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
            for cmd in _commands(hooks or {}):
                judge_cmd("agent-hook", f"agent hook in {r}", cmd, base="medium")
            if isinstance(cfg, dict):
                if cfg.get("enableAllProjectMcpServers"):
                    add("medium", "agent-config", r, f"{r} auto-approves every project MCP server", r)
                allow = ((cfg.get("permissions") or {}).get("allow") or []) if isinstance(cfg.get("permissions"), dict) else []
                broad = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(\(\*?\))?|Bash\(\s*\*\s*\)", a)]
                if broad:
                    add("medium", "agent-config", r, f"{r} pre-approves any shell command for the agent", ", ".join(broad))
                for cmd in _commands(cfg.get("mcpServers") or {}):
                    judge_cmd("project-mcp", f"MCP server in {r}", cmd)
        elif r in (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".roo/mcp.json", ".kiro/settings/mcp.json"):
            cfg = _json(p) or {}
            servers = (cfg.get("mcpServers") or cfg.get("servers") or {}) if isinstance(cfg, dict) else {}
            for sname, spec in servers.items() if isinstance(servers, dict) else []:
                cmd = " ".join(_commands({"command": (spec or {}).get("command", ""), "args": (spec or {}).get("args", [])}))
                url = (spec or {}).get("url") if isinstance(spec, dict) else None
                judge_cmd("project-mcp", f"project MCP server '{sname}' in {r}", cmd or str(url or ""))
        elif r == ".codex/config.toml":
            try:
                cfg = tomllib.loads(_read(p))
            except ValueError:
                cfg = {}
            for sname, spec in (cfg.get("mcp_servers") or {}).items():
                cmd = f"{spec.get('command', '')} {' '.join(spec.get('args', []))}".strip()
                judge_cmd("project-mcp", f"Codex MCP server '{sname}' in {r}", cmd)
            if cfg.get("notify"):
                judge_cmd("agent-hook", f"Codex notify hook in {r}", " ".join(map(str, cfg["notify"])), base="medium")
        elif name in ("plugin.json", "marketplace.json") and p.parent.name == ".claude-plugin":
            man = _json(p) or {}
            parts = [k for k in ("hooks", "commands", "agents", "mcpServers", "skills") if isinstance(man, dict) and man.get(k)]
            add("info", "plugin-manifest", r, f"Claude Code plugin manifest ({', '.join(parts) or 'metadata only'})", r)
            for cmd in _commands(man.get("mcpServers") or {} if isinstance(man, dict) else {}):
                judge_cmd("project-mcp", f"plugin MCP server in {r}", cmd)
        elif name in ("manifest.json", "server.json", "smithery.yaml") and p.parent == repo:
            text = _read(p)
            if '"tools"' in text or "mcp" in text.lower():
                add("info", "plugin-manifest", r, f"MCP server manifest {r}", r)
                hit = _injection(text)
                if hit:
                    add("high", "mcp-tool-poisoning", r, f"{r} tool metadata carries instructions aimed at the model", hit)

        if r in INSTRUCTION_FILES or r.startswith((".cursor/rules/", ".windsurf/rules/", ".clinerules/",
                                                    ".github/instructions/", ".claude/commands/", ".claude/agents/",
                                                    ".claude/skills/", "skills/", "commands/", "agents/")):
            hit = _injection(_read(p))
            if hit:
                add("high", "agent-instructions", r, f"{r} carries hidden or injected instructions for AI agents", hit)

        # ---- source tricks
        if p.suffix in SOURCE_EXT:
            text = _read(p)
            if BIDI.search(text):
                add("medium", "trojan-source", r, f"{r} contains bidirectional control characters", r)
            elif HIDDEN_CHARS.search(text):
                add("medium", "trojan-source", r, f"{r} contains invisible Unicode characters", r)
            m = SOURCE_INJECTION.search(text) if p.suffix in (".js", ".mjs", ".cjs", ".ts", ".py") else None
            if m:
                add("high", "agent-instructions", r, f"{r} contains text aimed at an AI model (tool description injection)",
                    m.group(0))
            if p.suffix in (".js", ".mjs", ".cjs", ".py", ".ts") and BLOB.search(text):
                add("medium", "encoded-blob", r, f"{r} embeds a large encoded blob", r)

    sev_rank = {"critical": 3, "high": 2, "medium": 1, "info": 0}
    return sorted(found.values(), key=lambda f: (-sev_rank[f.severity], f.rule, f.title))
