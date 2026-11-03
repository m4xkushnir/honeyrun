"""Static pre-scan: read the repo without running it.

Lists every place where code runs on its own (install hooks, editor tasks,
devcontainers, direnv, .pth files, agent hooks and plugins, project MCP
servers) and every file that talks to an AI agent (AGENTS.md, CLAUDE.md,
.cursorrules, tool descriptions in MCP manifests). Pure pattern matching on the
host: nothing here executes repo code and nothing here needs an AI.
"""
from __future__ import annotations

import json
import posixpath
import os
import re
import tomllib
from pathlib import Path

from . import artifacts, deobf
from .analyze import HIDDEN_CHARS, STRONG_INJECTION, Finding

# Only dirs that are huge and never hold the repo's own config. build/dist/vendor/.tox are still walked
# for hook, agent and config files (see BULKY): attackers hide those in "generated" directories.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
BULKY = {"dist", "build", "vendor", ".tox"}
MAX_FILES = 6000
MAX_BYTES = 1_000_000
MAX_DEPTH = 200

# a command that fetches and runs, or hides what it runs
HOT = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|/dev/(tcp|udp)/|\bnc\s+-[a-z]*e\b|"
                 r"base64\s+(-d|--decode)|\beval\s*\(|Buffer\.from\([^)]*base64|b64decode|"
                 r"powershell|Invoke-Expression|\biex\b|\bsocat\b.*exec:", re.I)
WARM = re.compile(r"\b(curl|wget|nc|ncat|node\s+-e|python[0-9.]*\s+-c|bash\s+-c|sh\s+-c)\b|https?://", re.I)

# Phrases aimed at a model, which have no business in ordinary source (tool descriptions live there).
# Tuned for code: prompt strings legitimately say "<system>" or "before calling this tool", so each
# pattern needs more than the phrase, and the verdict is high only next to a sensitive target.
SENSITIVE = re.compile(r"~/|\$HOME|\.ssh\b|\.env(?![.\w-])|mcp\.json|id_(rsa|ed25519|ecdsa)|credentials|token|\bkeys?\b|"
                       r"secret|password|conversation|previous messages|\.aws\b|claude_desktop_config|\.claude\.json", re.I)
TOOLISH = re.compile(r"tool|function|description|notes|argument|parameter", re.I)
_IMPORTANT_TAG = re.compile(r"<\s*/?\s*important\s*>", re.I)
_IGNORE_PREV = re.compile(r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts)", re.I)
_HIDE_FROM_USER = re.compile(r"(do not|don'?t|never) (?:(?:mention|tell|inform|reveal)(?: this| that| it)? to the user\b|"
                             r"tell the user\b(?!['\u2019]s)|(?:mention|tell|inform|reveal)(?: this| that| it)? the user about (?:this|it)\b)", re.I)
_BEFORE_TOOL = re.compile(r"before (using|calling|invoking) (this|any|the) tool,? (you must |first )?(read|send|pass|include)"
                          r"[\s\S]{0,80}?(~/|\$HOME|\.ssh|\.env(?![.\w-])|mcp\.json|id_rsa|credentials|token|\bkey\b|secret|"
                          r"password|conversation|previous messages)", re.I)


def _in_string(text: str, i: int) -> bool:
    """Is offset i plausibly inside a string literal rather than a comment?"""
    ls = text.rfind("\n", 0, i) + 1
    prefix = text[ls:i]
    if prefix.lstrip().startswith(("#", "//", "*", "/*", "--")):
        return False
    return any(q in prefix for q in "'\"") or "`" in text[max(0, i - 800):i] or '"""' in text[max(0, i - 800):i]


def source_injection(text: str) -> tuple[str, str] | None:
    """(matched text, severity) for model-directed instructions in source code, or None."""
    for m in _BEFORE_TOOL.finditer(text):
        return m.group(0)[:140], "high"
    best: tuple[str, str] | None = None
    for rx in (_IMPORTANT_TAG, _IGNORE_PREV, _HIDE_FROM_USER):
        for m in rx.finditer(text):
            i = m.start()
            window = text[max(0, i - 300): m.end() + 600]
            if rx is _IMPORTANT_TAG and not (_in_string(text, i) and TOOLISH.search(window)):
                continue
            if rx is _HIDE_FROM_USER and not _in_string(text, i):
                continue
            # Ordinary system prompts say "never tell the user..." and talk about tokens and keys.
            # What sets an injection apart is a concrete secret location next to the order.
            secret = re.search(_SECRET_TARGET, window, re.I)
            if rx is _HIDE_FROM_USER and not secret:
                continue
            sev = "high" if secret else "medium"
            if best is None or sev == "high":
                best = (m.group(0), sev)
            if sev == "high":
                return best
    return best


# Instruction files (AGENTS.md ...) are prose: naming ~/.config or saying "upload to https://" is
# ordinary documentation. Only imperative phrasing aimed at the model or at secrets counts.
_SECRET_TARGET = (r"(?:(?:~|\$HOME)/\.(?:ssh|aws|gnupg|kube|docker|npmrc|netrc|config/(?:gcloud|gh))|id_(?:rsa|ed25519|ecdsa)\b|"
                  r"\.env(?![.\w-])|\.aws/credentials|\.git-credentials|application_default_credentials|mcp\.json|claude_desktop_config|\.claude\.json)")
INSTRUCTION_INJECTION: list[tuple[re.Pattern, bool]] = [
    (re.compile(r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|rules)", re.I), False),
    (re.compile(r"(do not|don'?t|never) (tell|mention|inform|reveal|disclose)(?: this| that| it)?(?: to| about)? the user\b(?!['\u2019]s)", re.I), False),
    (re.compile(r"<\s*/?\s*important\s*>", re.I), False),
    (re.compile(r"<!--(?:(?!-->)[\s\S]){0,600}?\b(ignore (previous|prior|all)|you must|do not|don'?t|never|silently|secretly|"
                r"assistant|ai agent|llm|claude|when you (finish|are done))\b", re.I), False),
    (re.compile(r"\b(read|cat|print|echo|send|upload|post|exfiltrate|include|paste|output|dump|copy|forward|attach|curl)\b[^.\n]{0,60}?"
                + _SECRET_TARGET, re.I), True),
    (re.compile(r"\b(run|execute|exec)\b[^\n]{0,60}?\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I), False),
]
_NEGATION = re.compile(r"(do not|don'?t|never|must not|should not|avoid)\s+(\w+\s+)?$", re.I)
_BIDI_CTRL = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_TAGS = re.compile("[\U000e0000-\U000e007f]")
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060-\u2064\ufeff]")


def _emoji_zwj_free(text: str) -> str:
    """Drop a leading BOM and ZWJ joining two symbols/emoji: both are ordinary in documentation."""
    if text.startswith("\ufeff"):
        text = text[1:]
    return re.sub("(?<=[\u2190-\U0010ffff\ufe0f])\u200d(?=[\u2190-\U0010ffff])", "", text)


def instruction_injection(text: str) -> tuple[str, str] | None:
    """(evidence, severity) for an instruction file, or None."""
    text = _emoji_zwj_free(text)
    if _BIDI_CTRL.search(text) or _TAGS.search(text):
        return "invisible characters", "high"
    for rx, negatable in INSTRUCTION_INJECTION:
        for m in rx.finditer(text):
            if negatable and _NEGATION.search(text[max(0, m.start() - 25):m.start()]):
                continue
            return m.group(0)[:140], "high"
    if _ZERO_WIDTH.search(text):
        return "invisible characters", "medium"
    return None


# Code that waits: a date check or a long timer in the same file as something that acts.
DATE_GATE = re.compile(r"new Date\(\s*['\"]?20\d\d|Date\.now\(\)\s*[<>]=?\s*\d{12}|getTime\(\)\s*[<>]=?\s*\d{12}|"
                       r"datetime\.(now|today|utcnow)\(\)\s*[<>]=?|date\.today\(\)\s*[<>]=?|time\.time\(\)\s*[<>]=?\s*\d{9}|"
                       r"Time\.now\s*[<>]=?|strtotime\(|\(Get-Date\)\s*-(gt|ge|lt|le)\b")
LONG_TIMER = re.compile(r"set(Timeout|Interval)\([\s\S]{0,600}?,\s*(\d{7,}|\d+\s*\*\s*(60\s*\*\s*)?60\s*\*\s*(60\s*\*\s*)?1000)\s*\)|"
                        r"time\.sleep\(\s*\d{4,}|Start-Sleep\s+(-Seconds\s+)?\d{4,}|\bsleep\(\s*\d{4,}")
ENV_GATE = re.compile(r"process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI)\b|os\.environ(\.get)?\s*[\[(]\s*['\"](CI|GITHUB_ACTIONS)['\"]|"
                      r"os\.hostname\(\)|userInfo\(\)\.username|getpass\.getuser\(\)|platform\.node\(\)|"
                      r"ENV\[['\"](CI|GITHUB_ACTIONS)['\"]\]|\$env:(CI|GITHUB_ACTIONS|COMPUTERNAME|USERNAME)\b|getenv\(['\"](CI|GITHUB_ACTIONS)['\"]\)")
# A gate only matters when the same file reaches out: spawning a local tool (husky, tsc) behind a CI check is ordinary.
NET_CALL = re.compile(r"https?\.(request|get)\(|\bfetch\(|\b(curl|wget)\b|urllib|requests\.|socket|\.connect\(|net\.(connect|createConnection)|"
                      r"Invoke-WebRequest|Invoke-RestMethod|\biwr\b|DownloadString|DownloadFile|XMLHttpRequest|require\(['\"]https?['\"]\)|"
                      r"axios|Net::HTTP|open-uri|curl_exec|file_get_contents\(\s*['\"]http|LWP|dgram")
ACTS = re.compile(r"child_process|execSync|\bspawn\(|\beval\(|new Function\(|https?\.(request|get)\(|\bfetch\(|"
                  r"net\.(connect|createConnection)|dgram|subprocess|os\.system|urllib|requests\.(get|post)|"
                  r"socket\.socket|homedir\(\)|expanduser\(|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|Start-Process|"
                  r"DownloadString|DownloadFile|Net::HTTP|shell_exec|proc_open|passthru|curl_exec|\bsystem\(|Open3|IO::Socket")
GATE_EXT = {".js", ".mjs", ".cjs", ".py", ".ts", ".sh", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php"}
# Well-known names that typosquats imitate.
POPULAR = ("react", "lodash", "express", "axios", "chalk", "commander", "request", "moment", "webpack", "typescript",
           "eslint", "prettier", "jest", "next", "vue", "dotenv", "uuid", "debug", "colors", "yargs", "inquirer",
           "mongoose", "socket.io", "jsonwebtoken", "bcrypt", "cross-env", "nodemon", "electron", "puppeteer",
           "discord.js", "ethers", "web3", "openai", "@anthropic-ai/sdk", "@modelcontextprotocol/sdk",
           "requests", "numpy", "pandas", "urllib3", "setuptools", "flask", "django", "boto3", "pyyaml", "pillow",
           "cryptography", "selenium", "beautifulsoup4", "colorama", "matplotlib", "tensorflow", "torch", "anthropic",
           "langchain", "fastapi", "pydantic", "httpx", "mcp", "fastmcp")
# Real packages that sit 1-2 edits from a POPULAR name (or from each other): never typosquats.
KNOWN_GOOD = frozenset({
    "preact", "dotenvx", "dotenv-cli", "dotenv-expand", "react-dom", "react-is", "react-native", "react-router",
    "axios-retry", "axios-mock-adapter", "pydantic-core", "pydantic-settings", "httpcore", "attrs", "six", "toml",
    "tomli", "tomlkit", "idna", "click", "rich", "jinja2", "boto", "botocore", "s3transfer", "numpy", "scipy",
    "chalk-template", "nanoid", "nuxt", "vuex", "vue-router", "vue2", "jsdom", "jest-cli", "color", "color-name",
    "colorama", "pytest", "mocha", "chai", "sinon", "rimraf", "glob", "semver", "zod", "tslib", "ora", "execa",
    "got", "ws", "yaml", "ajv", "joi", "pg", "mysql2", "redis", "ioredis", "svelte", "vite", "vitest", "esbuild",
    "markupsafe", "werkzeug", "starlette", "uvicorn", "gunicorn", "celery", "kombu", "psycopg2", "pymysql",
    "lxml", "cffi", "certifi", "packaging", "wheel", "typing-extensions", "anyio", "h11", "tqdm", "orjson",
    "ujson", "pyjwt", "bcryptjs", "yargs-parser", "express-session",
    "next-auth", "next-themes", "mongodb", "web3-utils", "pillow-simd",
})
_POPULAR_SET = frozenset(POPULAR)


def _distance(a: str, b: str) -> int:
    """Edit distance counting an adjacent swap as one edit (lodahs vs lodash)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _typosquat(name: str) -> str | None:
    n = name.lower().replace("_", "-")
    if n in _POPULAR_SET or n in KNOWN_GOOD:
        return None
    for pop in POPULAR:
        if len(pop) < 4:
            continue
        d = _distance(n, pop)
        # affix variants (reactjs, vue2) only matter for short names: longer ones are usually real forks/ports
        if d == 1 or (len(pop) >= 7 and d == 2) or (len(n) < 6 and n in (pop + "js", pop + "-js", pop + "2", "py" + pop, pop + "-py")):
            return pop
    return None


BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
BLOB = re.compile(r"[A-Za-z0-9+/=]{3000,}")
# data: URIs (inline images, fonts) are long base64 by design
DATA_URI = re.compile(r"data:[\w/+.-]*(?:;[\w=.+-]+)*,[A-Za-z0-9+/=%_-]*")
SOURCE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".rb", ".go", ".rs", ".java",
              ".php", ".ps1", ".bat", ".cmd", ".pl", ".json", ".toml", ".yaml", ".yml"}
INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
                     ".github/copilot-instructions.md", "CONVENTIONS.md")
# matched by basename at any depth: monorepos keep one per package
INSTRUCTION_NAMES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
                     "copilot-instructions.md"}
INSTRUCTION_DIRS = (".cursor/rules/", ".windsurf/rules/", ".clinerules/", ".github/instructions/", ".claude/commands/",
                    ".claude/agents/", ".claude/skills/", "skills/", "commands/", "agents/")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
# files the scan reads by name: if one is too big to read, say so instead of implying it was clean
WATCHED_NAMES = {"package.json", "setup.py", "pyproject.toml", "binding.gyp", ".envrc", "sitecustomize.py",
                 "usercustomize.py", "manifest.json", "server.json", "smithery.yaml", "plugin.json", "marketplace.json"}
WATCHED_PATHS = {".vscode/tasks.json", ".devcontainer/devcontainer.json", ".devcontainer.json", ".claude/settings.json",
                 ".claude/settings.local.json", ".gemini/settings.json", ".cursor/hooks.json", ".codex/hooks.json",
                 ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".roo/mcp.json", ".kiro/settings/mcp.json",
                 ".codex/config.toml"}


def _is_instruction(r: str) -> bool:
    return r.rsplit("/", 1)[-1] in INSTRUCTION_NAMES or r in INSTRUCTION_FILES or r.startswith(INSTRUCTION_DIRS)


def _is_watched(r: str, name: str) -> bool:
    return (name in WATCHED_NAMES or r in WATCHED_PATHS or r.endswith("hooks/hooks.json") or name.endswith(".pth")
            or r.startswith((".husky/", ".githooks/")) or _is_instruction(r))


def safe_rel(rel: str) -> str | None:
    """Normalised relative path, or None when it is absolute or climbs out of its directory."""
    # repo-relative paths are POSIX on every OS, so matching works the same on Windows
    n = posixpath.normpath(str(rel).replace("\\", "/"))
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or n == ".." or n.startswith("../") or n == ".":
        return None
    return n


def _files(root: Path, state: dict | None = None):
    n = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for p in entries:
            try:
                if p.is_symlink():
                    # never followed: only recorded, so the target can be judged as text
                    if state is not None and len(state.setdefault("symlinks", [])) < 500:
                        state["symlinks"].append(p)
                    continue
                isdir, isfile = p.is_dir(), p.is_file()
            except OSError:
                continue
            if isdir:
                if p.name == "__pycache__":
                    if state is not None and len(state.setdefault("pycache", [])) < 300:
                        state["pycache"].append(p)
                elif p.name not in SKIP_DIRS:
                    stack.append(p)
            elif isfile:
                n += 1
                if n > MAX_FILES:
                    if state is not None:
                        state["truncated"] = True
                    return
                yield p


def _read(p: Path) -> str:
    try:
        if p.stat().st_size > MAX_BYTES:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _json(p: Path):
    try:
        return json.loads(_read(p) or "null")
    except (ValueError, RecursionError):
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
    """Every command line in a JSON-ish tree: command+args pairs and the usual *Command keys.

    Iterative and depth-capped: a hostile file can nest 5000 levels to crash a recursive walk.
    """
    out: list[str] = []
    stack = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_DEPTH:
            continue
        if isinstance(cur, dict):
            if isinstance(cur.get("command"), (str, list)):
                cmd = (_flat(cur["command"]) or [""])[0]
                if isinstance(cur.get("args"), list):
                    cmd += " " + " ".join(map(str, cur["args"]))
                out.append(cmd.strip())
            for k in CMD_KEYS:
                out += _flat(cur.get(k))
            kids = [v for k, v in cur.items() if k not in CMD_KEYS and k != "command" and isinstance(v, (dict, list))]
        elif isinstance(cur, list):
            kids = list(cur)
        else:
            continue
        stack += [(v, depth + 1) for v in reversed(kids)]
    return [c for c in out if c]


def _injection(text: str) -> str | None:
    if HIDDEN_CHARS.search(text):
        return "invisible characters"
    for rx in STRONG_INJECTION:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def _hook_files(repo: Path) -> set[str]:
    """Repo files that install hooks name, plus setup.py: the code that runs before anyone looks."""
    out = {"setup.py"}
    pkg = _json(repo / "package.json")
    scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
    for hook in LIFECYCLE:
        cmd = scripts.get(hook) if isinstance(scripts, dict) else None
        if isinstance(cmd, str):
            for t in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|ts|py|sh)\b", cmd):
                n = safe_rel(t)
                if n:
                    out.add(n)
    return out


# ---------------------------------------------------------------- rare install-time and config vectors

_URL_RE = re.compile(r"(https?|git\+\w+|ssh|ftp)://([^/\s:@'\"]*@)?(\[[0-9a-f:]+\]|[^/\s:'\"?#]+)", re.I)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _url_risk(url: str, ok_hosts: tuple[str, ...] = ()) -> str | None:
    """None for an expected host, 'high' for plain http or a raw IP, else 'medium'."""
    m = _URL_RE.match(url.strip().strip("'\""))
    if not m:
        return None
    host = m.group(3).lower().strip("[]")
    if host in ok_hosts or any(host.endswith("." + h) for h in ok_hosts):
        return None
    if m.group(1).lower() == "http" or _IPV4.match(host) or ":" in host:
        return "high"
    return "medium"


NPM_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com")
PYPI_HOSTS = ("pypi.org", "pypi.python.org", "files.pythonhosted.org")
_NPMRC_KEYS = re.compile(r"^\s*(script-shell|node-options|ignore-scripts|(?:@[\w.-]+:)?registry)\s*=\s*(.*?)\s*$", re.I | re.M)
_PIP_OPT = re.compile(r"^[ \t]*(?:--)?(index-url|extra-index-url|trusted-host|-i)[ \t]*[= ][ \t]*(\S+)", re.I | re.M)
_PIP_OPT_REQ = re.compile(r"^[ \t]*(--index-url|--extra-index-url|--trusted-host|-i)[ \t=]+(\S+)", re.I | re.M)


def _pkg_config(r: str, name: str, text: str, add) -> None:
    low = name.lower()
    if low == ".npmrc":
        for m in _NPMRC_KEYS.finditer(text):
            key, val = m.group(1).lower(), m.group(2).strip("'\"")
            if key == "ignore-scripts":
                if val.lower() == "false":
                    add("medium", "pkg-config", r + key, f"{r} turns install scripts back on (ignore-scripts=false)", m.group(0).strip())
            elif key.endswith("registry"):
                risk = _url_risk(val, NPM_HOSTS)
                if risk:
                    add(risk, "pkg-config", r + key + val, f"{r} points npm at a non-default registry", m.group(0).strip())
            else:
                add("medium", "pkg-config", r + key, f"{r} sets {key}, which changes what npm install runs", m.group(0).strip())
    elif low == ".yarnrc.yml":
        m_yp = re.search(r"^\s*yarnPath\s*:\s*['\"]?([^\s'\"#]+)", text, re.M)
        if m_yp:
            # Yarn Berry repos pin their yarn under .yarn/releases/ by design; anywhere else is unusual.
            usual = re.fullmatch(r"\.yarn/releases/yarn-[\w.-]+\.c?js", m_yp.group(1).lstrip("./"))
            add("info" if usual else "medium", "pkg-config", r + "yarnPath",
                f"{r} runs a repo-supplied yarn (yarnPath)", m_yp.group(1))
        if re.search(r"^\s*plugins\s*:", text, re.M):
            add("medium", "pkg-config", r + "plugins", f"{r} loads yarn plugins (repo code runs on every yarn command)", "plugins:")
        for m in re.finditer(r"^\s*npmRegistryServer\s*:\s*(\S+)", text, re.M):
            risk = _url_risk(m.group(1), NPM_HOSTS)
            if risk:
                add(risk, "pkg-config", r + "reg", f"{r} points yarn at a non-default registry", m.group(0).strip())
    elif low == ".yarnrc":
        if re.search(r"^\s*yarn-path\b", text, re.M):
            add("medium", "pkg-config", r + "yarn-path", f"{r} runs a repo-supplied yarn (yarn-path)", "yarn-path")
    elif low in (".pnpmfile.cjs", ".pnpmfile.mjs", "pnpmfile.js"):
        add("medium", "pkg-config", r, f"{r} runs repo code at every pnpm install", "pnpm hooks can rewrite any dependency")
    else:
        if low == "pyproject.toml" and not re.search(r"^\[+tool\.(pip|uv)\b", text, re.M):
            return
        rx = _PIP_OPT_REQ if low.startswith("requirements") and low.endswith(".txt") else _PIP_OPT
        if low.endswith(".txt") and not low.startswith("requirements"):
            return
        for m in rx.finditer(text):
            key, val = m.group(1).lower().lstrip("-"), m.group(2).strip("'\",")
            if key == "trusted-host":
                add("high" if _IPV4.match(val.split(":")[0]) else "medium", "pkg-config", r + key + val,
                    f"{r} disables TLS checking for a package host (trusted-host)", m.group(0).strip())
            else:
                risk = _url_risk(val, PYPI_HOSTS)
                if risk:
                    add(risk, "pkg-config", r + key + val, f"{r} installs Python packages from a non-PyPI index", m.group(0).strip())


_FETCH_EXEC = re.compile(r"(curl|wget)[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|/dev/(tcp|udp)/|base64\s+(-d|--decode)|"
                         r"powershell|Invoke-Expression|\bnc\s+-[a-z]*e\b", re.I)
_DEV_NET = re.compile(r"\b(curl|wget)\b|urlopen\(|urllib\.request|requests\.(get|post|put)\(|http\.client|"
                      r"socket\.create_connection|Invoke-WebRequest|\bnc\s|aiohttp\.ClientSession|httpx\.(get|post)\(")
_RS_RISK = re.compile(r"TcpStream|UdpSocket|reqwest::|ureq::|curl::|Command::new\(\s*\"(?:curl|wget|sh|bash|powershell|pwsh)\"|"
                      r"include_bytes!\(\s*\"[^\"]*\.(?:bin|exe|so|dll|dylib|dat|node|wasm|elf)\"")


def _make_default_target(text: str) -> str:
    out, seen = [], False
    for ln in text.splitlines():
        if not seen:
            if re.match(r"^[A-Za-z0-9_][^\s:=#]*(\s+[^\s:=#]+)*\s*:(?![=:])", ln) and not ln.startswith("."):
                seen = True
                out.append(ln.split(":", 1)[1])
            continue
        if ln.startswith(("\t", " ")) or not ln.strip():
            out.append(ln)
        elif not ln.lstrip().startswith("#"):
            break
    return "\n".join(out)


def _dev_autorun(r: str, p: Path, name: str, text: str, add) -> None:
    low = name.lower()
    if low in ("conftest.py", "noxfile.py", "tasks.py") or low in ("makefile", "gnumakefile"):
        body = _make_default_target(text) if low in ("makefile", "gnumakefile") else text
        when = {"conftest.py": "pytest imports it on every test run", "noxfile.py": "runs on every nox command",
                "tasks.py": "runs on every invoke command"}.get(low, "the default make target runs it")
        if _FETCH_EXEC.search(body):
            add("high", "dev-autorun", r, f"{r} fetches and runs code ({when})", _FETCH_EXEC.search(body).group(0)[:120])
        elif _DEV_NET.search(body):
            add("medium", "dev-autorun", r, f"{r} talks to the network ({when})", _DEV_NET.search(body).group(0)[:120])
    elif low == "build.rs":
        m = _RS_RISK.search(text)
        if m:
            add("medium", "dev-autorun", r, f"{r} does network work, runs a downloader or shell, or embeds a binary at cargo build",
                m.group(0)[:120])
    elif low.endswith(".go"):
        for m in re.finditer(r"^[ \t]*//go:generate[ \t]+(.+)$", text, re.M):
            cmd = m.group(1)
            if re.search(r"\b(curl|wget)\b", cmd) or re.match(r"(sh|bash|zsh|powershell|pwsh)\b", cmd):
                add("medium", "dev-autorun", r + cmd[:40], f"{r} has a go:generate line that runs a downloader or shell", cmd[:150])
    elif low in ("gradle-wrapper.properties", "maven-wrapper.properties"):
        gradle = low.startswith("gradle")
        jar = p.parent / ("gradle-wrapper.jar" if gradle else "maven-wrapper.jar")
        if not jar.is_file():
            return
        ok = ("services.gradle.org", "downloads.gradle.org") if gradle else ("repo.maven.apache.org", "repo1.maven.org")
        for m in re.finditer(r"^\s*(distributionUrl|wrapperUrl)\s*=\s*(\S+)", text, re.M):
            url = m.group(2).replace("\\:", ":")
            if _url_risk(url, ok):
                add("medium", "dev-autorun", r, f"{r} fetches the build tool from a non-standard host and a wrapper jar runs it",
                    m.group(1) + "=" + url[:150])


SHADOWED = {"ls", "cat", "sh", "bash", "zsh", "git", "npm", "npx", "node", "python", "python3", "pip", "pip3", "sudo", "ssh",
            "curl", "wget", "docker", "kubectl", "code", "claude", "codex", "gemini", "cursor"}
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions",
                 "pnpm")


def _dep_values(obj, depth=0):
    """(name, spec) pairs from a dependency table, descending into nested overrides."""
    if depth > 4 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        if isinstance(v, str):
            yield str(k), v
        elif isinstance(v, dict):
            yield from _dep_values(v, depth + 1)


def _package_json_checks(r: str, pkg: dict, add) -> None:
    bins = pkg.get("bin")
    names = []
    if isinstance(bins, str) and isinstance(pkg.get("name"), str):
        names = [pkg["name"].rsplit("/", 1)[-1]]
    elif isinstance(bins, dict):
        names = [str(k) for k in bins]
    for n in names:
        if n in SHADOWED:
            add("high", "bin-shadow", r + n, f"{r} installs a command named '{n}' that shadows the real one",
                f"bin: {n}")
    n_dep = 0
    for sect in _DEP_SECTIONS:
        for dep, spec in _dep_values(pkg.get(sect)):
            n_dep += 1
            if n_dep > 400:
                return
            s = spec.strip()
            if re.match(r"(git\+|git://|github:|gitlab:|bitbucket:|file:|link:|https?://)", s, re.I) or re.search(r"\.t(ar\.)?gz$", s):
                risk = _url_risk(s)
                sev = "medium" if (s.lower().startswith("http://") or risk == "high") else "info"
                add(sev, "dep-source", r + dep, f"{r} installs '{dep}' from outside the registry", f"{dep}: {s[:150]}")
            elif (dep.startswith("@") or re.search(r"internal|corp|private", dep, re.I)) and re.match(r"^[\^~>=v\s]*(99|999|9999|99999)(\.\d+){0,2}", s):
                add("info", "dep-confusion", r + dep, f"{r} pins '{dep}' to version {s}, a dependency-confusion pattern", f"{dep}: {s}")


def _workflow_check(r: str, text: str, add) -> None:
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    if not re.search(r"\b(pull_request_target|workflow_run)\b", body):
        return
    if not re.search(r"checkout", body):
        return
    m = re.search(r"github\.event\.pull_request\.head\.(sha|ref|repo[\w.]*)|github\.head_ref|"
                  r"github\.event\.workflow_run\.head_(sha|branch|repository[\w.]*)|refs/pull/[^\s'\"]*/(merge|head)", body)
    if m:
        add("medium", "ci-untrusted-checkout", r, "CI workflow runs untrusted PR code with repository secrets",
            f"{r}: privileged trigger plus checkout of {m.group(0)}; a risk to the repo's own users and maintainers")


# files that mention telemetry SDKs by dependency name
_TEL_EXACT = {"posthog", "posthog-js", "posthog-node", "analytics-node", "analytics-python", "segment-analytics-python",
              "mixpanel", "mixpanel-browser", "amplitude", "amplitude-js", "sentry-sdk", "raven", "datadog", "ddtrace",
              "dd-trace", "newrelic", "applicationinsights", "opencensus-ext-azure", "logrocket", "hotjar", "react-ga",
              "react-ga4", "google-analytics", "gtag", "ga-gtag", "vue-gtag", "plausible-tracker", "plausible",
              "heap-api", "heapanalytics", "bugsnag", "rollbar", "honeybadger", "firebase-analytics", "rudder-sdk-js",
              "rudder-sdk-node", "rudderstack", "@vercel/analytics", "@vercel/speed-insights"}
_TEL_PREFIX = ("@sentry/", "@segment/", "@datadog/", "@amplitude/", "@bugsnag/", "@honeybadger-io/", "@rudderstack/",
               "@plausible", "@firebase/analytics", "@hotjar/", "@newrelic/", "@microsoft/applicationinsights",
               "@posthog/", "@mixpanel/", "@logrocket/")
_MCP_DEPS = {"@modelcontextprotocol/sdk", "mcp", "fastmcp"}
_PRIVACY_FILE = re.compile(r"^(privacy|terms|data[-_ ]collection|telemetry)([-_ ].*)?$", re.I)
_PRIVACY_HEAD = re.compile(r"^#{1,6}[ \t].*\b(privacy|telemetry|data collection|analytics)\b", re.I | re.M)
OPTOUT = re.compile(r"\bDO_NOT_TRACK\b|\b[A-Z][A-Z0-9_]{1,40}_(?:NO_TELEMETRY|TELEMETRY_(?:DISABLED?|OPT_?OUT|OFF)|"
                    r"DISABLE_TELEMETRY|DISABLE_ANALYTICS|ANALYTICS_DISABLED)\b|\bDISABLE_TELEMETRY\b|\bNO_TELEMETRY\b")


def _tel(dep: str) -> bool:
    d = dep.lower().replace("_", "-")
    return d in _TEL_EXACT or d.startswith(_TEL_PREFIX)


def _py_dep_names(lines) -> set[str]:
    out = set()
    for ln in lines:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", ln) if isinstance(ln, str) else None
        if m:
            out.add(m.group(1).lower().replace("_", "-"))
    return out


def _collect_deps(r: str, name: str, text: str, pkg, ctx: dict) -> None:
    low = name.lower()
    if low == "package.json" and isinstance(pkg, dict):
        for sect in ("dependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(pkg.get(sect), dict):
                ctx["deps"] |= {str(k) for k in pkg[sect]}
    elif low.startswith("requirements") and low.endswith(".txt") and not re.search(r"dev|test|doc|lint", low):
        ctx["deps"] |= _py_dep_names(text.splitlines())
    elif low == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except (ValueError, RecursionError):
            return
        proj = data.get("project") if isinstance(data.get("project"), dict) else {}
        if isinstance(proj.get("dependencies"), list):
            ctx["deps"] |= _py_dep_names(proj["dependencies"])
        opt = proj.get("optional-dependencies")
        for k, v in opt.items() if isinstance(opt, dict) else []:
            if isinstance(v, list) and not re.search(r"dev|test|doc|lint", str(k)):
                ctx["deps"] |= _py_dep_names(v)
        poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
        if isinstance(poetry.get("dependencies"), dict):
            ctx["deps"] |= {str(k).lower() for k in poetry["dependencies"]}


# ---------------------------------------------------------------- obfuscated JavaScript

_OBF_HEX_IDS = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_OBF_STRARRAY = re.compile(r"\b(?:var|let|const)\s+_0x[0-9a-f]{3,6}\s*=\s*\[\s*['\"]")
_OBF_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")
_OBF_CHARCODES = re.compile(r"fromCharCode\s*\(\s*(?:\d+\s*,\s*){29,}\d+")
_OBF_JSFUCK = re.compile(r"[\[\]()+!]{200,}")


def obfuscation(text: str) -> str | None:
    """Short name of the obfuscation scheme found in JavaScript source, or None."""
    n = len(_OBF_HEX_IDS.findall(text))
    if n >= 20:
        return f"javascript-obfuscator style identifiers ({n} _0x names)"
    if _OBF_STRARRAY.search(text) and re.search(r"\(function\s*\(\s*_0x[0-9a-f]+\s*,\s*_0x[0-9a-f]+", text):
        return "string-array with rotation function"
    if _OBF_ESCAPES.search(text):
        return "long \\x escape run"
    if _OBF_CHARCODES.search(text):
        return "String.fromCharCode chain of 30+ numbers"
    if _OBF_JSFUCK.search(text):
        return "JSFuck-style symbol run"
    return None


_IMG_REF = re.compile(r"['\"`]([\w./@ -]*?([\w-]+\.(?:png|jpe?g|gif|webp|bmp|ico)))['\"`]", re.I)
_EVALISH = re.compile(r"(?<![.\w])eval\s*\(|new\s+Function\s*\(|(?<![.\w])Function\s*\(|(?<![.\w])exec\s*\(|vm\.run\w+\(")
_READS_FILE = re.compile(r"readFileSync|readFile\s*\(|createReadStream|\bopen\s*\(|Path\([^)]*\)\.read_bytes|read_bytes\(|__file__|__filename")
COMPILED_EXT = {".pyc", ".so", ".node", ".dll", ".exe", ".jar", ".dylib", ".pyd"}


def _hook_refs(repo: Path) -> tuple[set[str], set[str]]:
    """(files an install hook names, files package.json main/bin names). Any extension: a hook can run a .node or .jar."""
    refs: set[str] = set()
    entries: set[str] = set()
    tok = re.compile(r"[\w./@+-]+\.[A-Za-z0-9]{1,6}\b")

    def put(dest: set, t: str):
        n = safe_rel(t[2:] if t.startswith("./") else t)
        if n:
            dest.add(n)

    pkg = _json(repo / "package.json")
    if isinstance(pkg, dict):
        scripts = pkg.get("scripts")
        for hook in LIFECYCLE:
            cmd = scripts.get(hook) if isinstance(scripts, dict) else None
            if isinstance(cmd, str):
                for t in tok.findall(cmd):
                    put(refs, t)
        if isinstance(pkg.get("main"), str):
            put(entries, pkg["main"])
        b = pkg.get("bin")
        for v in ([b] if isinstance(b, str) else list(b.values()) if isinstance(b, dict) else []):
            if isinstance(v, str):
                put(entries, v)
    setup = _read(repo / "setup.py")
    for t in re.findall(r"['\"]([\w./-]+\.[A-Za-z0-9]{1,6})['\"]", setup):
        put(refs, t)
    return refs, entries


RANK = {"critical": 3, "high": 2, "medium": 1, "info": 0}


def _post(repo: Path, state: dict, ctx: dict, loaders, images: dict, scanner, add) -> None:
    """Checks that need the whole walk: symlinks, orphaned bytecode, steganography loaders, telemetry, budget."""
    root = os.path.realpath(repo)
    for p in state.get("symlinks", []):
        r = p.relative_to(repo).as_posix()
        try:
            tgt = os.readlink(p)
        except OSError:
            continue
        if os.path.isabs(tgt):
            norm = os.path.normpath(tgt)
            outside = not (norm == root or norm.startswith(root + os.sep) or norm == str(repo) or norm.startswith(str(repo) + os.sep))
        elif tgt.startswith("~"):
            norm, outside = tgt, True
        else:
            norm = os.path.normpath(os.path.join(os.path.dirname(r), tgt))
            outside = norm == ".." or norm.startswith(".." + os.sep)
        if not outside:
            continue
        cred = _CRED_LINK.search(tgt) or _CRED_LINK.search(norm)
        add("high" if cred else "medium", "symlink-escape", r,
            f"symlink {r} points outside the repo" + (" at a credential or system path" if cred else ""),
            f"{r} -> {tgt}", file=r)
    for d in state.get("pycache", []):
        try:
            pycs = [x.name for x in d.iterdir() if x.name.endswith(".pyc")]
        except OSError:
            continue
        orphans = [n for n in pycs if not (d.parent / (n.split(".")[0] + ".py")).exists()]
        if orphans:
            rd = d.relative_to(repo).as_posix()
            add("medium", "compiled-python", rd, f"{rd} holds compiled Python with no matching source",
                ", ".join(orphans[:4]), file=rd)
    for r, names in loaders:
        hit = sorted(n for n in names if n in images)
        if hit:
            add("high", "image-loader", r, f"{r} reads {hit[0]} and runs code (possible steganography loader)",
                f"image {images[hit[0]]} is named in a file that reads files and calls eval/exec/Function", file=r)
    sdks = sorted(d for d in ctx["deps"] if _tel(d))
    if sdks:
        add("info", "data-sharing", "sdks", "sends data to third parties: " + ", ".join(sdks[:12]), "telemetry or error-reporting SDKs in dependencies", file="")
        if not ctx["policy"]:
            agent = ctx["plugin"] or bool(ctx["deps"] & _MCP_DEPS)
            add("medium" if agent else "info", "privacy-policy", "nopolicy", "no privacy policy found",
                ("this MCP server or agent plugin sees your conversations and files, and ships telemetry SDKs without saying what it sends"
                 if agent else "telemetry SDKs are present but there is no PRIVACY or TERMS file or privacy section in the README"), file="")
    if ctx["optouts"]:
        add("info", "telemetry-optout", "optout", "telemetry can be disabled with " + ", ".join(sorted(ctx["optouts"])[:5]), "", file="")
    if scanner.budget.incomplete:
        add("medium", "scan-incomplete", "artifact-budget",
            "artifact scan incomplete: the 300 MB read budget ran out, some archives, binaries or images were not inspected",
            "", file="")


_CRED_LINK = re.compile(r"\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.netrc|\.npmrc|\.config\b|id_rsa|id_ed25519|credentials|"
                        r"/etc(?:/|$)|/proc(?:/|$)|Keychains|\.git-credentials|\.env\b|~$", re.I)


def scan(repo: Path) -> list[Finding]:
    found: dict[tuple, Finding] = {}
    try:
        hooked = _hook_files(repo)
    except Exception:
        hooked = {"setup.py"}
    try:
        refs, entries = _hook_refs(repo)
    except Exception:
        refs, entries = set(), set()
    scanner = artifacts.Scanner(refs | hooked, entries)
    # telemetry / privacy facts gathered while walking, judged once at the end
    ctx: dict = {"deps": set(), "policy": False, "optouts": set(), "plugin": False}
    loaders: list[tuple[str, set[str]]] = []   # code that reads files and evals, with the images it names
    images: dict[str, str] = {}                # image basename -> repo path
    cur = [""]

    def add(sev, rule, key, title, detail="", file=None):
        old = found.get((rule, key))
        if old and RANK[old.severity] >= RANK[sev]:
            return
        found[(rule, key)] = Finding(sev, rule, title, detail[:300], "static", cur[0] if file is None else file)

    def rel(p: Path) -> str:
        return p.relative_to(repo).as_posix()

    def judge_cmd(rule: str, where: str, cmd: str, base: str = "info"):
        # keyed on the whole command: two hooks sharing a 40-char prefix must not shadow each other
        if HOT.search(cmd):
            add("high", rule, where + cmd, f"{where} runs a fetch-and-execute or obfuscated command", cmd)
        elif WARM.search(cmd):
            add("medium" if base != "high" else "high", rule, where + cmd, f"{where} runs a command", cmd)
        else:
            add(base, rule, where + cmd, f"{where} runs a command", cmd)

    def one(p: Path):
        name, r = p.name, rel(p)
        cur[0] = r
        bulky = any(part in BULKY for part in Path(r).parts[:-1])

        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        if size > MAX_BYTES and _is_watched(r, name):
            add("medium", "scan-incomplete", r, f"{r} is too large to inspect ({size} bytes)", r)
            return

        depth = r.count("/")
        low = name.lower()
        if low in (".npmrc", ".yarnrc.yml", ".yarnrc", ".pnpmfile.cjs", ".pnpmfile.mjs", "pnpmfile.js", "pip.conf", "setup.cfg",
                   "pyproject.toml") or (low.startswith("requirements") and low.endswith(".txt")):
            text = _read(p)
            _pkg_config(r, name, text, add)
            if low == "pyproject.toml" or low.startswith("requirements"):
                _collect_deps(r, name, text, None, ctx)
        if low in ("conftest.py", "noxfile.py", "tasks.py", "makefile", "gnumakefile", "build.rs",
                   "gradle-wrapper.properties", "maven-wrapper.properties") or low.endswith(".go"):
            if not (low.endswith(".go") and bulky):
                _dev_autorun(r, p, name, _read(p), add)
        if low.endswith((".yml", ".yaml")) and r.startswith(".github/workflows/"):
            _workflow_check(r, _read(p), add)
        if r.startswith(".claude-plugin/"):
            ctx["plugin"] = True
        if depth <= 2 and _PRIVACY_FILE.match(p.stem) and p.suffix.lower() in ("", ".md", ".txt", ".html", ".rst"):
            ctx["policy"] = True
        if depth <= 1 and low.startswith("readme"):
            rd = _read(p)
            if _PRIVACY_HEAD.search(rd):
                ctx["policy"] = True
            ctx["optouts"] |= set(OPTOUT.findall(rd))
        if low == "package.json" and depth <= 2:
            pj = _json(p)
            if isinstance(pj, dict):
                _package_json_checks(r, pj, add)
                _collect_deps(r, name, "", pj, ctx)
        if p.suffix.lower() == ".pyc":
            add("medium", "compiled-python", r, f"{r} is compiled Python committed without its source",
                "bytecode hides what the code does; ask for the .py source")
        if p.suffix.lower() in COMPILED_EXT and (r in refs):
            add("high", "compiled-hook", r, f"{r} is a compiled file run or loaded by an install hook",
                "install hooks should run readable scripts, not binaries or bytecode")
        if p.suffix.lower() in artifacts.IMG_EXT:
            images.setdefault(p.name, r)
        if p.suffix.lower() in (".js", ".mjs", ".cjs") and (not name.endswith(".min.js") or r in refs or r in entries):
            named = r in refs or r in entries
            js = _read(p) if size <= MAX_BYTES else ""
            if js:
                why = obfuscation(js)
                if why:
                    add("medium" if named else "info", "obfuscated-js", r,
                        f"{r} is obfuscated JavaScript" + (" run by an install hook or entry point" if named else ""), why)

        # ---- package managers: code that runs at install
        if name == "package.json":
            pkg = _json(p)
            pkg = pkg if isinstance(pkg, dict) else {}
            if r == "package.json" and isinstance(pkg.get("name"), str):
                twin = _typosquat(pkg["name"])
                if twin:
                    add("medium", "typosquat", pkg["name"], f"package name '{pkg['name']}' imitates '{twin}'", r)
            scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
            for hook in LIFECYCLE:
                if isinstance(scripts.get(hook), str):
                    judge_cmd("install-hook", f"{r} {hook}", scripts[hook])
                    for decoded in deobf.payloads(scripts[hook])[:2]:
                        add("medium", "decoded-payload", r + hook + decoded[:20],
                            f"{r} {hook} hides an encoded payload; decoded:", decoded[:300])
            engines = pkg.get("engines")
            if isinstance(engines, dict) and "vscode" in engines:
                events = pkg.get("activationEvents")
                events = events if isinstance(events, list) else []
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
            except (ValueError, RecursionError):
                data = {}
            proj = data.get("project")
            pname = proj.get("name") if isinstance(proj, dict) else None
            if r == "pyproject.toml" and isinstance(pname, str) and _typosquat(pname):
                add("medium", "typosquat", pname, f"package name '{pname}' imitates '{_typosquat(pname)}'", r)
            bs = data.get("build-system")
            if isinstance(bs, dict) and bs.get("backend-path"):
                add("medium", "install-hook", r, f"{r} uses an in-tree build backend (repo code runs at install)", r)
        elif p.suffix == ".pth" or name in ("sitecustomize.py", "usercustomize.py"):
            body = _read(p)
            if name.endswith(".py") or re.search(r"^\s*import\s", body, re.M):
                add("high", "auto-exec", r, f"{r} runs code at every Python start", body.strip()[:120])
        elif name == "binding.gyp":
            add("info", "install-hook", r, f"{r} compiles native code at install", r)

        # ---- editors, shells, containers
        elif r == ".vscode/tasks.json":
            tasks = _json(p)
            tl = tasks.get("tasks") if isinstance(tasks, dict) else None
            for t in tl if isinstance(tl, list) else []:
                ro = t.get("runOptions") if isinstance(t, dict) else None
                if isinstance(ro, dict) and ro.get("runOn") == "folderOpen":
                    judge_cmd("auto-exec", "VS Code task that runs when the folder is opened",
                              " ".join(_commands(t)) or str(t.get("label")), base="high")
        elif r in (".devcontainer/devcontainer.json", ".devcontainer.json"):
            dc = _json(p)
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
            cfg = _json(p)
            hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
            for cmd in _commands(hooks or {}):
                judge_cmd("agent-hook", f"agent hook in {r}", cmd, base="medium")
            if isinstance(cfg, dict):
                if cfg.get("enableAllProjectMcpServers"):
                    add("medium", "agent-config", r, f"{r} auto-approves every project MCP server", r)
                allow = ((cfg.get("permissions") or {}).get("allow") or []) if isinstance(cfg.get("permissions"), dict) else []
                allow = allow if isinstance(allow, list) else []
                broad = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(\(\*?\))?|Bash\(\s*\*\s*\)", a)]
                if broad:
                    add("medium", "agent-config", r, f"{r} pre-approves any shell command for the agent", ", ".join(broad))
                for cmd in _commands(cfg.get("mcpServers") or {}):
                    judge_cmd("project-mcp", f"MCP server in {r}", cmd)
        elif r in (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".roo/mcp.json", ".kiro/settings/mcp.json"):
            cfg = _json(p)
            servers = (cfg.get("mcpServers") or cfg.get("servers") or {}) if isinstance(cfg, dict) else {}
            for sname, spec in servers.items() if isinstance(servers, dict) else []:
                if not isinstance(spec, dict):
                    continue
                args = spec.get("args") if isinstance(spec.get("args"), list) else []
                cmd = " ".join(_commands({"command": spec.get("command", ""), "args": args}))
                url = spec.get("url")
                judge_cmd("project-mcp", f"project MCP server '{sname}' in {r}", cmd or str(url or ""))
        elif r == ".codex/config.toml":
            try:
                cfg = tomllib.loads(_read(p))
            except (ValueError, RecursionError):
                cfg = {}
            servers = cfg.get("mcp_servers")
            for sname, spec in servers.items() if isinstance(servers, dict) else []:
                if not isinstance(spec, dict):
                    continue
                args = spec.get("args") if isinstance(spec.get("args"), list) else []
                cmd = f"{spec.get('command', '')} {' '.join(map(str, args))}".strip()
                judge_cmd("project-mcp", f"Codex MCP server '{sname}' in {r}", cmd)
            notify = cfg.get("notify")
            if notify:
                # a bare string is one command; only a list is an argv to join
                line = " ".join(map(str, notify)) if isinstance(notify, list) else str(notify)
                judge_cmd("agent-hook", f"Codex notify hook in {r}", line, base="medium")
        elif name in ("plugin.json", "marketplace.json") and p.parent.name == ".claude-plugin":
            man = _json(p)
            man = man if isinstance(man, dict) else {}
            parts = [k for k in ("hooks", "commands", "agents", "mcpServers", "skills") if man.get(k)]
            add("info", "plugin-manifest", r, f"Claude Code plugin manifest ({', '.join(parts) or 'metadata only'})", r)
            for cmd in _commands(man.get("mcpServers") or {}):
                judge_cmd("project-mcp", f"plugin MCP server in {r}", cmd)
        elif name in ("manifest.json", "server.json", "smithery.yaml") and p.parent == repo:
            text = _read(p)
            if '"tools"' in text or "mcp" in text.lower():
                add("info", "plugin-manifest", r, f"MCP server manifest {r}", r)
                hit = _injection(text)
                if hit:
                    add("high", "mcp-tool-poisoning", r, f"{r} tool metadata carries instructions aimed at the model", hit)

        if _is_instruction(r):
            hit = instruction_injection(_read(p))
            if hit:
                add(hit[1], "agent-instructions", r, f"{r} carries hidden or injected instructions for AI agents", hit[0])

        # ---- source tricks (skipped in generated dirs: only their config and hook files matter)
        if p.suffix in SOURCE_EXT and not bulky:
            text = _read(p)
            if BIDI.search(text):
                add("medium", "trojan-source", r, f"{r} contains bidirectional control characters", r)
            elif HIDDEN_CHARS.search(text):
                add("info", "trojan-source", r, f"{r} contains invisible Unicode characters", r)
            ctx["optouts"] |= set(OPTOUT.findall(text))
            if p.suffix in (".js", ".mjs", ".cjs", ".ts", ".py") and len(loaders) < 300 and _EVALISH.search(text) \
                    and _READS_FILE.search(text):
                names = {m.group(2) for m in _IMG_REF.finditer(text)}
                if names:
                    loaders.append((r, names))
            hit = source_injection(text) if p.suffix in (".js", ".mjs", ".cjs", ".ts", ".py") else None
            if hit:
                add(hit[1], "agent-instructions", r, f"{r} contains text aimed at an AI model (tool description injection)", hit[0])
            if p.suffix in GATE_EXT and ACTS.search(text):
                gate = DATE_GATE.search(text) or LONG_TIMER.search(text)
                sev = "medium" if r in hooked else "info"
                if gate:
                    add(sev, "delayed-activation", r, f"{r} waits for a date or a long timer before acting",
                        gate.group(0)[:100])
                env_gate = ENV_GATE.search(text)
                if env_gate and r in hooked and NET_CALL.search(text):
                    add("medium", "environment-gate", r, f"{r} checks CI, hostname or user before acting",
                        env_gate.group(0))
            body = DATA_URI.sub("data:", text)
            blob = BLOB.search(body)
            if r in hooked or blob:
                for decoded in deobf.payloads(body)[:2]:
                    add("medium" if r in hooked else "info", "decoded-payload", r + decoded[:20],
                        f"{r} hides an encoded payload; decoded:", decoded[:300])
            if blob and p.suffix in (".js", ".mjs", ".cjs", ".py", ".ts"):
                readable = deobf._decode(blob.group(0)) is not None
                add("medium" if readable else "info", "encoded-blob", r, f"{r} embeds a large encoded blob", r)

    def artifact(p: Path):
        if not scanner.wants(p.name):
            return
        try:
            size = p.stat().st_size
        except OSError:
            return
        r = rel(p)
        cur[0] = r
        for h in scanner.scan_file(p, r, size):
            add(h.severity, h.rule, h.key, h.title, h.detail, file=r)

    state: dict = {}
    for p in _files(repo, state):
        try:
            one(p)
            artifact(p)
        except Exception:  # a hostile file must never abort the scan
            try:
                r = rel(p)
            except ValueError:
                r = p.name
            add("info", "scan-error", "err:" + r, f"could not parse {r}", r, file=r)
    try:
        _post(repo, state, ctx, loaders, images, scanner, add)
    except Exception:
        add("info", "scan-error", "post", "could not finish the artifact and privacy checks", "", file="")
    if state.get("truncated"):
        add("medium", "scan-incomplete", "max-files", f"scan incomplete: more than {MAX_FILES} files, the rest were not read", "", file="")

    return sorted(found.values(), key=lambda f: (-RANK[f.severity], f.rule, f.title))
