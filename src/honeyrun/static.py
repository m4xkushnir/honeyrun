"""Static pre-scan: read the repo without running it.

Lists every place where code runs on its own (install hooks, editor tasks,
devcontainers, direnv, .pth files, agent hooks and plugins, project MCP
servers) and every file that talks to an AI agent (AGENTS.md, CLAUDE.md,
.cursorrules, tool descriptions in MCP manifests). Pure pattern matching on the
host: nothing here executes repo code and nothing here needs an AI.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

from . import deobf
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
            sev = "high" if SENSITIVE.search(window) else "medium"
            if best is None or sev == "high":
                best = (m.group(0), sev)
            if sev == "high":
                return best
    return best


# Instruction files (AGENTS.md ...) are prose: naming ~/.config or saying "upload to https://" is
# ordinary documentation. Only imperative phrasing aimed at the model or at secrets counts.
_SECRET_TARGET = (r"(?:(?:~|\$HOME)/\.(?:ssh|aws|gnupg|kube|docker|npmrc|netrc|config/(?:gcloud|gh))|id_(?:rsa|ed25519|ecdsa)\b|"
                  r"\.env(?![.\w-])|credentials\b|mcp\.json|claude_desktop_config|\.claude\.json)")
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
    n = os.path.normpath(rel)
    if os.path.isabs(n) or n == ".." or n.startswith(".." + os.sep) or n == ".":
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
                    continue
                isdir, isfile = p.is_dir(), p.is_file()
            except OSError:
                continue
            if isdir:
                if p.name not in SKIP_DIRS:
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
        return p.read_text(errors="replace")
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


RANK = {"critical": 3, "high": 2, "medium": 1, "info": 0}


def scan(repo: Path) -> list[Finding]:
    found: dict[tuple, Finding] = {}
    try:
        hooked = _hook_files(repo)
    except Exception:
        hooked = {"setup.py"}
    cur = [""]

    def add(sev, rule, key, title, detail="", file=None):
        old = found.get((rule, key))
        if old and RANK[old.severity] >= RANK[sev]:
            return
        found[(rule, key)] = Finding(sev, rule, title, detail[:300], "static", cur[0] if file is None else file)

    def rel(p: Path) -> str:
        return str(p.relative_to(repo))

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

    state: dict = {}
    for p in _files(repo, state):
        try:
            one(p)
        except Exception:  # a hostile file must never abort the scan
            try:
                r = rel(p)
            except ValueError:
                r = p.name
            add("info", "scan-error", "err:" + r, f"could not parse {r}", r, file=r)
    if state.get("truncated"):
        add("medium", "scan-incomplete", "max-files", f"scan incomplete: more than {MAX_FILES} files, the rest were not read", "", file="")

    return sorted(found.values(), key=lambda f: (-RANK[f.severity], f.rule, f.title))
