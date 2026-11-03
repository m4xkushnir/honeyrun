"""Work out how to install and run a repository."""
from __future__ import annotations

import json
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

MCP_NODE_DEPS = {"@modelcontextprotocol/sdk", "fastmcp", "mcp-framework"}
MCP_PY_DEPS = re.compile(r"^\s*['\"]?(mcp|fastmcp)\b", re.I)
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")


@dataclass
class Plan:
    ecosystem: str = "unknown"
    mcp: bool = False
    phases: list[dict] = field(default_factory=list)
    lifecycle: dict[str, str] = field(default_factory=dict)


def _node(repo: Path, plan: Plan, offline: bool) -> tuple[str | None, str | None]:
    try:
        pkg = json.loads((repo / "package.json").read_text())
    except (OSError, ValueError):
        pkg = {}
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps |= set((pkg.get(key) or {}).keys())
    plan.mcp = bool(deps & MCP_NODE_DEPS)
    scripts = pkg.get("scripts") or {}
    plan.lifecycle = {k: scripts[k] for k in LIFECYCLE if k in scripts}

    install = "npm install --no-audit --no-fund"
    bin_ = pkg.get("bin")
    bin_path = next(iter(bin_.values()), None) if isinstance(bin_, dict) else bin_
    main = pkg.get("main")
    run = None
    if plan.mcp and bin_path:
        run = f"node {shlex.quote(bin_path)}"
    elif "start" in scripts:
        run = "npm start --silent"
    elif main and (repo / main).exists():
        run = f"node {shlex.quote(main)}"
    elif bin_path:
        run = f"node {shlex.quote(bin_path)}"
    elif (repo / "index.js").exists():
        run = "node index.js"
    return install, run


def _python(repo: Path, plan: Plan, offline: bool) -> tuple[str | None, str | None]:
    deps: list[str] = []
    scripts: dict = {}
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
            project = data.get("project") or {}
            deps += project.get("dependencies") or []
            scripts = project.get("scripts") or {}
        except (OSError, ValueError):
            pass
    req = repo / "requirements.txt"
    if req.exists():
        deps += req.read_text(errors="replace").splitlines()
    plan.mcp = any(MCP_PY_DEPS.match(d) for d in deps)

    install = None
    if pyproject.exists() or (repo / "setup.py").exists():
        install = "python3 -m pip install --user ."
        if offline:
            install += " --no-build-isolation --no-deps --no-index"
    elif req.exists() and not offline:
        install = "python3 -m pip install --user -r requirements.txt"

    run = None
    if scripts and install:
        run = shlex.quote(next(iter(scripts)))
    else:
        for name in ("server.py", "main.py", "app.py", "__main__.py"):
            if (repo / name).exists():
                run = f"python3 {name}"
                break
    return install, run


def plan(repo: Path, network: str, install: str | None, run: str | None,
         install_timeout: int, run_timeout: int, mcp: bool | None = None) -> Plan:
    p = Plan()
    offline = network == "offline"
    auto_install = auto_run = None
    if (repo / "package.json").exists():
        p.ecosystem = "node"
        auto_install, auto_run = _node(repo, p, offline)
    elif any((repo / f).exists() for f in ("pyproject.toml", "setup.py", "requirements.txt")):
        p.ecosystem = "python"
        auto_install, auto_run = _python(repo, p, offline)
    if mcp is not None:
        p.mcp = mcp

    install = install if install is not None else auto_install
    run = run if run is not None else auto_run
    if install:
        p.phases.append({"name": "install", "cmd": install, "timeout": install_timeout})
    if run:
        p.phases.append({"name": "run", "cmd": run, "timeout": run_timeout, "mcp": p.mcp})
    return p
