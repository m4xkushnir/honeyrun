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
LATER_CLOCK = "+45d"   # far enough for "activate after N days" checks, near enough to look plausible
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")


@dataclass
class Plan:
    ecosystem: str = "unknown"
    mcp: bool = False
    phases: list[dict] = field(default_factory=list)
    lifecycle: dict[str, str] = field(default_factory=dict)


def _strs(v) -> dict[str, str]:
    return {k: x for k, x in v.items() if isinstance(k, str) and isinstance(x, str)} if isinstance(v, dict) else {}


def _exists(repo: Path, rel: object) -> bool:
    try:
        return isinstance(rel, str) and bool(rel) and (repo / rel).exists()
    except (OSError, ValueError):
        return False


def _node(repo: Path, plan: Plan, offline: bool) -> tuple[str | None, str | None]:
    try:
        pkg = json.loads((repo / "package.json").read_text())
    except (OSError, ValueError):
        pkg = {}
    if not isinstance(pkg, dict):
        pkg = {}
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        if isinstance(pkg.get(key), dict):
            deps |= {k for k in pkg[key] if isinstance(k, str)}
    plan.mcp = bool(deps & MCP_NODE_DEPS)
    scripts = _strs(pkg.get("scripts"))
    plan.lifecycle = {k: scripts[k] for k in LIFECYCLE if k in scripts}

    install = "npm install --no-audit --no-fund"
    bin_ = pkg.get("bin")
    if isinstance(bin_, dict):
        bin_path = next((v for v in bin_.values() if isinstance(v, str) and v), None)
    else:
        bin_path = bin_ if isinstance(bin_, str) and bin_ else None
    main = pkg.get("main")
    run = None
    if plan.mcp and bin_path:
        run = f"node {shlex.quote(bin_path)}"
    elif "start" in scripts:
        run = "npm start --silent"
    elif _exists(repo, main):
        run = f"node {shlex.quote(main)}"
    elif bin_path:
        run = f"node {shlex.quote(bin_path)}"
    elif (repo / "index.js").exists():
        run = "node index.js"
    return install, run


def _python(repo: Path, plan: Plan, offline: bool) -> tuple[str | None, str | None]:
    deps: list[str] = []
    scripts: list[str] = []
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
            project = data.get("project") if isinstance(data, dict) else None
            project = project if isinstance(project, dict) else {}
            if isinstance(project.get("dependencies"), list):
                deps += [d for d in project["dependencies"] if isinstance(d, str)]
            if isinstance(project.get("scripts"), dict):
                scripts = [k for k in project["scripts"] if isinstance(k, str) and k]
        except (OSError, ValueError):
            pass
    req = repo / "requirements.txt"
    if req.exists():
        try:
            deps += req.read_text(errors="replace").splitlines()
        except OSError:
            pass
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
        run = shlex.quote(scripts[0])
    else:
        for name in ("server.py", "main.py", "app.py", "__main__.py"):
            if (repo / name).exists():
                run = f"python3 {name}"
                break
    return install, run


def plan(repo: Path, network: str, install: str | None, run: str | None,
         install_timeout: int, run_timeout: int, mcp: bool | None = None, later: bool = True) -> Plan:
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
    if later and p.phases:
        last = p.phases[-1]
        hooks = bool(p.lifecycle) or (repo / "setup.py").exists() or (install is not None and install != auto_install)
        if install and run and hooks:
            # An install-time bomb must be replayed too, not only the run phase.
            p.phases.append({**p.phases[0], "name": "later-install", "clock": LATER_CLOCK,
                             "timeout": min(install_timeout, 180)})
        p.phases.append({**last, "name": "later", "clock": LATER_CLOCK,
                         "timeout": min(last["timeout"], run_timeout)})
    return p
