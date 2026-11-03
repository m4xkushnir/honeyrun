"""honeyrun command line."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__, bait, detect, installed, report, review, static
from .analyze import SEVERITIES, Finding, analyze, scrub
from .sandbox import SandboxError, ensure_image, pick_runtime, run_job

GIT_URL = re.compile(r"^(https?://|git@|ssh://)|^[\w.-]+/[\w.-]+$")


SCHEME = re.compile(r"^[A-Za-z][\w+.-]*://")


def url_label(url: str, head: str = "") -> str:
    """A display name for a clone URL: no scheme, no user:password@, nothing secret-looking."""
    rest = SCHEME.sub("", url.strip())
    host, sep, tail = rest.partition("/")
    # userinfo is everything before the last "@" of the authority (https://u:p@h/x, git@h:x/y)
    host = host.rsplit("@", 1)[-1]
    rest = host + sep + tail
    return scrub(rest + (f" @ {head}" if head else ""))


def fetch(target: str, ref: str | None) -> tuple[Path, str, Path | None]:
    path = Path(target).expanduser()
    if path.exists():
        # Reports get shared: never put the user's home directory in them.
        return path.resolve(), scrub(str(path).replace(os.path.expanduser("~"), "~")), None
    if not GIT_URL.search(target):
        raise SandboxError(f"{target} is neither a directory nor a git URL")
    url = f"https://github.com/{target}" if re.match(r"^[\w.-]+/[\w.-]+$", target) else target
    dest = Path(tempfile.mkdtemp(prefix="honeyrun-src-"))
    # Cloning runs on the host, so nothing in the repo may execute here:
    # no hooks, no submodules, no local or ext:: transports, no credential prompts.
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "-c", "protocol.ext.allow=never", "-c", "credential.helper=", "-c", "core.fsmonitor=false",
           "-c", "transfer.fsckObjects=true", "clone", "--quiet", "--depth", "1", "--no-recurse-submodules"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, str(dest / "repo")]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        # git echoes the URL back on failure: never let its credentials through.
        raise SandboxError(f"git clone failed: {scrub(res.stderr.replace(url, url_label(url)))}")
    head = subprocess.run(["git", "-C", str(dest / "repo"), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    return dest / "repo", url_label(url, head), dest


def _guard(what: str, fn, *a) -> list[Finding]:
    """A scanner that crashes on an odd repo must not hide the verdict: say so, and mark the scan incomplete."""
    try:
        return list(fn(*a))
    except Exception as e:      # noqa: BLE001 - any failure, by design
        return [Finding("info", "internal-error", f"internal error while scanning: {type(e).__name__}", what),
                Finding("medium", "incomplete", f"the {what} scan failed, so part of the repo was not checked", what)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="honeyrun",
        description="Install and run an untrusted repo in a sandbox full of fake credentials, "
                    "then report what it opened, ran and tried to send.")
    ap.add_argument("target", nargs="?", help="GitHub URL, owner/repo, any git URL, or a local directory")
    ap.add_argument("--ref", help="branch or tag to clone")
    ap.add_argument("--subdir", help="run from this subdirectory of the repo (monorepos)")
    ap.add_argument("--network", choices=("offline", "open"), default="offline",
                    help="offline (default): no network, DNS and HTTP(S) answered by a local sinkhole that records "
                         "everything. open: real network, so dependencies install")
    ap.add_argument("--install", help="install command (default: detected from the repo, '' to skip)")
    ap.add_argument("--run", help="run command (default: detected from the repo, '' to skip)")
    ap.add_argument("--mcp", action=argparse.BooleanOptionalAction, default=None,
                    help="treat the run command as an MCP stdio server: list its tools and call each one")
    ap.add_argument("--install-timeout", type=int, default=600)
    ap.add_argument("--run-timeout", type=int, default=30)
    ap.add_argument("--engine", choices=("auto", "docker", "podman", "container"), default="auto",
                    help="sandbox engine. auto picks the strongest available: Apple container (a VM per sandbox), "
                         "then Docker or Podman with gVisor, then Docker Desktop's VM, then rootless Podman")
    ap.add_argument("--runtime", choices=("auto", "runsc", "krun", "runc"), default="auto")
    ap.add_argument("--no-later", action="store_true",
                    help="skip the extra pass with the clock 45 days ahead (catches time bombs)")
    ap.add_argument("--installed", action="store_true",
                    help="the target directory already has its dependencies installed: also check every package "
                         "in node_modules and every .pth in its virtualenvs (reads only, runs nothing)")
    ap.add_argument("--agent-configs", action="store_true",
                    help="check the MCP servers and hooks your coding agents start (Claude Code, Codex, Cursor, "
                         "Gemini CLI, Windsurf, VS Code). Local and read-only; env values are never printed")
    ap.add_argument("--allow-runc", action="store_true", help="allow plain runc on a Linux host without gVisor")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--markdown", metavar="FILE", help="write a Markdown summary (for PR comments)")
    ap.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 (GitHub code scanning and other tools)")
    ap.add_argument("--abuse-report", metavar="FILE",
                    help="on NOT SAFE, write a short report to paste into GitHub/npm/PyPI abuse forms")
    ap.add_argument("--keep-trace", metavar="DIR", help="save raw strace, sinkhole and MCP logs here")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:], default="high",
                    help="exit 1 when a finding at or above this severity exists (default: high)")
    ap.add_argument("--static-only", action="store_true",
                    help="only read the repo (hooks, manifests, agent configs); run nothing, no Docker needed")
    ap.add_argument("--agent", action="store_true",
                    help="compact output for coding agents (Claude Code, Codex, Gemini CLI, Cursor...): few tokens")
    ap.add_argument("--review", metavar="CMD",
                    help="ask your AI CLI to explain WARN and FAIL results (never PASS), e.g. \"claude -p\", "
                         "\"codex exec -\", \"gemini -p {prompt_file}\". It receives a short, masked summary; "
                         "advisory only, it never changes the exit code")
    ap.add_argument("-v", "--verbose", action="store_true", help="also show info findings")
    ap.add_argument("--version", action="version", version=f"honeyrun {__version__}")
    args = ap.parse_args(argv)
    if args.agent_configs and not args.target:
        return _agent_configs(args)
    if not args.target:
        ap.error("a target is required (or use --agent-configs)")

    cleanup = None
    trace: dict[str, bytes] = {}
    runtime_label = "none (static scan only)"
    try:
        src, label, cleanup = fetch(args.target, args.ref)
        if args.subdir:
            sub = (src / args.subdir).resolve()
            if not sub.is_dir() or (sub != src.resolve() and src.resolve() not in sub.parents):
                raise SandboxError(f"--subdir {args.subdir} is not a directory inside the repo")
            src, label = sub, f"{label} ({args.subdir})"
        pre = _guard("static", static.scan, src)
        if args.installed:
            pre += _guard("installed", installed.scan_dependencies, src)
        if args.agent_configs:
            pre += _guard("agent-configs", installed.scan_agent_configs)
        plan = detect.plan(src, args.network, args.install, args.run, args.install_timeout,
                           args.run_timeout, args.mcp, later=not args.no_later)
        baits = bait.generate()
        if not args.static_only and not args.installed:
            runtime = pick_runtime(args.runtime, args.allow_runc, args.engine)
            runtime_label = runtime.label
            job = {"network": args.network, "phases": plan.phases,
                   "files": bait.files(baits), "env": bait.env(baits)}
            image = ensure_image(quiet=args.agent, engine=runtime.engine)
            budget = sum(p["timeout"] for p in plan.phases) + 120
            trace = run_job(src, job, runtime, image, timeout=budget)
    except SandboxError as e:
        print(f"honeyrun: {scrub(e)}", file=sys.stderr)
        return 3
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)

    if args.keep_trace and trace:
        out = Path(args.keep_trace)
        out.mkdir(parents=True, exist_ok=True)
        for name, data in trace.items():
            (out / name.lstrip("_")).write_bytes(data)

    result = analyze(trace, baits, args.network)
    result.findings = sorted(result.findings + pre,
                             key=lambda f: (-SEVERITIES.index(f.severity), f.rule, f.title))

    manifest = next((m for m in ("package.json", "pyproject.toml", "setup.py") if (Path(src) / m).is_file()), "") \
        if not cleanup else ""
    ctx = {"target": label, "runtime": runtime_label, "network": args.network if trace else "not run",
           "baits": len(baits) if trace else 0, "mcp": plan.mcp and bool(trace), "manifest": manifest}
    return _finish(args, result, ctx)


def _agent_configs(args) -> int:
    from .analyze import Analysis
    result = Analysis(installed.scan_agent_configs(), [], 0, 0, [], [])
    result.findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.rule, f.title))
    args.verbose = True
    ctx = {"target": "agent configs on this machine", "runtime": "none (read-only check)", "network": "not run",
           "baits": 0, "mcp": False, "manifest": "",
           "advice": {"FAIL": "Remove or replace the flagged entries in your agent configs.",
                      "WARN": "Check the flagged entries; each one runs when your agent starts.",
                      "PASS": "Nothing risky in what your agents start. Check unfamiliar servers with honeyrun <package>."}}
    return _finish(args, result, ctx)


def _finish(args, result, ctx) -> int:
    v = report.verdict(result.findings)
    note = None
    if args.review and v in ("WARN", "FAIL"):
        note = review.run(args.review, result, ctx)
    if args.agent:
        report.agent(result, ctx, note)
    else:
        report.terminal(result, ctx, show_info=args.verbose)
        if note:
            print("\nAI review (advisory, does not change the exit code):\n" + report.note_text(note))
    if args.json:
        Path(args.json).write_text(report.to_json(result, ctx, report.note_text(note) if note else None))
    if args.markdown:
        Path(args.markdown).write_text(report.to_markdown(result, ctx))
    if args.sarif:
        Path(args.sarif).write_text(report.to_sarif(result, ctx, __version__))
    text = report.abuse(result, ctx, __version__) if v == "FAIL" else ""
    if args.abuse_report and text:
        Path(args.abuse_report).write_text(text)
    elif text and not args.agent and not args.json:
        print("\nTo report it, run again with --abuse-report FILE for a ready-to-paste report.")

    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
