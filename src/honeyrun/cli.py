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

from . import __version__, bait, detect, report, review, static
from .analyze import SEVERITIES, analyze
from .sandbox import SandboxError, ensure_image, pick_runtime, run_job

GIT_URL = re.compile(r"^(https?://|git@|ssh://)|^[\w.-]+/[\w.-]+$")


def fetch(target: str, ref: str | None) -> tuple[Path, str, Path | None]:
    path = Path(target).expanduser()
    if path.exists():
        return path.resolve(), str(path), None
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
        raise SandboxError(f"git clone failed: {res.stderr.strip()}")
    head = subprocess.run(["git", "-C", str(dest / "repo"), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    return dest / "repo", f"{url.removeprefix('https://')} @ {head}", dest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="honeyrun",
        description="Install and run an untrusted repo in a sandbox full of fake credentials, "
                    "then report what it opened, ran and tried to send.")
    ap.add_argument("target", help="GitHub URL, owner/repo, any git URL, or a local directory")
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
    ap.add_argument("--runtime", choices=("auto", "runsc", "runc"), default="auto")
    ap.add_argument("--allow-runc", action="store_true", help="allow plain runc on a Linux host without gVisor")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--markdown", metavar="FILE", help="write a Markdown summary (for PR comments)")
    ap.add_argument("--keep-trace", metavar="DIR", help="save raw strace, sinkhole and MCP logs here")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:], default="high",
                    help="exit 1 when a finding at or above this severity exists (default: high)")
    ap.add_argument("--static-only", action="store_true",
                    help="only read the repo (hooks, manifests, agent configs); run nothing, no Docker needed")
    ap.add_argument("--agent", action="store_true",
                    help="compact output for coding agents (Claude Code, Codex, Gemini CLI, Cursor...): few tokens")
    ap.add_argument("--review", metavar="CMD",
                    help="ask an AI CLI for a second opinion on WARN results only, e.g. \"claude -p\", "
                         "\"codex exec -\", \"gemini -p {prompt_file}\". Advisory: never changes the exit code")
    ap.add_argument("-v", "--verbose", action="store_true", help="also show info findings")
    ap.add_argument("--version", action="version", version=f"honeyrun {__version__}")
    args = ap.parse_args(argv)

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
        pre = static.scan(src)
        plan = detect.plan(src, args.network, args.install, args.run, args.install_timeout,
                           args.run_timeout, args.mcp)
        baits = bait.generate()
        if not args.static_only:
            runtime = pick_runtime(args.runtime, args.allow_runc)
            runtime_label = runtime.label
            job = {"network": args.network, "phases": plan.phases,
                   "files": bait.files(baits), "env": bait.env(baits)}
            image = ensure_image(quiet=args.agent)
            budget = sum(p["timeout"] for p in plan.phases) + 120
            trace = run_job(src, job, runtime, image, timeout=budget)
    except SandboxError as e:
        print(f"honeyrun: {e}", file=sys.stderr)
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

    ctx = {"target": label, "runtime": runtime_label, "network": args.network if trace else "not run",
           "baits": len(baits) if trace else 0, "mcp": plan.mcp and bool(trace)}
    note = None
    if args.review and report.verdict(result.findings) == "WARN":
        note = review.run(args.review, result, ctx)
    if args.agent:
        report.agent(result, ctx, note)
    else:
        report.terminal(result, ctx, show_info=args.verbose)
        if note:
            print("\nAI review (advisory, does not change the exit code):\n" + note)
    if args.json:
        Path(args.json).write_text(report.to_json(result, ctx, note))
    if args.markdown:
        Path(args.markdown).write_text(report.to_markdown(result, ctx))

    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
