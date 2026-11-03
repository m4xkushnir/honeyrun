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

from . import __version__, bait, detect, report
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
    ap.add_argument("-v", "--verbose", action="store_true", help="also show info findings")
    ap.add_argument("--version", action="version", version=f"honeyrun {__version__}")
    args = ap.parse_args(argv)

    cleanup = None
    try:
        runtime = pick_runtime(args.runtime, args.allow_runc)
        src, label, cleanup = fetch(args.target, args.ref)
        if args.subdir:
            sub = (src / args.subdir).resolve()
            if not sub.is_dir() or src.resolve() not in sub.parents:
                raise SandboxError(f"--subdir {args.subdir} is not a directory inside the repo")
            src, label = sub, f"{label} ({args.subdir})"
        plan = detect.plan(src, args.network, args.install, args.run, args.install_timeout,
                           args.run_timeout, args.mcp)
        baits = bait.generate()
        job = {"network": args.network, "phases": plan.phases,
               "files": bait.files(baits), "env": bait.env(baits)}
        image = ensure_image()
        budget = sum(p["timeout"] for p in plan.phases) + 120
        trace = run_job(src, job, runtime, image, timeout=budget)
    except SandboxError as e:
        print(f"honeyrun: {e}", file=sys.stderr)
        return 3
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)

    if args.keep_trace:
        out = Path(args.keep_trace)
        out.mkdir(parents=True, exist_ok=True)
        for name, data in trace.items():
            (out / name.lstrip("_")).write_bytes(data)

    result = analyze(trace, baits, args.network)
    if plan.lifecycle:
        from .analyze import Finding
        for hook, cmd in plan.lifecycle.items():
            result.findings.append(Finding("info", "lifecycle-script", f"declares {hook}: {cmd[:80]}", phase="install"))

    ctx = {"target": label, "runtime": runtime.label, "network": args.network,
           "baits": len(baits), "mcp": plan.mcp}
    report.terminal(result, ctx, show_info=args.verbose)
    if args.json:
        Path(args.json).write_text(report.to_json(result, ctx))
    if args.markdown:
        Path(args.markdown).write_text(report.to_markdown(result, ctx))

    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
