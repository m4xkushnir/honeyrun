"""Run every fixture in bench/fixtures through honeyrun and compare with expected.json.

    python bench/run.py [--runtime runsc] [--out bench/out]

Writes bench/out/results.json and bench/out/RESULTS.md. Exits 1 if any fixture misses.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIX = ROOT / "fixtures"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="auto")
    ap.add_argument("--out", default=str(ROOT / "out"))
    ap.add_argument("--only", help="comma-separated substrings of fixture names")
    ap.add_argument("--engine", default="auto")
    ap.add_argument("--real", action="store_true",
                    help="run the well-known repos in bench/real-repos.txt with network on; all should PASS")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.real:
        return real(args, out)
    rows, misses = [], 0
    for fx in sorted(FIX.iterdir()):
        if not fx.is_dir() or (args.only and not any(o in fx.name for o in args.only.split(","))):
            continue
        exp = json.loads((fx / "expected.json").read_text())
        cmd = [sys.executable, "-m", "honeyrun", str(fx), "--runtime", args.runtime, "--engine", args.engine,
               "--json", str(out / f"{fx.name}.json"), "--run-timeout", "20"]
        for key in ("install", "run"):
            if key in exp:
                cmd += [f"--{key}", exp[key]]
        if exp.get("deep"):
            cmd.append("--deep")
        cmd += ["--no-history", "--no-intel"]   # each fixture run must stand on its own
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        secs = time.time() - t0
        try:
            rep = json.loads((out / f"{fx.name}.json").read_text())
        except (OSError, ValueError):
            print(proc.stdout, proc.stderr, file=sys.stderr)
            rep = {"verdict": "ERROR", "findings": [], "runtime": "?"}
        got = {f["rule"] for f in rep["findings"] if f["severity"] != "info"}
        missing = sorted(set(exp["rules"]) - got)
        ok = rep["verdict"] == exp["verdict"] and not missing
        misses += not ok
        rows.append({"fixture": fx.name, "malicious": fx.name.startswith("mal-"), "expected": exp["verdict"],
                     "verdict": rep["verdict"], "rules": sorted(got), "missing": missing, "ok": ok,
                     "seconds": round(secs, 1), "runtime": rep.get("runtime")})
        print(f"{'ok ' if ok else 'MISS'} {fx.name:<28} {rep['verdict']:<5} {secs:5.1f}s  {', '.join(sorted(got))}"
              + (f"  missing: {missing}" if missing else ""), flush=True)

    mal = [r for r in rows if r["malicious"]]
    ben = [r for r in rows if not r["malicious"]]
    caught = sum(r["verdict"] != "PASS" for r in mal)
    fp = sum(r["verdict"] != "PASS" for r in ben)
    secs = sorted(r["seconds"] for r in rows)
    summary = {
        "runtime": rows[0]["runtime"] if rows else None,
        "malicious_flagged": f"{caught}/{len(mal)}", "benign_flagged": f"{fp}/{len(ben)}",
        "exact_match": f"{sum(r['ok'] for r in rows)}/{len(rows)}",
        "median_seconds": secs[len(secs) // 2] if secs else None,
    }
    (out / "results.json").write_text(json.dumps({"summary": summary, "fixtures": rows}, indent=2))
    md = [f"Runtime: {summary['runtime']}", "",
          "| Fixture | Expected | Got | Rules fired | Time |", "|---|---|---|---|---|"]
    md += [f"| `{r['fixture']}` | {r['expected']} | {r['verdict']} | {', '.join(r['rules']) or '-'} | {r['seconds']}s |"
           for r in rows]
    md += ["", f"Malicious flagged: **{summary['malicious_flagged']}**, benign flagged: **{summary['benign_flagged']}**, "
               f"exact rule match: **{summary['exact_match']}**, median wall time: **{summary['median_seconds']}s**"]
    (out / "RESULTS.md").write_text("\n".join(md) + "\n")
    print(json.dumps(summary))
    return 1 if misses else 0


def real(args, out: Path) -> int:
    rows = []
    for line in (ROOT / "real-repos.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        repo, _, sub = line.partition(" ")
        name = (repo + "_" + sub).strip("_").replace("/", "_")
        cmd = [sys.executable, "-m", "honeyrun", repo, "--network", "open", "--runtime", args.runtime, "--no-history", "--no-intel",
               "--json", str(out / f"real-{name}.json"), "--run-timeout", "20", "-v"]
        if sub:
            cmd += ["--subdir", sub]
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        print(proc.stdout, flush=True)
        try:
            rep = json.loads((out / f"real-{name}.json").read_text())
        except (OSError, ValueError):
            print(proc.stderr, file=sys.stderr)
            rep = {"verdict": "ERROR", "findings": [], "phases": [], "mcp_tools": []}
        rows.append({"repo": f"{repo} {sub}".strip(), "verdict": rep["verdict"],
                     "findings": [f"{f['severity']}: {f['title']}" for f in rep["findings"] if f["severity"] != "info"],
                     "phases": {p["name"]: ("timeout" if p["timed_out"] else p["exit"]) for p in rep["phases"]},
                     "mcp_tools": rep.get("mcp_tools", []), "seconds": round(time.time() - t0, 1)})
    flagged = sum(r["verdict"] != "PASS" for r in rows)
    md = ["| Repo | Verdict | Phases (exit) | MCP tools called | Time |", "|---|---|---|---|---|"]
    md += [f"| `{r['repo']}` | {r['verdict']} | {', '.join(f'{k} {v}' for k, v in r['phases'].items())} "
           f"| {len(r['mcp_tools']) or '-'} | {r['seconds']}s |" for r in rows]
    md += ["", f"Flagged: **{flagged}/{len(rows)}**"]
    (out / "REAL.md").write_text("\n".join(md) + "\n")
    (out / "real.json").write_text(json.dumps(rows, indent=2))
    print("\n".join(md))
    broken = [r["repo"] for r in rows if r["verdict"] == "ERROR" or r["phases"].get("install", 0) != 0]
    if broken:
        print(f"install failed or sandbox error: {broken}", file=sys.stderr)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
