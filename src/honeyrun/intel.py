"""What the world already knows about the target: OSV advisories and the repo's open security reports.

- OSV.dev: known vulnerabilities, and MAL- entries from the OpenSSF malicious-packages
  feed (a package already confirmed as malware).
- GitHub: published security advisories for the repo, open issues that report a leak,
  a backdoor or code execution, and open pull requests that fix one but are not merged yet.

Privacy: these lookups tell OSV and GitHub which package or repo you are checking. They run
by default only for targets that are already public (git URLs, npm:, pypi:); for a local
directory they need --intel. --no-intel turns them off. Failures never block a check.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request

from .analyze import Finding

UA = {"User-Agent": "honeyrun (+https://github.com/m4xkushnir/honeyrun)", "Accept": "application/vnd.github+json"}
PERSONAL = (r"\bleak|expos|token|credential|secret|password|private key|RCE\b|remote code execution|"
            r"code injection|command injection|backdoor|malware|exfiltrat|arbitrary file|path traversal")
SECURITY_WORDS = ("security", "vulnerability", "CVE", "leak", "leaks", "exposes", "token", "credentials",
                  "secret", "RCE", "remote code execution", "injection", "malware", "backdoor", "exfiltrat")


def _request(url: str, body: dict | None = None, timeout: int = 8, github: bool = False):
    headers = dict(UA)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if github and token:
        headers["Authorization"] = f"Bearer {token}"   # optional, only raises the rate limit
    data = json.dumps(body).encode() if body is not None else None
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(4 * 1024 * 1024))


def osv(ecosystem: str, name: str, version: str = "") -> list[Finding]:
    body = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    try:
        vulns = (_request("https://api.osv.dev/v1/query", body) or {}).get("vulns") or []
    except (OSError, ValueError):
        return [Finding("info", "intel", f"could not reach OSV for {name}", "", "intel")]
    out: list[Finding] = []
    malicious = [v for v in vulns if str(v.get("id", "")).startswith("MAL-")
                 or re.search(r"\bmalicious\b|\bmalware\b|embedded malicious code", str(v.get("summary", "")), re.I)]
    for v in malicious[:3]:
        out.append(Finding("critical", "known-malware", f"{name} is listed as malicious ({v.get('id')})",
                           str(v.get("summary") or v.get("details") or "")[:160], "intel"))
    others = [v for v in vulns if v not in malicious]
    if others and version:
        ids = ", ".join(str(v.get("id")) for v in others[:5])
        out.append(Finding("medium", "known-vulnerability",
                           f"{name} {version} has {len(others)} known vulnerabilit{'y' if len(others) == 1 else 'ies'}",
                           ids, "intel"))
    return out


def github(owner: str, repo: str) -> list[Finding]:
    out: list[Finding] = []
    base = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    try:
        advisories = _request(f"{base}/security-advisories?state=published&per_page=20", github=True) or []
        for a in advisories[:3]:
            sev = str(a.get("severity") or "").lower()
            out.append(Finding("high" if sev in ("critical", "high") else "medium", "repo-advisory",
                               f"published advisory {a.get('ghsa_id')}: {str(a.get('summary'))[:100]}",
                               f"severity {sev or 'unknown'}", "intel"))
    except (OSError, ValueError):
        pass
    words = " OR ".join(f'"{w}"' if " " in w else w for w in SECURITY_WORDS)
    for kind, label in (("issue", "open security reports"), ("pr", "unmerged security fixes")):
        q = f"repo:{owner}/{repo} is:{kind} is:open in:title {words}"
        try:
            res = _request("https://api.github.com/search/issues?per_page=5&q=" + urllib.parse.quote(q), github=True) or {}
        except (OSError, ValueError):
            continue
        items = [i for i in res.get("items") or [] if re.search("|".join(SECURITY_WORDS), str(i.get("title")), re.I)]
        if items:
            titles = "; ".join(f"#{i.get('number')} {str(i.get('title'))[:70]}" for i in items[:3])
            # Big projects always have open issues that say "security"; only the ones that could touch
            # the user's data or machine are worth a warning.
            touches_user = any(re.search(PERSONAL, str(i.get("title")), re.I) for i in items)
            sev = "medium" if kind == "issue" and touches_user else "info"
            out.append(Finding(sev, "open-security-reports",
                               f"{res.get('total_count', len(items))} {label} not resolved yet", titles, "intel"))
    return out


def github_repo(label: str) -> tuple[str, str] | None:
    m = re.match(r"^(?:https?://)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:\s|$|/)", label)
    return (m.group(1), m.group(2)) if m else None
