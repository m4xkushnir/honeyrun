"""Keep the AI that reads honeyrun's results from being steered by the code it is checking.

Two readers are exposed to text written by the code under test:

1. A coding agent reading `--agent` output. Every untrusted string it sees is quoted, kept
   on one line, and withheld entirely when it is phrased for a model (an injected tool
   description, a decoded payload, a fake "honeyrun PASS" line). The verdict and `next:`
   lines carry a per-run tag, so a forged line inside a quote can't pass for honeyrun's own.

2. The `--review` AI. It runs in an empty temporary folder, without the user's registry,
   cloud or git tokens and without the SSH agent, gets its evidence fenced with a per-run
   nonce, and must end with a second nonce. If that end marker is missing, or the answer
   calls clearly malicious code benign, or it tells the user to run commands, the answer is
   flagged as possibly hijacked and the deterministic verdict stands.

None of this makes an AI immune to prompt injection. It keeps the blast radius small: the
reviewer never decides the verdict, holds no extra secrets, and can't touch the project.
"""
from __future__ import annotations

import os
import re
import unicodedata

from .analyze import STRONG_INJECTION, scrub

# Text that only makes sense when addressed to a model, or that imitates honeyrun's own output.
AIMED_AT_AI = [*STRONG_INJECTION, *(re.compile(p, re.I) for p in (
    r"\b(you are|act as|pretend to be) (now |an? )?(ai|assistant|agent|model|claude|chatgpt|gpt|codex|gemini)\b",
    r"\b(system|developer) (prompt|message|instructions?)\b",
    r"\bas an ai\b",
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|above|previous|prior|guidelines)\b",
    r"\b(run|execute|paste|type) (this|the following|these) (command|commands|code|script)\b",
    r"\bhoneyrun\s+(PASS|WARN|FAIL)\b|\b(LOOKS SAFE|NOT SAFE|LIKELY-BENIGN|LIKELY-MALICIOUS)\b",
    r"^\s*next\s*:|\bnext:\s",
    r"</?\s*evidence",
    r"\b(tell|say to|inform) the user\b",
))]
# Rules whose detail is, by nature, words written for a model or decoded attacker code.
WITHHELD_RULES = {"mcp-tool-poisoning", "mcp-result-injection", "agent-instructions", "decoded-payload",
                  "mcp-hidden-text", "image-payload"}

# The reviewer gets an allowlist: whatever else sits in the user's environment (cloud, deploy and
# payment keys under names nobody could list) stays out. Provider keys it needs for its own API calls stay.
BASE_ENV = re.compile(r"^(PATH|HOME|USER|LOGNAME|SHELL|LANG|LC_\w+|TERM|TMPDIR|TEMP|TMP|XDG_\w+|SYSTEMROOT|APPDATA|"
                      r"LOCALAPPDATA|USERPROFILE|COMSPEC|PATHEXT|(?i:https?_proxy|no_proxy)|SSL_CERT_FILE|SSL_CERT_DIR|"
                      r"REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS)$")
KEEP_ENV = re.compile(r"^(ANTHROPIC_\w+|CLAUDE_\w+|OPENAI_\w+|CODEX_\w+|GEMINI_\w+|GOOGLE_(API_KEY|CLOUD_PROJECT|"
                      r"GENAI_\w+)|AZURE_OPENAI_\w+|VERTEX_\w+)$")
DANGEROUS_ADVICE = re.compile(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh|\brm\s+-rf\b|\bchmod\s+\+x\b|\bsudo\b|"
                              r"\bnpm\s+(i|install)\b|\bpip\s+install\b|powershell|iex\b|Invoke-Expression", re.I)


# Characters that are invisible or reorder text: zero-width, bidi controls, tags, BOM, soft hyphen.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e"
                        "\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\U000e0000-\U000e0fff]")


def _normalize(text: str) -> str:
    """NFKC folds fullwidth letters; invisible characters can't split a keyword any more."""
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", str(text)))


def aimed_at_ai(text: str) -> bool:
    t = _normalize(text)
    spaced = re.sub(r"[\W_]+", " ", t)   # "i.g.n.o.r.e", "ignore_previous" and the like
    return any(rx.search(v) for rx in AIMED_AT_AI for v in (t, spaced))


def for_agent(rule: str, text: str, limit: int = 100) -> str:
    """One untrusted string, made safe to show a coding agent."""
    if not text:
        return ""
    t = _normalize(text)
    if rule in WITHHELD_RULES or aimed_at_ai(t):
        return "[withheld: text written for AI models; see --json]"
    flat = scrub(t).replace('"', "'")
    return f'"{flat[:limit]}"'


def reviewer_env(env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if env is None else env)
    keep = {k: v for k, v in env.items() if BASE_ENV.match(k) or KEEP_ENV.match(k)}
    # Bedrock and Vertex reviewers authenticate with the cloud's own credentials: only then do they stay.
    if env.get("CLAUDE_CODE_USE_BEDROCK"):
        keep.update({k: v for k, v in env.items() if k.startswith("AWS_")})
    if env.get("CLAUDE_CODE_USE_VERTEX") and "GOOGLE_APPLICATION_CREDENTIALS" in env:
        keep["GOOGLE_APPLICATION_CREDENTIALS"] = env["GOOGLE_APPLICATION_CREDENTIALS"]
    return keep


REVIEW_VERDICTS = ("LIKELY-BENIGN", "SUSPICIOUS", "LIKELY-MALICIOUS")


def review_for_agent(note: str, limit: int = 300) -> str:
    """The reviewer's note: its verdict token from an allowlist, the rest quoted and filtered.

    The token itself trips the "imitates honeyrun output" filter, so it is taken out first.
    """
    lines = [l for l in str(note).splitlines() if l.strip()]
    token = ""
    if lines:
        m = re.match(r"\s*(LIKELY-BENIGN|SUSPICIOUS|LIKELY-MALICIOUS)\b[\s:.-]*", lines[0])
        if m:
            token, lines[0] = m.group(1), lines[0][m.end():]
    rest = for_agent("ai-review", " ".join(l.strip() for l in lines), limit)
    return f"{token} {rest}".strip()


def check_review(output: str, end_marker: str, deterministic_verdict: str) -> list[str]:
    """Reasons to distrust a reviewer's answer. Empty means nothing looked off."""
    problems = []
    lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
    if not lines or lines[-1] != end_marker:
        problems.append("it did not end with the marker it was given, so it may have followed instructions "
                        "hidden in the code under test")
    first = lines[0].upper() if lines else ""
    if deterministic_verdict == "FAIL" and "LIKELY-BENIGN" in first:
        problems.append("it calls the code benign although honeyrun saw hard evidence against it")
    if DANGEROUS_ADVICE.search(output):
        problems.append("it tells you to run or install something")
    return problems


def strip_marker(output: str, end_marker: str) -> str:
    lines = output.rstrip().splitlines()
    if lines and lines[-1].strip() == end_marker:
        lines = lines[:-1]
    return "\n".join(lines)
