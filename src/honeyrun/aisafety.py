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

# Secrets the reviewer CLI never needs. Its own provider key and config stay, everything else goes.
DROP_ENV = re.compile(r"^(GITHUB_TOKEN|GH_TOKEN|GH_ENTERPRISE_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|"
                      r"PYPI_TOKEN|TWINE_PASSWORD|TWINE_USERNAME|UV_PUBLISH_TOKEN|CARGO_REGISTRY_TOKEN|"
                      r"DOCKER_PASSWORD|DOCKER_AUTH_CONFIG|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|SSH_AUTH_SOCK|GPG_AGENT_INFO|"
                      r"KUBECONFIG|VAULT_TOKEN|DIGITALOCEAN_TOKEN|CLOUDFLARE_API_TOKEN|SLACK_\w+|DISCORD_\w+|"
                      r"\w*_(PASSWORD|PASSWD|SECRET|PRIVATE_KEY)|DATABASE_URL|\w*_DSN)$")
# Provider credentials the reviewer may legitimately need for its own API calls.
KEEP_ENV = re.compile(r"^(ANTHROPIC_\w+|CLAUDE_\w+|OPENAI_\w+|CODEX_\w+|GEMINI_\w+|GOOGLE_(API_KEY|CLOUD_PROJECT|"
                      r"GENAI_\w+|APPLICATION_CREDENTIALS)|AZURE_OPENAI_\w+|VERTEX_\w+)$")
DANGEROUS_ADVICE = re.compile(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh|\brm\s+-rf\b|\bchmod\s+\+x\b|\bsudo\b|"
                              r"\bnpm\s+(i|install)\b|\bpip\s+install\b|powershell|iex\b|Invoke-Expression", re.I)


def aimed_at_ai(text: str) -> bool:
    return any(rx.search(text) for rx in AIMED_AT_AI)


def for_agent(rule: str, text: str, limit: int = 100) -> str:
    """One untrusted string, made safe to show a coding agent."""
    if not text:
        return ""
    if rule in WITHHELD_RULES or aimed_at_ai(text):
        return "[withheld: text written for AI models; see --json]"
    flat = scrub(text).replace('"', "'")
    return f'"{flat[:limit]}"'


def reviewer_env(env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if env is None else env)
    return {k: v for k, v in env.items() if KEEP_ENV.match(k) or not DROP_ENV.match(k)}


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
