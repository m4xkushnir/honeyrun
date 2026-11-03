"""Fake credentials planted in the sandbox.

Every run gets fresh random values, so a value seen leaving the sandbox can
only have come from the bait in this run.
"""
from __future__ import annotations

import base64
import json
import secrets
import string
from dataclasses import dataclass

ALNUM = string.ascii_letters + string.digits
UPPER = string.ascii_uppercase + string.digits


def _tok(n: int, alphabet: str = ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@dataclass
class Bait:
    label: str            # what a human would call it
    secret: str           # the value we look for in egress
    path: str | None      # relative to $HOME, or None for an env var
    env: str | None = None
    content: str = ""


def generate() -> list[Bait]:
    baits: list[Bait] = []

    key_body = _tok(70 * 5)
    ssh = "\n".join(key_body[i:i + 70] for i in range(0, len(key_body), 70))
    baits.append(Bait("SSH private key", key_body[:48], ".ssh/id_ed25519",
                      content=f"-----BEGIN OPENSSH PRIVATE KEY-----\n{ssh}\n-----END OPENSSH PRIVATE KEY-----\n"))

    aws_id, aws_secret = "AKIA" + _tok(16, UPPER), _tok(40)
    baits.append(Bait("AWS secret key", aws_secret, ".aws/credentials",
                      content=f"[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"))

    gho = "gho_" + _tok(36)
    baits.append(Bait("GitHub CLI token", gho, ".config/gh/hosts.yml",
                      content=f"github.com:\n    oauth_token: {gho}\n    user: dev\n    git_protocol: https\n"))

    ghp = "ghp_" + _tok(36)
    baits.append(Bait("git credential", ghp, ".git-credentials",
                      content=f"https://dev:{ghp}@github.com\n"))

    npm = "npm_" + _tok(36)
    baits.append(Bait("npm token", npm, ".npmrc",
                      content=f"//registry.npmjs.org/:_authToken={npm}\n"))

    docker_auth = base64.b64encode(f"dev:dckr_pat_{_tok(27)}".encode()).decode()
    baits.append(Bait("Docker registry auth", docker_auth, ".docker/config.json",
                      content=json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": docker_auth}}}, indent=2)))

    kube = _tok(64)
    baits.append(Bait("Kubernetes token", kube, ".kube/config", content=(
        "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: prod\n"
        f"users:\n- name: admin\n  user:\n    token: {kube}\ncontexts:\n- context:\n    cluster: prod\n    user: admin\n"
        "  name: prod\ncurrent-context: prod\n")))

    wallet = _tok(88, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    baits.append(Bait("Solana wallet", wallet, ".config/solana/id.json", content=json.dumps({"secret": wallet})))

    cursor_key = "sk-ant-api03-" + _tok(48)
    baits.append(Bait("Cursor MCP config", cursor_key, ".cursor/mcp.json", content=json.dumps({"mcpServers": {
        "internal-db": {"command": "npx", "args": ["-y", "pg-mcp"], "env": {"ANTHROPIC_API_KEY": cursor_key}}}}, indent=2)))

    claude_key = "sk-proj-" + _tok(48)
    baits.append(Bait("Claude Desktop config", claude_key, ".config/Claude/claude_desktop_config.json",
                      content=json.dumps({"mcpServers": {"search": {"command": "uvx", "args": ["search-mcp"],
                                                                     "env": {"OPENAI_API_KEY": claude_key}}}}, indent=2)))

    for label, var, value in (
        ("GITHUB_TOKEN env", "GITHUB_TOKEN", "ghp_" + _tok(36)),
        ("OPENAI_API_KEY env", "OPENAI_API_KEY", "sk-proj-" + _tok(48)),
        ("ANTHROPIC_API_KEY env", "ANTHROPIC_API_KEY", "sk-ant-api03-" + _tok(48)),
        ("AWS_SECRET_ACCESS_KEY env", "AWS_SECRET_ACCESS_KEY", _tok(40)),
    ):
        baits.append(Bait(label, value, None, env=var))
    return baits


def needles(secret: str) -> set[str]:
    """Encodings of `secret` that survive common exfiltration tricks."""
    raw = secret.encode()
    out = {secret, secret.lower(), raw.hex(), raw.hex().upper()}
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + raw).decode()
        # keep only the characters that depend on the secret alone
        core = enc[-(-8 * pad // 6):-4]
        if len(core) >= 16:
            out.add(core)
            out.add(core.replace("+", "-").replace("/", "_"))
    return {n for n in out if len(n) >= 16}


def files(baits: list[Bait]) -> dict[str, dict]:
    return {b.path: {"content": b.content, "mode": "600"} for b in baits if b.path}


def env(baits: list[Bait]) -> dict[str, str]:
    return {b.env: b.secret for b in baits if b.env}
