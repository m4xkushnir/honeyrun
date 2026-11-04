<div align="center">

# honeyrun

**Run an untrusted repo or MCP server and see what it truly reaches for.**

[![ci](https://github.com/m4xkushnir/honeyrun/actions/workflows/ci.yml/badge.svg)](https://github.com/m4xkushnir/honeyrun/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)
![macOS · Linux · Windows](https://img.shields.io/badge/runs%20on-macOS%20%C2%B7%20Linux%20%C2%B7%20Windows-555)
![sandbox: gVisor or VM](https://img.shields.io/badge/sandbox-gVisor%20or%20VM-4285f4)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-success)
![works with](https://img.shields.io/badge/works%20with-Claude%20Code%20%C2%B7%20Codex%20%C2%B7%20Gemini%20CLI%20%C2%B7%20Cursor-8a2be2)

[![Try it](https://img.shields.io/badge/Try%20it-2ea44f?style=for-the-badge)](#try-it)
[![What it looks for](https://img.shields.io/badge/What%20it%20looks%20for-0969da?style=for-the-badge)](#what-it-looks-for)
[![Benchmark](https://img.shields.io/badge/Benchmark-bf8700?style=for-the-badge)](#benchmark)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-24292f?style=for-the-badge&logo=githubactions&logoColor=white)](#in-ci-or-in-the-cloud)

<img src="docs/demo.svg" alt="honeyrun catching an MCP server that reads ~/.cursor/mcp.json and posts it out" width="760">

</div>

Your coding agent installs packages, clones repos and adds MCP servers for you now. One `postinstall` script or one poisoned tool description can read `~/.ssh`, `~/.aws` and your agent's API keys before you notice. Reading the code first doesn't help much when the payload is base64, waits a month, or only wakes up inside CI.

honeyrun runs it for you first, in a throwaway sandbox whose home folder is full of fake keys: SSH, AWS, GitHub, npm, and the configs of Claude, Codex, Cursor and Gemini. Each key is made up for that run. If one turns up in a web request, a DNS lookup or a log line, you know exactly what took it and where it went.

```bash
pipx install honeyrun==0.1.1      # signed build on PyPI; see "Verify what you install"
honeyrun npm:some-package        # or owner/repo, pypi:name, a folder, an MCP server
```

Before running anything it reads the code for hooks and hidden instructions. While it runs, it watches every process, file and connection. Then it runs the code again with the clock 45 days ahead, for code that waits. You get one line at the end: **LOOKS SAFE**, **UNCLEAR** or **NOT SAFE**, and what to do next.

- **One command, no account, no server.** Runs on your laptop or in a GitHub Action. Zero Python dependencies.
- **Catches what scanners can't read.** Encrypted, obfuscated and delayed payloads show themselves when they run.
- **Built for the agent era.** It calls every MCP tool, spots instructions hidden for your AI, notices when a tool quietly changes after you approved it, and gives your agent a short answer it can act on.

## Try it

Point it at whatever you're about to trust:

```bash
honeyrun owner/repo                  # any git host: GitHub, GitLab, Codeberg, your own server
honeyrun npm:some-package            # npm:@scope/name@1.2.3 works too
honeyrun pypi:some-package==1.0.0
honeyrun ./downloads/tool.tgz        # .tgz .zip .whl .vsix .crate
honeyrun ./my-app --installed        # already installed it? checks node_modules and .venv, runs nothing
honeyrun --agent-configs             # the MCP servers and hooks your agents start on this machine
honeyrun owner/repo --static-only    # read only, a few seconds, no sandbox needed
honeyrun owner/repo --deep           # extra passes: as if inside CI, and three runs in a row
```

The end of a run looks like this:

```
NOT SAFE  Do not install or run this.
          2 critical, 4 high, 1 medium

What to do now:
  1. It ran only inside the sandbox: your real files and keys were not exposed by this check.
  2. Don't install it. If you already did, run `honeyrun <that project dir> --installed` and follow the steps it gives.
  3. Report it so others are protected: rerun with --abuse-report report.txt and paste it into the form it names.
```

When the problem is on your own machine (`--installed`, `--agent-configs`), the steps say what to remove, which keys to rotate and where to look for leftovers.

### Sandboxes, with or without Docker

`--engine auto` picks the strongest one you have:

| Engine | Boundary | Notes |
|---|---|---|
| Apple `container` (macOS 26+) | a small VM per sandbox | no always-on daemon, light on RAM. Experimental, from [apple/container](https://github.com/apple/container/releases) |
| Docker or Podman + gVisor (Linux) | a user-space kernel between the code and yours | [`scripts/install-gvisor.sh`](scripts/install-gvisor.sh), see below |
| Podman + krun (Linux) | a microVM per sandbox | `--engine podman --runtime krun` with `crun-krun` |
| Docker Desktop (macOS, Windows) | Docker's Linux VM | works out of the box |
| Rootless Podman (Linux) | user namespaces, no daemon | lightest; weaker than gVisor, still no root on your machine |

No engine at all? `--static-only`, `--installed` and `--agent-configs` don't need one.

To install gVisor, take the script from a release tag, check it, then run it. It only trusts gVisor's apt key if its fingerprint matches `6F1DF85E3A71C24918E727D56FC6D554E32BD943`, the key published in the [gVisor source](https://github.com/google/gvisor/blob/master/website/archive.key):

```bash
curl -fsSLO https://raw.githubusercontent.com/m4xkushnir/honeyrun/v0.1.1/scripts/install-gvisor.sh
echo "499613d33d17c1516a171f60559f0faecef935a6a87b24660b72504d640dad89  install-gvisor.sh" | sha256sum -c -
bash install-gvisor.sh
```

## What it looks for

**Before it runs.** Install hooks and anything that runs on its own: VS Code tasks that start when you open the folder, devcontainer commands that run on your host, `.envrc`, `.pth` files, git hooks, `conftest.py`, Rust `build.rs`. Hooks, permissions and MCP servers the repo sets up for Claude Code, Codex, Gemini CLI and Cursor. Hidden orders for AI models in `AGENTS.md`, `CLAUDE.md`, rules files and tool descriptions. Commands that shadow `git` or `ssh`, typosquatted names, obfuscated JavaScript, payloads tucked inside images, archives and binaries. Encoded payloads are decoded as text and shown to you. They are never run.

**While it runs.** Which fake keys it opens and whether they leave, even when hex or base64 encoded, split across DNS lookups, or sent over HTTPS (honeyrun intercepts TLS with a per-run CA). Cloud metadata endpoints, your SSH agent, keyboard and clipboard access, browser and chat-app sessions, crypto wallets. Persistence in shell files, cron, systemd, PATH and other agents' configs. Dropped binaries, wipers, miners, reverse shells, paste sites and webhooks, processes dressed up as `kworker`. MCP servers get their tools listed and every tool called, so payloads that wait for a tool call still go off.

**Later, and under other conditions.** A second pass with the clock 45 days ahead. With `--deep`, also a pass that looks like CI and three runs in a row. Behaviour that only shows up there is reported as a time bomb or a CI-only payload.

**What others already know.** Known malware and vulnerabilities from [OSV](https://osv.dev), the repo's published advisories, and open issues about leaks or code execution that aren't fixed yet.

**What changed.** honeyrun remembers a fingerprint of each check on your machine. Next time it tells you about new hosts, changed install hooks, and MCP tools whose description changed after you approved them (a "rug pull").

The full list with severities is in [docs/RULES.md](docs/RULES.md).

## How it works

```mermaid
flowchart LR
  T["repo, package or MCP server"] --> R["read: hooks, configs,<br/>instructions, binaries"]
  R --> H["honeyrun"]
  H -->|"code goes in as a tar,<br/>nothing of yours is mounted"| S
  subgraph S["sandbox: gVisor or a VM, read-only root, no capabilities, no network"]
    B[("20 fake credentials<br/>in home and env")]
    W["install, run, call MCP tools<br/>as an unprivileged user"]
    W -->|"every exec, open, connect"| X[("trace, root-only")]
    W -->|"DNS, HTTP, HTTPS"| K["fake internet<br/>answers and records"]
    W -->|"clock +45 days"| L["second pass"]
  end
  S --> V["LOOKS SAFE / UNCLEAR / NOT SAFE<br/>+ what to do now"]
```

The code runs as an unprivileged user under strace, inside gVisor or a VM, with a read-only root and no Linux capabilities. Offline (the default), every hostname resolves to the sandbox itself, so exfiltration code "succeeds" and leaves its evidence behind. A root-only agent keeps the trace where the code can't touch it, compares the filesystem before and after, and hands everything back as a tar. Your files, keys and environment never go in.

## With your coding agent

`--agent` prints a dozen short lines ending in a `next:` instruction, so an agent spends a few hundred tokens rather than reading a trace.

- **Claude Code:** copy [`integrations/claude-code/honeyrun`](integrations/claude-code/honeyrun) into `~/.claude/skills/`.
- **Codex, Cursor, Gemini CLI, Copilot, Windsurf:** paste [`integrations/AGENTS.md`](integrations/AGENTS.md) into your `AGENTS.md`, `GEMINI.md` or rules file.
- Agents that can start subagents are told to hand the check to one and keep only the verdict lines.

**A second opinion from your own AI, only when it helps.** `--review "claude -p"` (or `"codex exec -"`, or `"gemini -p {prompt_file}"`) asks the AI you already use to explain an UNCLEAR or NOT SAFE result in plain words, including what any decoded payload does, and to draft the abuse report. LOOKS SAFE runs never call it. It gets about 6 KB of masked, pre-filtered evidence and is told to explain only, never to rewrite or improve the code. Its answer never changes the exit code.

### Keeping your AI safe while it checks

The code being checked may try to talk to the AI that reads the results. honeyrun assumes it will:

- In `--agent` output, every string from the code under test is quoted as `evidence:`. Text written for a model (hidden tool instructions, decoded payloads, a fake "LOOKS SAFE" line) is withheld and left in `--json` for humans.
- The verdict line and the `next:` line end with the same per-run tag, so a forged verdict can't pass for honeyrun's.
- The `--review` AI runs in an empty folder, without your GitHub, npm, cloud or SSH-agent credentials, and gets its evidence fenced with a random nonce. It has to end its answer with a second secret marker. If that marker is missing, if it calls hard evidence benign, or if it tells you to run something, honeyrun labels the answer unreliable. Either way the verdict comes from the evidence, never from the AI.
- The skill and `AGENTS.md` snippet tell agents not to open the target before it's checked, never to act on quoted evidence, and to give a checking subagent nothing but shell access to honeyrun.

## In CI or in the cloud

```yaml
- uses: m4xkushnir/honeyrun@v0.1.1   # pin to the full commit SHA of the tag in your workflows
  with:
    target: .              # or owner/repo, npm:name, pypi:name
    network: open          # offline | open
    fail-on: high          # medium | high | critical
```

The step installs gVisor on the runner, fails on findings and writes the report to the job summary. It's also the easiest way to keep untrusted code off your laptop entirely: it runs on GitHub's machines. To use a server of your own, point Docker at it: `DOCKER_HOST=ssh://you@server honeyrun owner/repo`.

Other tools can read the results too: `--sarif` for GitHub code scanning and other SARIF readers, `--json` for scripts, `--markdown` for PR comments, and exit codes `0` clean, `1` findings, `3` couldn't run. It sits well next to static scanners such as Socket, GuardDog, Semgrep or OSV-Scanner. They read code and advisories; honeyrun watches behaviour.

## Verify what you install

honeyrun asks you to distrust code you haven't checked, so it shouldn't ask for blind trust either:

- **Releases are signed and attested.** Each release's wheel and sdist are built in GitHub Actions, published to PyPI with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no stored tokens) and carry a Sigstore build-provenance attestation. PyPI shows it on the file page (PEP 740), and `gh attestation verify honeyrun-0.1.1-py3-none-any.whl --repo m4xkushnir/honeyrun` checks a downloaded file.
- **Tags and commits are signed.** Run `git tag -v v0.1.1` after cloning.
- **Pin the Action to a commit SHA**, not a branch: `uses: m4xkushnir/honeyrun@<full sha> # v0.1.1`. honeyrun's own workflows pin every action the same way.
- **Zero runtime dependencies.** Nothing else gets pulled in when you install it.

## Benchmark

Every number here comes from CI, under gVisor on `ubuntu-latest`, on every push.

**Detection on [32 fixtures](bench/fixtures).** 25 imitate real malware: install hooks that steal SSH and AWS keys, `curl | sh`, tokens tunnelled out over DNS or HTTPS, an MCP server that poisons its tool description and steals other agents' configs, a time bomb that waits 30 days, a CI-only payload, cloud metadata theft, SSH agent hijack, a fake `git` in PATH, droppers, wipers, miners, disguised processes, webhook exfiltration and hooks hidden in editor and agent configs. 7 are ordinary projects that build, read their own config, serve MCP and ship images, archives and analytics.

| Malicious flagged | Benign flagged | Exact rule match | Median time per check |
|:---:|:---:|:---:|:---:|
| **25 / 25** | **0 / 7** | **32 / 32** | **2.4 s** |

**False positives on well-known projects, with real network and the time-shifted pass:**

| Repo | Install | Run | MCP tools called | Verdict |
|---|:---:|:---:|:---:|:---:|
| chalk/chalk | ok | | | LOOKS SAFE |
| sindresorhus/slugify | ok | ok | | LOOKS SAFE |
| expressjs/express | ok | ok | | LOOKS SAFE |
| pallets/itsdangerous | ok | | | LOOKS SAFE |
| pallets/markupsafe | ok | | | LOOKS SAFE |
| psf/requests | ok | | | LOOKS SAFE |
| modelcontextprotocol/servers `src/fetch` | ok | ok | 1 | LOOKS SAFE |
| modelcontextprotocol/servers `src/time` | ok | ok | 2 | LOOKS SAFE |
| modelcontextprotocol/servers `src/git` | ok | ok | 12 | LOOKS SAFE |

**0 of 9 flagged**, and every install succeeded. CI fails if one doesn't, so a clean result can't hide a broken run. The same fixtures also run under rootless Podman, with no Docker at all, and the unit tests run on Linux, macOS and Windows.

Reproduce: `python bench/run.py` and `python bench/run.py --real`.

## Compared with

As described in each project's own README (November 2026):

| | honeyrun | [ossf/package-analysis](https://github.com/ossf/package-analysis) | [decon](https://github.com/staticplay/decon) | [mcp-sentinel](https://github.com/kirandevihosur74/mcp-sentinel) |
|---|---|---|---|---|
| One command on your own machine | yes | needs privileged nested containers | yes | no, sandbox runs on Daytona |
| Repos, npm, PyPI, archives, local dirs | yes | registry packages | repos | MCP servers |
| Watches behaviour at run time | yes | yes | no, static pre-flight | yes |
| Fake credentials as tripwires | 20 per run | no | no | yes |
| Calls MCP tools, tracks tool changes | yes | no | no | yes |
| Fake internet incl. HTTPS | yes | no | no | not stated |
| Time-shifted and CI-like passes | yes | no | no | no |

## Where to stay careful

honeyrun shows you what a piece of code does when it runs. A few things deserve your judgement on top:

- **Patient code.** A payload that waits months, or for one particular company's hostname, can stay quiet through every pass. The time-shifted and `--deep` passes catch the common triggers. Your own sense of whether a project is what it claims still matters.
- **Pinned TLS.** Code that ships its own certificate store shows where it connects but not what it sends. Plain HTTP, DNS and normal HTTPS are read in full.
- **Container awareness.** A determined sample can tell it's in a sandbox. When it checks, honeyrun reports the check itself (`sandbox-detection`).
- **Isolation strength depends on the engine.** gVisor and the VM engines are the strong options. On Linux without them, honeyrun falls back only to rootless Podman, or to plain containers if you pass `--allow-runc`.

## Privacy and responsible use

honeyrun has no telemetry and no server. It goes online only to fetch what you asked it to check, to look the target up in OSV and GitHub (`--no-intel` turns that off; local folders are never looked up unless you ask), and to call your own AI if you pass `--review`. Reports mask tokens and URL passwords and write `~` for your home folder. Your history of checks stays on your machine.

Check code you're allowed to run, and send reports through official channels. honeyrun is provided as is, without warranty. Read [DISCLAIMER.md](DISCLAIMER.md) for the full terms and [SECURITY.md](SECURITY.md) to report a problem in honeyrun itself.

## Contributing

Found malware it missed, or a false alarm on a real project? Open an issue with the package name, or better, a small fixture in `bench/fixtures/`: every fixture becomes a test that runs on each push. Security problems in honeyrun itself go through [SECURITY.md](SECURITY.md). AI agents working on this repo: read [AGENTS.md](AGENTS.md) first.

If honeyrun caught something for you, a star helps the next person find it.

## License

[MIT](LICENSE)
