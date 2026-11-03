# What honeyrun reports

Every finding has a rule id, a severity and a short piece of evidence. Severity decides the verdict: any `critical` or `high` gives NOT SAFE, any `medium` gives UNCLEAR, and `info` never changes the verdict.

## Before anything runs (reading files)

| Rule | Severity | Fires when |
|---|---|---|
| `install-hook` | info to high | `preinstall`/`postinstall`/`prepare`, `setup.py`, an in-tree build backend. Graded by what the command does: plain build is info, `node -e`/URLs are medium, fetch-and-run or decoding is high |
| `auto-exec` | high | code that runs without anyone asking: VS Code `folderOpen` tasks, devcontainer `initializeCommand` (runs on the host), `.envrc`, `.pth` and `sitecustomize.py` |
| `git-hook` | info to high | Husky or `.githooks` scripts |
| `dev-autorun` | medium, high | `conftest.py`, `noxfile.py`, `tasks.py`, Makefile default target, Rust `build.rs`, `//go:generate`, Gradle/Maven wrappers that download or fetch-and-run |
| `pkg-config` | info to high | repo `.npmrc` (`script-shell`, other registries), `.yarnrc.yml` `yarnPath`/plugins outside the usual place, `.pnpmfile.cjs`, pip indexes and `--trusted-host` |
| `bin-shadow` | high | a package installs a command named `git`, `ssh`, `sudo`, `claude`, `codex` and the like |
| `dep-source`, `dep-confusion` | info, medium | dependencies from plain http, IPs, git or tarball URLs; suspiciously high versions on internal-looking names |
| `typosquat` | medium | a name one or two typos away from a popular package |
| `agent-hook`, `agent-config` | medium, high | Claude Code, Codex, Gemini CLI and Cursor hooks in the repo, `Bash(*)` pre-approval, auto-approved project MCP servers |
| `project-mcp`, `plugin-manifest` | info to high | MCP servers the repo registers for your agent, Claude Code plugin and MCP manifests |
| `agent-instructions` | medium, high | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, Copilot instructions, skills, or tool descriptions in source that give the model hidden or injected orders, or hide text in invisible Unicode |
| `ci-untrusted-checkout` | medium | a workflow that runs pull-request code with the repo's secrets (`pull_request_target` + head checkout) |
| `symlink-escape` | medium, high | a link inside the repo that points at `~/.ssh`, `/etc` or elsewhere outside it |
| `delayed-activation` | info, medium | a date check or a long timer next to network or exec code in an install script |
| `environment-gate` | medium | an install script that checks CI, hostname or user before making a network call |
| `obfuscated-js`, `decoded-payload`, `encoded-blob` | info to medium | obfuscator output, `eval(Buffer.from(...))` style payloads (shown decoded, never run), large encoded blobs |
| `compiled-python`, `compiled-hook` | medium, high | `.pyc` without source; compiled files run by an install hook |
| `binary-strings` | info to high | URLs, IPs, shell commands or credential paths inside shipped binaries |
| `packed-data` | info, medium | encrypted or packed data. It shows itself only when the code decrypts it, which the sandbox run sees |
| `archive` | info to high | archives with executables, hooks, `.pth` files, path traversal or zip-bomb ratios |
| `image-payload`, `image-loader` | medium, high | data appended after an image's end, scripts in SVG, code that loads and runs data from its own images |
| `trojan-source` | info, medium | bidirectional control characters or invisible Unicode in source |
| `data-sharing`, `privacy-policy`, `telemetry-optout` | info, medium | analytics and error-reporting SDKs, whether a privacy policy exists (medium when an MCP server or agent plugin has telemetry and no policy), how to turn telemetry off |

## While it runs (sandbox)

| Rule | Severity | Fires when |
|---|---|---|
| `canary-exfil` | critical | a planted secret leaves over DNS, HTTP or intercepted HTTPS, raw or encoded (hex, base64, base32, reversed, URL-encoded, split across DNS labels) |
| `credential-to-own-service` | info | a credential sent to the service it belongs to, such as npm sending its token to the npm registry |
| `bait-read`, `bait-tamper` | high | one of the 20 fake credentials opened, rewritten or deleted |
| `secret-in-output` | high | a secret printed into the program's own output, where CI logs keep it |
| `credential-probe` | high | browser profiles, wallets, chat-app sessions (Discord, Slack, Telegram, Signal), cloud CLIs, password stores, shell history, other processes' environment or memory |
| `imds` | high | cloud metadata endpoints (`169.254.169.254` and friends), the classic cloud-key theft |
| `agent-hijack` | high | talks to your SSH or GPG agent socket |
| `persistence` | high | shell startup files, `authorized_keys`, systemd, cron, `~/.npmrc`, pip config, editor extensions, another agent's config or hooks |
| `path-shadow`, `loader-hijack`, `hook-hijack` | high | a fake `git`/`ssh`/`sudo` earlier in PATH, `ld.so.preload` or `LD_PRELOAD` tricks, git hooks in other repos |
| `dropped-binary`, `auto-exec` | medium, high | executables dropped outside the project, `.pth` files installed into Python |
| `wiper`, `anti-forensics` | high, medium | most of the repo deleted or rewritten; deleting its own scripts or shell history |
| `fileless-exec`, `escape-attempt`, `raw-socket` | medium, high | running from memory or `/dev/shm`, namespace, mount and kernel-module calls, raw sockets |
| `reverse-shell`, `remote-script`, `crypto-miner`, `docker-socket` | high | `/dev/tcp`, `nc -e`, `curl \| sh`, mining pools, `docker.sock` |
| `exfil-service`, `dns-txt` | high, medium | paste sites, webhooks, tunnels, out-of-band test hosts, `.onion`; DNS TXT lookups |
| `input-capture` | medium, high | keyboards (`/dev/input`), clipboard and screenshot tools |
| `disguised-process`, `fork-bomb` | high | processes named like `kworker` or `[kthreadd]` outside system paths; hundreds of processes |
| `mcp-tool-poisoning`, `mcp-hidden-text`, `mcp-result-injection` | high | instructions for the model in MCP tool descriptions or tool results, hidden Unicode |
| `network`, `listener` | medium | contact with anything other than package registries and code hosts; a port opened during install |
| `outside-workspace`, `lingering-process` | medium | files changed outside the project; processes left running after install |
| `sandbox-detection`, `obfuscation`, `downloader`, `privilege` | medium | probing for containers or debuggers, decode-and-run one-liners, `curl`/`wget`, `sudo`/`nsenter` |
| `delayed-activation`, `ci-triggered` | high | behaviour that appears only with the clock 45 days ahead or after repeated runs, or only when it believes it's in CI (`--deep`) |
| `incomplete` | medium, high | the install failed or timed out, the MCP server never answered, the clock could not be shifted, evidence was truncated. A quiet run is never reported as clean |

## Compared with the last check (local history)

| Rule | Severity | Fires when |
|---|---|---|
| `mcp-rug-pull` | high | an MCP tool changed its description or inputs since you last checked it |
| `regressed` | high | was LOOKS SAFE last time, isn't now |
| `hook-changed`, `new-hosts`, `mcp-new-tools` | medium | install hooks added or changed, new hosts contacted, new tools |

## What others already know (OSV and GitHub)

| Rule | Severity | Fires when |
|---|---|---|
| `known-malware` | critical | OSV lists the package as malicious (OpenSSF `MAL-` entries) |
| `known-vulnerability` | medium | known vulnerabilities in that exact version |
| `repo-advisory` | medium, high | the repo has published security advisories |
| `open-security-reports` | info, medium | open issues about leaks, exposed tokens or code execution, and unmerged security fixes |

## Your agent configs (`--agent-configs`)

| Rule | Severity | Fires when |
|---|---|---|
| `configured-mcp` | info to high | an MCP server your agent starts every session, graded by its command; unpinned `npx -y` and `uvx` noted |
| `configured-hook` | info to high | a hook your agent runs automatically |
