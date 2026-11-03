# Responsible use, privacy and disclaimer

This is not legal advice. It describes how honeyrun behaves and the terms you accept by using it.

## No warranty

honeyrun is released under the MIT License and provided "as is", without warranty of any kind. Its results are signals from one check of one version of the code, at one time. A LOOKS SAFE result means nothing suspicious happened during that check. It is not a certificate. You decide what to install and run, and you are responsible for that decision. The authors and contributors are not liable for any damage, loss or claim arising from use of honeyrun or from acting, or not acting, on its results.

## What honeyrun does with your data

- **No telemetry.** honeyrun has no analytics, no accounts and no server of its own. It never phones home.
- **Network use you can see.** It only goes online to:
  - download what you asked it to check (git clone, npm or PyPI download);
  - look the target up in [OSV](https://osv.dev) and the GitHub API, on by default only for `npm:`, `pypi:` and plain `https://` GitHub or GitLab targets (and `owner/repo`), off for local paths, ssh/scp URLs, other hosts and anything with credentials in the URL (`--intel` forces it on). Your `GITHUB_TOKEN`, if set, is sent only to api.github.com, and only for github.com targets. Turn it off with `--no-intel`;
  - send a review prompt with `--review`, and only to the command you name.
- **Inside the sandbox** the code under test sees fake credentials only. Your real home directory, keys and environment are never mounted or copied in. Local directories are packed without `.git` and without untracked secret-looking files (`.env`, keys, `.npmrc`, `.netrc`, ...).
- **On your machine,** `--agent-configs` and `--installed` read local files and print names, commands and findings. They mask tokens, passwords in URLs and secret-looking values, never print environment values, and write `~` instead of your home path.
- **History** of past checks is kept on your machine only (`~/Library/Caches/honeyrun`, `~/.cache/honeyrun` or `%LOCALAPPDATA%\honeyrun`), as fingerprints and masked finding titles. Delete that folder or pass `--no-history` to stop it.

## Your AI, your terms

`--review` sends a short, masked summary of the evidence to an AI command line tool that you choose and configure, such as Claude Code, Codex or Gemini CLI. honeyrun does not pick a provider or hold any keys. What you send to that provider, and whether that is allowed for your code and your organisation, is governed by your agreement with them and is your responsibility. Leave `--review` off if you are unsure.

The reviewer is instructed to explain behaviour only. It is told never to rewrite, complete, improve or weaponise the code it sees.

## Use it on code you may run

Only check code you have the right to download and run, and follow the terms of the services you fetch it from (GitHub, npm, PyPI and others) and the rules of your organisation. Don't use honeyrun to probe systems you don't own, and don't point it at third-party services.

## Reports about other people's code

`--abuse-report` writes a draft from the observed facts. Read it before you send it, keep it factual, and send it through the official channels it lists. Findings describe behaviour seen in a sandbox. They are not a judgement about anyone's intent.

## Test fixtures

`bench/fixtures/` contains small programs that imitate malware behaviour so honeyrun can be tested. They are inert: they only target reserved `example.net` names and the TEST-NET range, and only touch honeyrun's fake credentials. Don't open those folders as an editor or agent workspace.
