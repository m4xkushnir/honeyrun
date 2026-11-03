# Security policy

## Reporting a vulnerability in honeyrun

If you find a way for code under test to escape the sandbox, hide from honeyrun, read real data on the host, or make honeyrun leak something, please report it privately through [GitHub's private vulnerability reporting](https://github.com/m4xkushnir/honeyrun/security/advisories/new) rather than a public issue.

Include the honeyrun version, the engine and runtime from the report header (for example `gVisor (runsc)`), and the smallest repo or command that shows the problem. Expect a first reply within a few days.

## Scope

In scope:
- sandbox escape or host access from code under test
- evidence tampering: a workload that changes or hides what honeyrun reports
- detection bypasses with a realistic technique
- leaks of secrets or personal paths through any report, the history cache or `--review`

Out of scope: findings on purpose-built fixtures in `bench/fixtures/`, and the limits already listed in the README.

## Supported versions

Only the latest release and `main` get fixes.
