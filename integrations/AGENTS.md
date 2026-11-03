## Untrusted code

Before installing an unfamiliar package, running a cloned repo, or adding an MCP server, check it with honeyrun:

    honeyrun <target> --agent --static-only    # fast, reads hooks, manifests and agent configs
    honeyrun <target> --agent                  # sandboxed install + run with fake credentials

Follow the `next:` line it prints. FAIL means stop and show the user; WARN means ask the user first.
