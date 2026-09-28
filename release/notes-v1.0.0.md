First release of tmi-mcp, a local stdio MCP server that lets AI agents do threat-modeling work against a [TMI](https://github.com/ericfitz/tmi) server.

## Install (macOS)

```sh
brew install ericfitz/tap/tmi-mcp
tmi-mcp init
```

`tmi-mcp init` registers the server as `tmi` with Claude Code, Codex, and Grok Build (whichever are installed) and prints a sample `~/.config/tmi-mcp/config.yaml` if you have none. Elsewhere: `go install github.com/ericfitz/tmi-mcp/cmd/tmi-mcp@latest`.

## What's in it

- Tools: `auth`, `threat_models`, `threats`, `diagrams`, `assets`, `documents`, `notes`, `repositories`, `metadata`, `projects`, `teams`.
- OAuth (PKCE) browser login on first use; tokens persist in the OS keychain (mode-600 file fallback); automatic refresh and one retry on 401.
- Multiple TMI servers via config profiles; optional fixed `callback_port` for servers with a fixed-port callback allowlist.
- Server instructions tell the agent how the tools fit together.
- Several harness sessions can share one login: a process that loses a refresh-token race picks up the tokens the winner saved instead of opening a browser.
