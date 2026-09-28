# tmi-mcp

A local MCP server, written in Go and spoken over stdio, that lets AI agents
do threat-modeling work against a [TMI](https://github.com/ericfitz/tmi)
server: create, read, and update threat models and their threats, diagrams,
assets, documents, notes, repositories, and metadata. It wraps the generated
TMI Go client. Sign in once through an OAuth browser login; the session
persists across restarts (OS keychain, file fallback).

## Install

macOS, with Homebrew:

```sh
brew install ericfitz/tap/tmi-mcp
tmi-mcp init
```

Elsewhere, with Go:

```sh
go install github.com/ericfitz/tmi-mcp/cmd/tmi-mcp@latest
tmi-mcp init
```

`tmi-mcp version` prints the installed version.

## Configure

Create `~/.config/tmi-mcp/config.yaml` (override with `--config`). This path
honors `XDG_CONFIG_HOME` (`$XDG_CONFIG_HOME/tmi-mcp/config.yaml`), as does the
token fallback directory below.

```yaml
default_profile: prod
profiles:
  prod:
    server: https://api.tmi.dev
    idp: google
    callback_port: 8765
  local:
    server: http://localhost:8080
    idp: tmi
    login_hint: alice
    callback_port: 8765
```

`--profile` overrides `default_profile` for the process; any tool call can
also override both with its own `profile` argument. `callback_port` (1024-65535,
optional) pins the OAuth loopback listener to that port instead of a random
one; leave it unset unless the server prerequisite below requires it.

### Server prerequisite

Each target TMI server must allow the loopback OAuth callback tmi-mcp uses
for login, via that server's `auth.oauth.client_callback_allowlist` config (or
env `TMI_OAUTH_CLIENT_CALLBACK_ALLOWLIST`). TMI's allowlist matcher is a raw
string-prefix check, so there are two options:

- Set `callback_port: 8765` (or any fixed port) on the profile and add
  `http://127.0.0.1:8765/*` to the allowlist. Safe with the current matcher.
- Do **not** use the wildcard-port form `http://127.0.0.1:*` — with a prefix
  matcher it also matches `http://127.0.0.1:1@evil.example/...`. Avoid it
  until TMI's matcher parses URLs instead of prefix-matching strings.

Without an allowlist entry, login fails fast with an error naming the missing
entry.

The `tmi` identity provider (`idp: tmi`) is dev-only — it exists for local
TMI servers and test users like `login_hint: alice`, not production.

## Harness setup

`tmi-mcp init` registers the server as `tmi` with every agent harness it
finds (Claude Code, Codex, Grok Build, detected by `~/.claude`, `~/.codex`,
`~/.grok`) through each harness's own CLI. It is safe to rerun. If a
harness's CLI is not on PATH, it prints the config snippet to add by hand;
if you have no config file yet, it prints a sample. Restart the harness
afterward.

- `--harness claude|codex|grok` configures only that harness, even if it is
  not detected.
- `--dry-run` prints the commands without running them.

The server sends usage instructions to the harness when it connects, so the
agent learns how the tools fit together without extra setup.

To register by hand, or to pin a profile:

```sh
claude mcp add -s user tmi -- tmi-mcp
claude mcp add -s user tmi -- tmi-mcp --profile local
```

## Tools

Every tool takes an optional `profile` string. `fields` is a JSON object;
for `update` actions, each top-level key becomes a JSON Patch `add` at
`/<key>` (so omitted fields are never touched).

| Tool | Actions | Notes |
|---|---|---|
| `auth` | `login`, `logout`, `refresh`, `whoami`, `list_profiles` | `refresh` refreshes the token if possible, otherwise falls back to a browser login; `whoami` calls `GET /oauth2/userinfo` |
| `threat_models` | `list`, `get`, `create`, `update` | `list` filters: `name`, `owner`, `status`, `security_reviewer`, `limit`, `offset`; no delete |
| `threats` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `diagrams` | `list`, `get`, `create`, `update`, `delete`, `get_model` | scoped by `threat_model_id`; `get_model` returns a compact node/edge model |
| `assets` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `documents` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `notes` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `repositories` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `metadata` | `list`, `get`, `set`, `delete` | `target`: `threat_model`, `threat`, `diagram`, `asset`, `document`, `note`, `repository`; `set` upserts by key |
| `projects` | `list`, `get`, `create`, `update`, `delete` | |
| `teams` | `list`, `get`, `create`, `update`, `delete` | |

### Known client workarounds

- Responses with a field newer than the vendored client's spec (every
  generated model decodes with `DisallowUnknownFields`) are returned as raw
  JSON instead of failing the call.

## Where tokens live

OS keychain, service `tmi-mcp`, account = profile name. If the keychain is
unavailable, tokens fall back to `~/.config/tmi-mcp/tokens/<profile>.json`
(mode 0600, in a mode 0700 directory). Tokens are never logged.

## Development

```sh
make build             # go build -o bin/tmi-mcp ./cmd/tmi-mcp
make test              # go test -timeout 120s ./...
make lint              # golangci-lint run ./...
TMI_MCP_INTEGRATION_SERVER=http://localhost:8080 TMI_MCP_INTEGRATION_CALLBACK_PORT=8765 make test-integration   # go test -tags integration -timeout 300s ./...
```
