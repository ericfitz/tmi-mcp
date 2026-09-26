# tmi-mcp

A local MCP server, written in Go and spoken over stdio, that lets AI agents
do threat-modeling work against a [TMI](https://github.com/ericfitz/tmi)
server: create, read, and update threat models and their threats, diagrams,
assets, documents, notes, repositories, and metadata. It wraps the generated
TMI Go client. Sign in once through an OAuth browser login; the session
persists across restarts (OS keychain, file fallback).

## Install

```sh
go install github.com/ericfitz/tmi-mcp/cmd/tmi-mcp@latest
```

## Configure

Create `~/.config/tmi-mcp/config.yaml` (override with `--config`):

```yaml
default_profile: prod
profiles:
  prod:
    server: https://api.tmi.dev
    idp: google
  local:
    server: http://localhost:8080
    idp: tmi
    login_hint: alice
```

`--profile` overrides `default_profile` for the process; any tool call can
also override both with its own `profile` argument.

### Server prerequisite

Each target TMI server must allow the loopback OAuth callback tmi-mcp uses
for login. Add `http://127.0.0.1:*` (the trailing `*` is a prefix wildcard
covering any port) to that server's `auth.oauth.client_callback_allowlist`
config, or set env `TMI_OAUTH_CLIENT_CALLBACK_ALLOWLIST` on it. Without this,
login fails fast with an allowlist error naming the missing entry.

The `tmi` identity provider (`idp: tmi`) is dev-only — it exists for local
TMI servers and test users like `login_hint: alice`, not production.

## Claude Code setup

```sh
claude mcp add tmi -- tmi-mcp
```

To pin a profile:

```sh
claude mcp add tmi -- tmi-mcp --profile local
```

## Tools

Every tool takes an optional `profile` string. `fields` is a JSON object;
for `update` actions, each top-level key becomes a JSON Patch `add` at
`/<key>` (so omitted fields are never touched).

| Tool | Actions | Notes |
|---|---|---|
| `auth` | `login`, `logout`, `whoami`, `list_profiles` | `whoami` calls `GET /oauth2/userinfo` |
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

- Some responses that the vendored TMI client can't decode — because a
  server field is newer than the client's spec, or a decode bug in a
  particular generated type (e.g. diagrams) — are returned as raw JSON
  instead of failing the call.
- Token revoke sends a hand-built `application/x-www-form-urlencoded` POST;
  the generated revoke call sends an empty JSON body that the server
  rejects.

## Where tokens live

OS keychain, service `tmi-mcp`, account = profile name. If the keychain is
unavailable, tokens fall back to `~/.config/tmi-mcp/tokens/<profile>.json`
(mode 0600, in a mode 0700 directory). Tokens are never logged.

## Development

```sh
make build   # go build -o bin/tmi-mcp ./cmd/tmi-mcp
make test    # go test ./...
make lint    # golangci-lint run ./...
make test-integration   # go test -tags integration ./...; needs TMI_MCP_INTEGRATION_SERVER
```
