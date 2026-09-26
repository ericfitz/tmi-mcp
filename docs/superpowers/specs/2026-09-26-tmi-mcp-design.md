# tmi-mcp Design

Date: 2026-09-26
Status: Approved (conversation), pending written-spec review

## Purpose

A local MCP server, written in Go and spoken over stdio, that lets AI agents do
threat-modeling work against a TMI server: create, read, and update threat
models and their threats, diagrams, assets, documents, notes, repositories, and
metadata. It wraps the generated TMI Go client
(`github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0`). The user signs
in once through an OAuth browser login; the session then persists across
restarts.

Success looks like: an agent in Claude Code calls `threat_models list`, a
browser opens for login the first time, and subsequent calls (including after a
restart) work without further prompts until the refresh token expires.

## Human-Made Architectural Decisions

These were decided by the user (Eric Fitzgerald) during brainstorming on
2026-09-26:

1. **Scope: threat-modeling work only.** Admin, surveys, Timmy chat, addons,
   feedback, and real-time diagram collaboration (WebSocket) are out of scope.
2. **Token persistence: OS keychain, with a mode-600 file fallback.**
3. **Login trigger: lazy.** The first tool call that needs a token opens the
   browser and blocks until login completes or times out. Explicit
   `login`/`logout`/`whoami` actions also exist.
4. **Server selection: named profiles in a config file.** Every tool takes an
   optional `profile` argument.
5. **Tool shape: resource-grouped tools with an `action` argument** (not one
   tool per operation, not a generic OpenAPI passthrough).
6. **Action set trimmed:** threat models get no delete/restore; update and patch
   collapse into one `update` action everywhere; no restore or bulk actions; no
   metadata bulk upsert.

Transport (stdio) and language (Go, wrapping the generated client) were given
in the original request.

## Architecture

One binary, `tmi-mcp`, launched by the MCP client over stdio. It uses the
official MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`). All logging goes
to stderr; stdout carries only the protocol.

| Package | Responsibility |
|---|---|
| `cmd/tmi-mcp` | Flags (`--config`, `--profile`), wiring, run stdio server |
| `internal/config` | Load config file, resolve profiles |
| `internal/auth` | PKCE loopback login, token refresh, revoke |
| `internal/tokenstore` | Keychain (`github.com/zalando/go-keyring`) with file fallback, keyed by profile |
| `internal/session` | Lazily build one authenticated `*APIClient` per profile; on 401, refresh or log in, then retry once |
| `internal/tools` | Tool handlers, one file per resource group |

### Configuration

Default path `~/.config/tmi-mcp/config.yaml` (overridable with `--config`):

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

`--profile` overrides `default_profile` for the process. A tool's `profile`
argument overrides both for that call. An unknown profile is a tool error that
lists the configured profile names.

### Go client dependency

The client module lives in a subdirectory and has no Go-style tag
(`go-client-generated/v1_15_0/vX.Y.Z`). Pin it with a commit pseudo-version.
Ask the tmi-clients agent (Agentbus) whether subdirectory tags can be published;
switch to a tagged version when available.

## Authentication

### Token acquisition, per tool call

1. Load the profile's tokens from the store.
2. If the access token's `exp` claim is more than 60 s away, use it.
3. Else if a refresh token exists, call `POST /oauth2/refresh`, store the new
   pair, and continue. If refresh fails, fall through to login.
4. Else run the interactive login.

A per-profile mutex makes concurrent tool calls share one refresh or login.

### Interactive login (PKCE loopback)

1. Listen on `127.0.0.1:0` (random free port).
2. Generate a PKCE verifier (32 random bytes, base64url), its S256 challenge,
   and a random `state`.
3. Open in the system browser (`open` / `xdg-open` / `rundll32
   url.dll,FileProtocolHandler`):
   `{server}/oauth2/authorize?idp={idp}&client_callback=http://127.0.0.1:{port}/callback&code_challenge={c}&code_challenge_method=S256&state={s}&scope=openid%20profile%20email[&login_hint={h}]`
4. Before blocking, send an MCP log notification: "Opening browser for TMI
   login (profile X)…". Also print the URL to stderr in case the browser fails
   to open.
5. The `/callback` handler verifies `state`, then reads `code` or `error` from
   the query string (TMI redirects with `?code=…&state=…`; confirmed in
   `tmi/auth/handlers_oauth.go`). It serves a short "Login complete; you can
   close this tab" page (or an error page).
6. Exchange at `POST /oauth2/token` with `grant_type=authorization_code`,
   `code`, `code_verifier`, `redirect_uri` (the same callback URL), and
   `state`. Store the resulting tokens.
7. Timeout is 2 minutes. The listener shuts down on success, error, or timeout.

### Server prerequisite

TMI rejects any `client_callback` not in `auth.oauth.client_callback_allowlist`
(empty list means reject all). Each target server must allow
`http://127.0.0.1:*` (the trailing `*` is a prefix wildcard, covering any port).
When authorize fails for this reason, the tool error names the setting and the
exact entry to add.

### Logout

`auth logout` calls `POST /oauth2/revoke` (best effort) and deletes the stored
tokens for the profile.

### Token store

Keychain service `tmi-mcp`, account = profile name, value = JSON
`{access_token, refresh_token, expires_at}`. If the keychain is unavailable
(error on first write/read), use `~/.config/tmi-mcp/tokens/<profile>.json`
created with mode 0600 in a 0700 directory. Tokens are never logged.

## Tools

All tools take an optional `profile` string. `fields` is a JSON object.

| Tool | Actions | Notes |
|---|---|---|
| `auth` | `login`, `logout`, `whoami`, `list_profiles` | `whoami` calls `GET /oauth2/userinfo` |
| `threat_models` | `list`, `get`, `create`, `update` | `list` filters: `name`, `owner`, `status`, `security_reviewer`, `limit`, `offset` |
| `threats` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `diagrams` | `list`, `get`, `create`, `update`, `delete`, `get_model` | scoped by `threat_model_id` |
| `assets` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `documents` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `notes` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `repositories` | `list`, `get`, `create`, `update`, `delete` | scoped by `threat_model_id` |
| `metadata` | `list`, `get`, `set`, `delete` | `target`: `threat_model`, `threat`, `diagram`, `asset`, `document`, `note`, `repository`; `set` = PUT by key |
| `projects` | `list`, `get`, `create`, `update`, `delete` | |
| `teams` | `list`, `get`, `create`, `update`, `delete` | |

### `update` semantics

`update` takes a partial object in `fields`. Each top-level key becomes a JSON
Patch (RFC 6902) `add` operation at `/<key>` (`add` replaces an existing member),
sent to the resource's PATCH endpoint. Every resource with `update` has a PATCH
endpoint that accepts JSON Patch. Agents never send whole objects, so omitted
fields are never clobbered.

### Inputs

Each tool's JSON schema declares an `action` enum, the relevant IDs
(`threat_model_id`, `id`, `key`, `target`), `fields`, and list parameters. The
tool description gives one or two lines per action naming the important fields.

The `threats` description warns that TMI rejects threat `name`, `description`,
and `mitigation` text that looks like HTML/template injection (for example
`word =`, `javascript:`, `{{`, `${`), so agents avoid a confusing 400.

### Outputs

Responses are returned as JSON text content. `list` results are compacted to
key fields (id, name, status or severity where present, modified time) plus the
paging totals; `get` returns the full object.

## Error Handling

- TMI HTTP errors become tool errors (`isError: true`) containing the status,
  TMI's `error` and `error_description`, and a hint where useful: 401 after a
  retry means "log in again"; 403 means no access; 404 means wrong ID; 409 and
  412 mean re-fetch and retry.
- Login failures (timeout, user denied, allowlist rejection, state mismatch)
  are tool errors with a specific message.
- Invalid arguments (missing ID for the action, unknown action) are tool errors
  naming what's missing.
- Protocol-level errors are reserved for programming bugs.

## Testing

- Unit tests: PKCE generation, state verification, callback handler
  (`httptest`), token expiry and refresh decision, fields-to-JSON-Patch
  conversion, file token store permissions, config profile resolution.
- Tool handler tests against an `httptest` fake TMI serving canned responses,
  including 401-then-refresh-then-retry.
- Opt-in integration test (`-tags integration`) against a local TMI dev server
  using the `tmi` provider with `login_hint`, which redirects straight to
  `client_callback` without a real browser (the test follows the redirect
  itself instead of opening a browser).
- `golangci-lint`. `Makefile` targets: `build`, `test`, `lint`,
  `test-integration`.

## Distribution

`go install github.com/ericfitz/tmi-mcp/cmd/tmi-mcp@latest`. The README shows
`claude mcp add tmi -- tmi-mcp` and a sample config file.

## Out of Scope

Admin APIs, surveys, Timmy chat, addons, feedback, WebSocket diagram
collaboration, threat model delete/restore, restore of any resource, bulk
operations, metadata bulk upsert, client-credentials (non-interactive) login.
