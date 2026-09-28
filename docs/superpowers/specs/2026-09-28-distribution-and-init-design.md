# Distribution and `tmi-mcp init` — design

Date: 2026-09-28. Status: approved in conversation; awaiting spec review.

## Goal

Distribute tmi-mcp the way agentbus is distributed (signed, notarized macOS
binary via the `ericfitz/tap` Homebrew tap) and add `tmi-mcp init` to register
the server with installed agent harnesses, replacing the hand-typed
`claude mcp add`.

## Human decisions (architectural)

- **Distribution channel:** Homebrew tap `ericfitz/tap`, prebuilt universal
  macOS binary, codesigned and notarized, released via a local
  `release/release.sh` modeled on agentbus. `go install` remains the
  non-macOS path. (Decided by the user, 2026-09-28.)
- **`init` scope:** register only (option A). `init` registers the MCP server
  with detected harnesses and prints a sample config when none exists. It
  does not write `config.yaml` and does not log in. (Decided by the user,
  2026-09-28.)
- **Server instructions in this spec:** add MCP server `instructions` so the
  harness gets cross-tool usage guidance with no install step. (Decided by the
  user, 2026-09-28.)

## Current state

- Install: `go install github.com/ericfitz/tmi-mcp/cmd/tmi-mcp@latest`; no
  tags or releases.
- Version is hardcoded `"0.1.0"` in `cmd/tmi-mcp/main.go`.
- CLI is flags only (`--config`, `--profile`); running the binary starts the
  stdio MCP server.
- Registration is manual: `claude mcp add tmi -- tmi-mcp`.

## Design

### 1. CLI surface

- `tmi-mcp [--config PATH] [--profile NAME]` — unchanged; runs the stdio
  server. Existing registrations keep working.
- `tmi-mcp version` — prints the version. A package variable in `main`
  (`version`, default `dev`) is set at release time with
  `-ldflags "-X main.version=<ver>"`; `mcp.Implementation.Version` uses it.
- `tmi-mcp init [--harness claude|codex|grok] [--dry-run]` — see below.

Subcommands are dispatched on `os.Args[1]` before flag parsing; anything else
falls through to the existing server path.

### 2. `init` behavior

Approach: port agentbus's `internal/cli/init.go` registration pattern,
without hooks, skills, prompts, or per-repo setup.

- **Detection:** a harness is configured when its directory exists
  (`~/.claude`, `~/.codex`, `~/.grok`). `--harness X` configures only X,
  even if its directory is absent. If none is found, print a message naming
  the directories and the `--harness` flag, and exit 0.
- **Registration** through each harness's own CLI, remove-then-add so reruns
  are idempotent (a failed remove is ignored):

  | Harness | remove | add |
  |---|---|---|
  | claude | `claude mcp remove -s user tmi` | `claude mcp add -s user tmi -- tmi-mcp` |
  | codex | `codex mcp remove tmi` | `codex mcp add tmi -- tmi-mcp` |
  | grok | `grok mcp remove --scope user tmi` | `grok mcp add --scope user tmi -- tmi-mcp` |

  The server name is `tmi`, matching the existing README and the current
  local registration (which init replaces with the PATH binary).
- **CLI missing:** if the harness CLI is not on PATH, print the equivalent
  config snippet to add by hand (JSON for `~/.claude.json`, TOML for
  `~/.codex/config.toml` and `~/.grok/config.toml`).
- **`--dry-run`:** print the commands that would run; execute nothing.
- **Config hint:** if the resolved config path
  (`$XDG_CONFIG_HOME/tmi-mcp/config.yaml`, else
  `~/.config/tmi-mcp/config.yaml`, using the same resolver as the server)
  does not exist, print the path and a sample `prod` profile
  (`server: https://api.tmi.dev`, `idp: google`, `callback_port: 8765`).
  Never write it.
- **Finish** with: restart the harness; the first tool call triggers login.
- Add-command failure returns a non-zero exit with the command and error.

Code lives in a new `internal/cli` package (`init.go` + `init_test.go`);
`main.go` only dispatches. Dependencies (`LookPath`, command runner, home
dir, config path, output writer) are injected for tests.

Out of scope: `--profile` pinning in registration args, per-repo config,
config writing, login, hooks/skills.

### 3. Release pipeline

`release/release.sh <tag>`, copied from agentbus with these changes:
`BIN_NAME=tmi-mcp`, `GH_REPO=ericfitz/tmi-mcp`, build path `./cmd/tmi-mcp`,
`VERSION_VAR=main.version`. Same steps: build darwin arm64+amd64 from a
throwaway worktree of the tag with `CGO_ENABLED=0 -trimpath`, `lipo` to
universal, verify `tmi-mcp version` equals the tag version, codesign
(same Developer ID, hardened runtime), notarize (`sqdist-notary` profile),
tarball + sha256, `gh release create` (using `release/notes-<tag>.md` when
present), render the formula into `~/Projects/homebrew-tap` and push.

`release/tmi-mcp.rb.tmpl`: `depends_on :macos`, `bin.install "tmi-mcp"`,
caveats telling the user to run `tmi-mcp init` and create the config file,
test asserting `tmi-mcp version` equals the formula version.

`dist/` is added to `.gitignore`. The script needs the user's keychain
(signing, notarization) and SSH (tap push), so only the user runs it. First
tag: `v1.0.0` (user decision 2026-09-28, replacing `v0.1.0`).

### 4. Server instructions

Today `main.go` passes `nil` `ServerOptions`, so the `initialize` response
carries no `instructions`; models see only per-tool descriptions and input
schemas from `tools/list`. Set `mcp.ServerOptions{Instructions: ...}` (go-sdk
v1.8.0 field) to a constant in `internal/tools` (next to the tool
registrations it describes), about 10 lines, covering:

- Everything lives under a threat model: find or create it with
  `threat_models`, then pass its id as `threat_model_id` to `threats`,
  `diagrams`, `assets`, `documents`, `notes`, `repositories`; `metadata`
  takes a `target` plus ids.
- `update` sends only the keys in `fields` (each top-level key replaces that
  field); omitted fields are untouched. `get` first when changing nested
  values.
- Threat models cannot be deleted through this server.
- Login is automatic: the first call opens a browser, and an expired session
  is refreshed and retried once. If a call still returns an authentication
  error, call `auth` with `action=login`; `auth whoami` shows the signed-in
  user.
- `profile` on any tool selects a configured TMI server;
  `auth list_profiles` lists them. Omit it to use the default.
- `list` actions page with `limit`/`offset`.

Each statement must match current behavior (checked against
`internal/session` and `internal/tools` during implementation). Test: an
in-memory client/server test asserting the `initialize` result's
`instructions` is non-empty and names every registered tool.

### 5. Testing

- `internal/cli/init_test.go`: harness detection; `--harness` forcing an
  absent harness; exact remove/add argv per harness; snippet printed when the
  CLI is missing; `--dry-run` runs nothing; config hint printed only when the
  config file is absent; add failure surfaces an error.
- `version` default is `dev`.
- `shellcheck release/release.sh`.
- The release script itself is verified by the first real release.

### 6. Docs

README Install: `brew install ericfitz/tap/tmi-mcp` then `tmi-mcp init`;
`go install` as the alternative. "Claude Code setup" becomes "Harness setup"
describing `init`, with the manual `claude mcp add` kept as a fallback.
A sentence notes that the server sends usage instructions to the harness.
