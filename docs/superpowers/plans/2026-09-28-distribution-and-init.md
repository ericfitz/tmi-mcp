# Distribution and `tmi-mcp init` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship tmi-mcp through the `ericfitz/tap` Homebrew tap with a `version` subcommand, a `tmi-mcp init` that registers the server with installed harnesses, and MCP server instructions.

**Architecture:** `main.go` dispatches `version` / `init` on `os.Args[1]` and otherwise runs the stdio server unchanged. `init` lives in a new `internal/cli` package with injected seams (LookPath, command runner, home, config path, output). Server construction moves into `tools.NewServer`, which sets `ServerOptions.Instructions`. Release tooling is a copy of agentbus's `release/release.sh` + formula template.

**Tech Stack:** Go 1.x, `github.com/modelcontextprotocol/go-sdk` v1.8.0, bash, codesign/notarytool/lipo, gh, Homebrew.

**Spec:** `docs/superpowers/specs/2026-09-28-distribution-and-init-design.md`

## Global Constraints

- Server name registered in every harness: `tmi`; command: `tmi-mcp`, no args.
- Version variable: `main.version`, default `"dev"`, set with `-ldflags "-X main.version=<ver>"`.
- `init` never writes `config.yaml` and never logs in.
- Config path: `config.Dir()` + `/config.yaml` (honors `XDG_CONFIG_HOME`).
- Release: macOS universal binary, codesigned (`Developer ID Application: Robert Fitzgerald (796T45968D)`), notarized (`sqdist-notary`), tap `~/Projects/homebrew-tap`.
- First release tag: `v1.0.0` (user decision 2026-09-28, supersedes the spec's `v0.1.0`).
- No PRs on this repo: branch, then fast-forward main and push.

## Review Focus

- `tmi-mcp` run with an unknown first arg or only flags (`--profile x`) must still run the server, not error as an unknown subcommand. Test: `dispatch` returns "server" for `[]`, `["--profile","x"]`.
- Rerunning `init` must be idempotent: remove failure (entry absent) is ignored. Test: runner fails on `remove`, add still runs, exit 0.
- `--harness` with an unknown value must error, not silently do nothing. Test in Task 2.
- `init` with no harness dirs and no `--harness` prints guidance and exits 0. Test in Task 2.
- Instructions must stay accurate as tools change: test asserts every registered tool name appears in the instructions.

---

### Task 1: `version` subcommand and subcommand dispatch

**Files:**
- Modify: `cmd/tmi-mcp/main.go`
- Test: `cmd/tmi-mcp/main_test.go`

**Interfaces:**
- Produces: `var version = "dev"`; `func subcommand(args []string) string` returning `"version"`, `"init"`, or `""` (server).

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestSubcommand(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"--profile", "x"}, ""},
		{[]string{"version"}, "version"},
		{[]string{"init", "--dry-run"}, "init"},
		{[]string{"bogus"}, ""},
	} {
		if got := subcommand(c.args); got != c.want {
			t.Errorf("subcommand(%q) = %q, want %q", c.args, got, c.want)
		}
	}
	if version != "dev" {
		t.Errorf("version = %q, want dev", version)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./cmd/tmi-mcp/` → FAIL (undefined: subcommand).

- [ ] **Step 3: Implement.** In `main.go` add:

```go
// version is set at release time with -ldflags "-X main.version=<ver>".
var version = "dev"

// subcommand returns the subcommand named by args[0], or "" to run the server.
func subcommand(args []string) string {
	if len(args) > 0 && (args[0] == "version" || args[0] == "init") {
		return args[0]
	}
	return ""
}
```

At the top of `main()`:

```go
switch subcommand(os.Args[1:]) {
case "version":
	fmt.Println(version)
	return
case "init":
	os.Exit(cli.Main(os.Args[2:], os.Stdout, os.Stderr))
}
```

(`cli.Main` arrives in Task 2; for this task, leave the `init` case out and add it in Task 2.) Replace `Version: "0.1.0"` with `Version: version`. Note `flag.Parse()` with a leftover `bogus` arg is harmless (positional args are ignored).

- [ ] **Step 4: Run** `go test ./cmd/tmi-mcp/ && go build -o bin/tmi-mcp ./cmd/tmi-mcp && bin/tmi-mcp version` → PASS, prints `dev`.
- [ ] **Step 5: Commit** `feat: add version subcommand`.

### Task 2: `tmi-mcp init`

**Files:**
- Create: `internal/cli/init.go`, `internal/cli/init_test.go`
- Modify: `cmd/tmi-mcp/main.go` (add `init` case)

**Interfaces:**
- Consumes: `config.Dir() (string, error)`.
- Produces: `func Main(args []string, stdout, stderr io.Writer) int`; `type Initer struct { Home, ConfigPath string; Harness string; DryRun bool; LookPath func(string) (string, error); Run func(name string, args ...string) error; Out io.Writer }`; `func (in *Initer) Init() error`.

Harness table (exact argv):

| harness | dir | remove | add |
|---|---|---|---|
| claude | `~/.claude` | `mcp remove -s user tmi` | `mcp add -s user tmi -- tmi-mcp` |
| codex | `~/.codex` | `mcp remove tmi` | `mcp add tmi -- tmi-mcp` |
| grok | `~/.grok` | `mcp remove --scope user tmi` | `mcp add --scope user tmi -- tmi-mcp` |

Snippets when the CLI is missing:
- claude: `{ "mcpServers": { "tmi": { "command": "tmi-mcp" } } } in ~/.claude.json`
- codex: `[mcp_servers.tmi]\n  command = "tmi-mcp"\n  in ~/.codex/config.toml`
- grok: `[mcp_servers.tmi]\n  command = "tmi-mcp"\n  in ~/.grok/config.toml`

- [ ] **Step 1: Write failing tests** (`init_test.go`) using a fake runner that records `name+" "+strings.Join(args," ")` and can fail by prefix, a `LookPath` that succeeds for a given set, and a temp dir as `Home`:
  - claude dir only → calls exactly `claude mcp remove -s user tmi`, `claude mcp add -s user tmi -- tmi-mcp`.
  - all three dirs → six calls in order claude, codex, grok.
  - `Harness: "grok"` with no dirs → only grok calls.
  - `Harness: "vim"` → `Init()` returns error containing `unknown harness`.
  - no dirs, no harness → no calls, output contains `no harness found`, nil error.
  - remove fails → add still called, nil error.
  - add fails → error containing `claude mcp add`.
  - LookPath fails for claude → no calls, output contains `"command": "tmi-mcp"`.
  - `DryRun` → no calls, output contains `would run: claude mcp add -s user tmi -- tmi-mcp`.
  - ConfigPath absent → output contains the path and `server: https://api.tmi.dev`; ConfigPath present (touch a file) → output lacks `server:`.
  - output ends with a line containing `restart`.

- [ ] **Step 2: Run** `go test ./internal/cli/` → FAIL (package has no non-test files).

- [ ] **Step 3: Implement** `internal/cli/init.go`:

```go
// Package cli implements tmi-mcp's non-server subcommands.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ericfitz/tmi-mcp/internal/config"
)

type harness struct {
	name, dir     string
	remove, add   []string
	snippet       string
}

func harnesses(home string) []harness {
	return []harness{
		{"claude", filepath.Join(home, ".claude"),
			[]string{"mcp", "remove", "-s", "user", "tmi"},
			[]string{"mcp", "add", "-s", "user", "tmi", "--", "tmi-mcp"},
			`{ "mcpServers": { "tmi": { "command": "tmi-mcp" } } } in ~/.claude.json`},
		{"codex", filepath.Join(home, ".codex"),
			[]string{"mcp", "remove", "tmi"},
			[]string{"mcp", "add", "tmi", "--", "tmi-mcp"},
			"[mcp_servers.tmi]\n  command = \"tmi-mcp\"\n  in ~/.codex/config.toml"},
		{"grok", filepath.Join(home, ".grok"),
			[]string{"mcp", "remove", "--scope", "user", "tmi"},
			[]string{"mcp", "add", "--scope", "user", "tmi", "--", "tmi-mcp"},
			"[mcp_servers.tmi]\n  command = \"tmi-mcp\"\n  in ~/.grok/config.toml"},
	}
}

const sampleConfig = `default_profile: prod
profiles:
  prod:
    server: https://api.tmi.dev
    idp: google
    callback_port: 8765`

// Initer registers the tmi MCP server with installed agent harnesses.
type Initer struct {
	Home, ConfigPath string
	Harness          string // "" = every detected harness
	DryRun           bool
	LookPath         func(string) (string, error)
	Run              func(name string, args ...string) error
	Out              io.Writer
}

func (in *Initer) say(format string, a ...any) { _, _ = fmt.Fprintf(in.Out, format+"\n", a...) }

// Init registers tmi-mcp with each selected harness and prints a sample
// config when none exists.
func (in *Initer) Init() error {
	all := harnesses(in.Home)
	var picked []harness
	for _, h := range all {
		if in.Harness == h.name {
			picked = []harness{h}
			break
		}
		if in.Harness == "" {
			if _, err := os.Stat(h.dir); err == nil {
				picked = append(picked, h)
			}
		}
	}
	if in.Harness != "" && len(picked) == 0 {
		return fmt.Errorf("unknown harness %q (want claude, codex, or grok)", in.Harness)
	}
	if len(picked) == 0 {
		in.say("no harness found (no %s, %s, or %s); use --harness claude|codex|grok to force one", all[0].dir, all[1].dir, all[2].dir)
		return nil
	}
	for _, h := range picked {
		if err := in.register(h); err != nil {
			return err
		}
	}
	if _, err := os.Stat(in.ConfigPath); errors.Is(err, os.ErrNotExist) {
		in.say("no config at %s; create it, for example:\n\n%s\n", in.ConfigPath, sampleConfig)
	}
	in.say("done: restart the harness; the first tmi tool call opens a browser to log in")
	return nil
}

// register uses the harness's own CLI so the entry lands in the right file
// and format; without the CLI it prints the snippet to add by hand.
func (in *Initer) register(h harness) error {
	in.say("%s:", h.name)
	if _, err := in.LookPath(h.name); err != nil {
		in.say("  %s CLI not on PATH; add this yourself:\n  %s", h.name, h.snippet)
		return nil
	}
	if in.DryRun {
		in.say("  would run: %s %s", h.name, strings.Join(h.remove, " "))
		in.say("  would run: %s %s", h.name, strings.Join(h.add, " "))
		return nil
	}
	_ = in.Run(h.name, h.remove...) // an absent entry is fine
	if err := in.Run(h.name, h.add...); err != nil {
		return fmt.Errorf("%s %s: %w", h.name, strings.Join(h.add, " "), err)
	}
	in.say("  registered the tmi MCP server via %s %s", h.name, strings.Join(h.add, " "))
	return nil
}

// Main runs `tmi-mcp init` with args and returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tmi-mcp init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	h := fs.String("harness", "", "configure only this harness (claude, codex, or grok), even if it is not detected")
	dry := fs.Bool("dry-run", false, "print what would change without running anything")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "tmi-mcp init:", err)
		return 1
	}
	dir, err := config.Dir()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "tmi-mcp init:", err)
		return 1
	}
	in := &Initer{
		Home: home, ConfigPath: filepath.Join(dir, "config.yaml"),
		Harness: *h, DryRun: *dry, LookPath: exec.LookPath, Out: stdout,
		Run: func(name string, args ...string) error {
			cmd := exec.Command(name, args...)
			cmd.Stdout, cmd.Stderr = io.Discard, stderr
			return cmd.Run()
		},
	}
	if err := in.Init(); err != nil {
		_, _ = fmt.Fprintln(stderr, "tmi-mcp init:", err)
		return 1
	}
	return 0
}
```

Add the `init` case to `main.go` (Task 1 Step 3 snippet) and import `github.com/ericfitz/tmi-mcp/internal/cli`.

- [ ] **Step 4: Run** `go test ./internal/cli/ ./cmd/tmi-mcp/ && make lint && make build && bin/tmi-mcp init --dry-run` → PASS; dry run lists would-run lines for detected harnesses.
- [ ] **Step 5: Commit** `feat: add tmi-mcp init to register the server with agent harnesses`.

### Task 3: Server instructions

**Files:**
- Create: `internal/tools/server.go`, `internal/tools/server_test.go`
- Modify: `cmd/tmi-mcp/main.go` (use `tools.NewServer`)

**Interfaces:**
- Produces: `const Instructions string`; `func NewServer(version string, d *Deps) *mcp.Server` (creates the server with `&mcp.ServerOptions{Instructions: Instructions}` and calls `Register`).

- [ ] **Step 1: Write failing test** (`server_test.go`): build `NewServer("test", &Deps{S: session.New(cfg, &memStore{m: map[string]*tokenstore.Tokens{}}, "")})`, connect via `mcp.NewInMemoryTransports()`, then assert `cs.InitializeResult().Instructions` is non-empty and, for every tool from `cs.ListTools`, contains the backticked tool name (`` "`"+tool.Name+"`" ``).

- [ ] **Step 2: Run** `go test -run TestInstructions ./internal/tools/` → FAIL (undefined: NewServer).

- [ ] **Step 3: Implement** `server.go`:

```go
package tools

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Instructions is sent to the harness in the initialize result: how the
// tools fit together, which per-tool descriptions cannot say.
const Instructions = `Tools for threat modeling on a TMI server.
- Most work lives under a threat model: find or create it with ` + "`threat_models`" + `, then pass its id as threat_model_id to ` + "`threats`, `diagrams`, `assets`, `documents`, `notes`, and `repositories`" + `. ` + "`metadata`" + ` takes a target plus threat_model_id (and id for anything but the threat model itself). ` + "`projects` and `teams`" + ` are top-level.
- update changes only the top-level keys in fields; omitted fields are untouched. get first when changing a nested value.
- Threat models cannot be deleted through these tools.
- Login is automatic: the first call opens a browser, and an expired session is refreshed and the call retried once. If a call still fails with an authentication error, call ` + "`auth`" + ` with action=login; action=whoami shows the signed-in user.
- Every tool takes an optional profile naming a configured TMI server; ` + "`auth`" + ` action=list_profiles lists them. Omit it for the default.
- list actions page with limit and offset.`

// NewServer returns the tmi-mcp MCP server with every tool registered.
func NewServer(version string, d *Deps) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "tmi-mcp", Version: version}, &mcp.ServerOptions{Instructions: Instructions})
	Register(s, d)
	return s
}
```

In `main.go`, replace the `mcp.NewServer(...)` + `tools.Register(...)` lines with `srv := tools.NewServer(version, &tools.Deps{S: m})` and drop the now-unused `mcp` import if the transport line still needs it (it does: `&mcp.StdioTransport{}`; keep the import).

- [ ] **Step 4: Verify each instruction line** against code: `internal/session/session.go` (refresh + one retry on 401, login fallback), `internal/tools/threat_models.go` (no delete), `internal/tools/metadata.go` (target/id rules), `subresource.go` (limit/offset). Run `go test ./... && make lint` → PASS.
- [ ] **Step 5: Commit** `feat: send MCP server instructions describing how the tools fit together`.

### Task 4: Release tooling and docs

**Files:**
- Create: `release/release.sh` (mode 755), `release/tmi-mcp.rb.tmpl`, `release/notes-v1.0.0.md`
- Modify: `.gitignore` (add `dist/`), `README.md` (Install, Harness setup), `docs/superpowers/specs/2026-09-28-distribution-and-init-design.md` (first tag v1.0.0)

- [ ] **Step 1:** Copy `~/Projects/agentbus/release/release.sh` to `release/release.sh` and change: `BIN_NAME="tmi-mcp"`, `GH_REPO="ericfitz/tmi-mcp"`, `VERSION_VAR="main.version"`, build line `go build -trimpath -ldflags "-s -w -X ${VERSION_VAR}=${VERSION}" -o "${BIN}-${arch}" ./cmd/tmi-mcp`. Everything else identical.
- [ ] **Step 2:** `release/tmi-mcp.rb.tmpl`:

```ruby
# Formula for tmi-mcp — installs a prebuilt, signed, notarized universal binary.
# Rendered from release/tmi-mcp.rb.tmpl by release/release.sh; do not edit
# the copy in the tap by hand.
class TmiMcp < Formula
  desc "MCP server for threat modeling against a TMI server"
  homepage "https://github.com/ericfitz/tmi-mcp"
  url "__URL__"
  sha256 "__SHA256__"
  license "Apache-2.0"

  # Prebuilt universal binary; no build dependencies. macOS only.
  depends_on :macos

  def install
    bin.install "tmi-mcp"
  end

  def caveats
    <<~EOS
      Register tmi-mcp with your coding harnesses:
        tmi-mcp init
      Then create ~/.config/tmi-mcp/config.yaml (init prints a sample).
    EOS
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/tmi-mcp version").strip
  end
end
```

  Check `LICENSE` is Apache-2.0 first; use its actual SPDX id.
- [ ] **Step 3:** `release/notes-v1.0.0.md` summarizing: first release; tools list; OAuth login with keychain; `tmi-mcp init`; server instructions; cross-process refresh fix.
- [ ] **Step 4:** README: Install → `brew install ericfitz/tap/tmi-mcp` then `tmi-mcp init`; `go install ...@latest` as the non-macOS alternative. Rename "Claude Code setup" to "Harness setup": `tmi-mcp init` (flags `--harness`, `--dry-run`), manual `claude mcp add tmi -- tmi-mcp` fallback, profile pinning via manual add, one sentence that the server sends usage instructions to the harness. Add `dist/` to `.gitignore`. Spec: change "First tag: `v0.1.0`" to "First tag: `v1.0.0` (user decision 2026-09-28)".
- [ ] **Step 5:** `shellcheck release/release.sh` → clean. `ruby -c release/tmi-mcp.rb.tmpl` → Syntax OK.
- [ ] **Step 6: Commit** `build: add Homebrew release tooling; docs for brew install and init`.

### Task 5: Merge and release v1.0.0

- [ ] **Step 1:** Final review of the branch diff; `go test -race ./... && make lint && make build`.
- [ ] **Step 2:** Fast-forward main, push, delete branch. Update PROGRESS.md (pushed state), push.
- [ ] **Step 3:** `git tag -a v1.0.0 -m v1.0.0 && git push origin v1.0.0`.
- [ ] **Step 4:** `./release/release.sh v1.0.0` (codesign/notarize use the user's keychain; tap push uses SSH + Touch ID — wait for the user on a Touch ID prompt, never work around it).
- [ ] **Step 5:** Verify: `brew update && brew install ericfitz/tap/tmi-mcp && tmi-mcp version` → `1.0.0`; `tmi-mcp init` re-registers `tmi` → the brew binary on PATH (replacing the `bin/` dev entry); `claude mcp get tmi` shows `tmi-mcp`.
