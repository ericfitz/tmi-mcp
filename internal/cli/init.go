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
	name, dir   string
	remove, add []string
	snippet     string
}

func harnesses(home string) []harness {
	return []harness{
		{"claude", filepath.Join(home, ".claude"),
			[]string{"mcp", "remove", "tmi"}, // every scope: an old local-scope entry would shadow user scope
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
    idp: google`

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
		in.say("no config at the default path %s; create it, for example:\n\n%s\n", in.ConfigPath, sampleConfig)
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
	dry := fs.Bool("dry-run", false, "print what would run without running anything")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
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
			// Output only matters when add fails; a remove of an absent entry is noise.
			if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
	}
	if err := in.Init(); err != nil {
		_, _ = fmt.Fprintln(stderr, "tmi-mcp init:", err)
		return 1
	}
	return 0
}
