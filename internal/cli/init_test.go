package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fake struct {
	calls  []string
	failOn string // fail any call starting with this prefix
}

func (f *fake) run(name string, args ...string) error {
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	if f.failOn != "" && strings.HasPrefix(c, f.failOn) {
		return errors.New("boom")
	}
	return nil
}

// setup returns an Initer over a temp home containing dirs, with the given
// harness CLIs on PATH.
func setup(t *testing.T, dirs []string, onPath ...string) (*Initer, *fake, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(home, "."+d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := &fake{}
	out := &bytes.Buffer{}
	in := &Initer{
		Home:       home,
		ConfigPath: filepath.Join(home, "cfg", "config.yaml"),
		LookPath: func(n string) (string, error) {
			for _, p := range onPath {
				if p == n {
					return "/bin/" + n, nil
				}
			}
			return "", errors.New("not found")
		},
		Run: f.run,
		Out: out,
	}
	return in, f, out
}

var all = []string{"claude", "codex", "grok"}

func TestClaudeOnly(t *testing.T) {
	in, f, _ := setup(t, []string{"claude"}, all...)
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	want := []string{"claude mcp remove -s user tmi", "claude mcp add -s user tmi -- tmi-mcp"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q", f.calls)
	}
}

func TestAllHarnesses(t *testing.T) {
	in, f, _ := setup(t, all, all...)
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"claude mcp remove -s user tmi", "claude mcp add -s user tmi -- tmi-mcp",
		"codex mcp remove tmi", "codex mcp add tmi -- tmi-mcp",
		"grok mcp remove --scope user tmi", "grok mcp add --scope user tmi -- tmi-mcp",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q", f.calls)
	}
}

func TestForcedHarnessWithoutDir(t *testing.T) {
	in, f, _ := setup(t, nil, all...)
	in.Harness = "grok"
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	want := []string{"grok mcp remove --scope user tmi", "grok mcp add --scope user tmi -- tmi-mcp"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q", f.calls)
	}
}

func TestUnknownHarness(t *testing.T) {
	in, _, _ := setup(t, all, all...)
	in.Harness = "vim"
	if err := in.Init(); err == nil || !strings.Contains(err.Error(), "unknown harness") {
		t.Fatalf("err = %v", err)
	}
}

func TestNoHarnessFound(t *testing.T) {
	in, f, out := setup(t, nil, all...)
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || !strings.Contains(out.String(), "no harness found") {
		t.Fatalf("calls = %q, out = %s", f.calls, out)
	}
}

func TestRemoveFailureIgnored(t *testing.T) {
	in, f, _ := setup(t, []string{"claude"}, all...)
	f.failOn = "claude mcp remove"
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls = %q", f.calls)
	}
}

func TestAddFailure(t *testing.T) {
	in, f, _ := setup(t, []string{"claude"}, all...)
	f.failOn = "claude mcp add"
	if err := in.Init(); err == nil || !strings.Contains(err.Error(), "claude mcp add") {
		t.Fatalf("err = %v", err)
	}
}

func TestCLIMissingPrintsSnippet(t *testing.T) {
	in, f, out := setup(t, []string{"claude"})
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || !strings.Contains(out.String(), `"command": "tmi-mcp"`) {
		t.Fatalf("calls = %q, out = %s", f.calls, out)
	}
}

func TestDryRun(t *testing.T) {
	in, f, out := setup(t, []string{"claude"}, all...)
	in.DryRun = true
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || !strings.Contains(out.String(), "would run: claude mcp add -s user tmi -- tmi-mcp") {
		t.Fatalf("calls = %q, out = %s", f.calls, out)
	}
}

func TestConfigHint(t *testing.T) {
	in, _, out := setup(t, []string{"claude"}, all...)
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, in.ConfigPath) || !strings.Contains(s, "server: https://api.tmi.dev") {
		t.Fatalf("out = %s", s)
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if !strings.Contains(lines[len(lines)-1], "restart") {
		t.Fatalf("last line = %q", lines[len(lines)-1])
	}

	in, _, out = setup(t, []string{"claude"}, all...)
	if err := os.MkdirAll(filepath.Dir(in.ConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.ConfigPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := in.Init(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "server:") {
		t.Fatalf("hint printed despite existing config: %s", out)
	}
}
