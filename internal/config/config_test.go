package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const sample = `
default_profile: prod
profiles:
  prod:
    server: https://api.tmi.dev
    idp: google
  local:
    server: http://localhost:8080
    idp: tmi
    login_hint: alice
`

func TestResolveDefaultAndNamed(t *testing.T) {
	c, err := Load(write(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve("")
	if err != nil || p.Name != "prod" || p.Server != "https://api.tmi.dev" || p.IDP != "google" {
		t.Fatalf("default: %+v %v", p, err)
	}
	p, err = c.Resolve("local")
	if err != nil || p.LoginHint != "alice" {
		t.Fatalf("local: %+v %v", p, err)
	}
}

func TestResolveUnknownListsNames(t *testing.T) {
	c, _ := Load(write(t, sample))
	_, err := c.Resolve("nope")
	if err == nil || !strings.Contains(err.Error(), "local, prod") {
		t.Fatalf("want error listing profiles, got %v", err)
	}
}

func TestLoadMissingFileMentionsPath(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/config.yaml") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadBadYAMLMentionsPath(t *testing.T) {
	p := write(t, "profiles: [unclosed")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadValidatesProfiles(t *testing.T) {
	_, err := Load(write(t, "default_profile: x\nprofiles:\n  x:\n    idp: tmi\n"))
	if err == nil || !strings.Contains(err.Error(), "server") {
		t.Fatalf("want missing server error, got %v", err)
	}
	_, err = Load(write(t, "default_profile: y\nprofiles:\n  x:\n    server: http://a\n"))
	if err == nil || !strings.Contains(err.Error(), "default_profile") {
		t.Fatalf("want bad default error, got %v", err)
	}
}

func TestDirHonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	d, err := Dir()
	if err != nil || d != "/tmp/xdg/tmi-mcp" {
		t.Fatalf("got %q %v", d, err)
	}
}
