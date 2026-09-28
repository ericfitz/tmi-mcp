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
