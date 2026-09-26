// Package config loads tmi-mcp's profile configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Profile struct {
	Name         string `yaml:"-"`
	Server       string `yaml:"server"`
	IDP          string `yaml:"idp"`
	LoginHint    string `yaml:"login_hint"`
	CallbackPort int    `yaml:"callback_port"`
}

type Config struct {
	DefaultProfile string             `yaml:"default_profile"`
	Profiles       map[string]Profile `yaml:"profiles"`
}

// Dir returns $XDG_CONFIG_HOME/tmi-mcp, else ~/.config/tmi-mcp.
func Dir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "tmi-mcp"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tmi-mcp"), nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(c.Profiles) == 0 {
		return nil, fmt.Errorf("config %s: no profiles defined", path)
	}
	for name, p := range c.Profiles {
		if p.Server == "" {
			return nil, fmt.Errorf("config %s: profile %q has no server", path, name)
		}
		if p.CallbackPort != 0 && (p.CallbackPort < 1024 || p.CallbackPort > 65535) {
			return nil, fmt.Errorf("config %s: profile %q has invalid callback_port %d (must be 1024-65535)",
				path, name, p.CallbackPort)
		}
	}
	if _, ok := c.Profiles[c.DefaultProfile]; !ok {
		return nil, fmt.Errorf("config %s: default_profile %q is not a defined profile (have: %s)",
			path, c.DefaultProfile, strings.Join(c.Names(), ", "))
	}
	return &c, nil
}

func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (c *Config) Resolve(name string) (Profile, error) {
	if name == "" {
		name = c.DefaultProfile
	}
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (have: %s)", name, strings.Join(c.Names(), ", "))
	}
	p.Name = name
	return p, nil
}
