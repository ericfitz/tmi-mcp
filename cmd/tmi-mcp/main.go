// Command tmi-mcp is a stdio MCP server wrapping the TMI Go client.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/session"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
	"github.com/ericfitz/tmi-mcp/internal/tools"
)

func main() {
	dir, err := config.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tmi-mcp:", err)
		os.Exit(1)
	}

	configPath := flag.String("config", filepath.Join(dir, "config.yaml"), "path to config.yaml")
	profile := flag.String("profile", "", "profile name to use (overrides default_profile)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tmi-mcp:", err)
		os.Exit(1)
	}

	store := &tokenstore.Store{Dir: filepath.Join(dir, "tokens")}
	m := session.New(cfg, store, *profile)

	if *profile != "" {
		if _, err := m.Profile(""); err != nil {
			fmt.Fprintln(os.Stderr, "tmi-mcp:", err)
			os.Exit(1)
		}
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "tmi-mcp", Version: "0.1.0"}, nil)
	tools.Register(srv, &tools.Deps{S: m})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "tmi-mcp:", err)
		os.Exit(1)
	}
}
