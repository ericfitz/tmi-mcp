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

	"github.com/ericfitz/tmi-mcp/internal/cli"
	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/session"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
	"github.com/ericfitz/tmi-mcp/internal/tools"
)

// version is set at release time with -ldflags "-X main.version=<ver>".
var version = "dev"

// subcommand returns the subcommand named by args[0], or "" to run the server.
func subcommand(args []string) string {
	if len(args) > 0 && (args[0] == "version" || args[0] == "init") {
		return args[0]
	}
	return ""
}

func main() {
	switch subcommand(os.Args[1:]) {
	case "version":
		fmt.Println(version)
		return
	case "init":
		os.Exit(cli.Main(os.Args[2:], os.Stdout, os.Stderr))
	}

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

	srv := tools.NewServer(version, &tools.Deps{S: m})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "tmi-mcp:", err)
		os.Exit(1)
	}
}
