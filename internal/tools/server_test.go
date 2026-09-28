package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/session"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
)

func TestInstructionsNameEveryTool(t *testing.T) {
	cfg := &config.Config{DefaultProfile: "t", Profiles: map[string]config.Profile{"t": {Server: "http://x"}}}
	srv := NewServer("test", &Deps{S: session.New(cfg, &memStore{m: map[string]*tokenstore.Tokens{}}, "")})
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	got := cs.InitializeResult().Instructions
	if got == "" {
		t.Fatal("no instructions")
	}
	res, err := cs.ListTools(ctx, nil)
	if err != nil || len(res.Tools) == 0 {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range res.Tools {
		if !strings.Contains(got, "`"+tool.Name+"`") {
			t.Errorf("instructions do not mention `%s`", tool.Name)
		}
	}
}
