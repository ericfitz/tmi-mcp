package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/session"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
)

type memStore struct{ m map[string]*tokenstore.Tokens }

func (s *memStore) Load(p string) (*tokenstore.Tokens, error) { return s.m[p], nil }
func (s *memStore) Save(p string, t *tokenstore.Tokens) error { s.m[p] = t; return nil }
func (s *memStore) Delete(p string) error                     { delete(s.m, p); return nil }

// harness starts a fake TMI (handler), a session pre-loaded with a valid token, and an in-memory MCP client.
func harness(t *testing.T, tmiHandler http.Handler) *mcp.ClientSession {
	t.Helper()
	fake := httptest.NewServer(tmiHandler)
	t.Cleanup(fake.Close)
	cfg := &config.Config{DefaultProfile: "t", Profiles: map[string]config.Profile{"t": {Server: fake.URL, IDP: "tmi"}}}
	store := &memStore{m: map[string]*tokenstore.Tokens{"t": {AccessToken: "AT", RefreshToken: "RT", ExpiresAt: time.Now().Add(time.Hour)}}}
	m := session.New(cfg, store, "")
	m.LoginFn = func(context.Context, config.Profile, func(string)) (*tokenstore.Tokens, error) {
		t.Errorf("unexpected login")
		return nil, errors.New("unexpected login")
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "tmi-mcp", Version: "test"}, nil)
	Register(srv, &Deps{S: m})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call invokes a tool and returns (decoded JSON text of first content, isError).
func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (any, string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("protocol error: %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	var v any
	_ = json.Unmarshal([]byte(text), &v)
	return v, text, res.IsError
}

func TestAuthListProfilesNoLogin(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	v, text, isErr := call(t, cs, "auth", map[string]any{"action": "list_profiles"})
	if isErr || v.(map[string]any)["default"] != "t" {
		t.Fatalf("%s", text)
	}
}

func TestAuthWhoamiSendsBearer(t *testing.T) {
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/userinfo" || r.Header.Get("Authorization") != "Bearer AT" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userinfoJSON))
	}))
	_, text, isErr := call(t, cs, "auth", map[string]any{"action": "whoami"})
	if isErr {
		t.Fatalf("%s", text)
	}
}

func TestUnknownActionIsToolError(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "auth", map[string]any{"action": "explode"})
	if !isErr {
		t.Fatalf("want tool error, got %s", text)
	}
}
