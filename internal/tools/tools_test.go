package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// TestAuthRefresh exercises the auth tool's refresh action end to end: the
// harness's real RefreshFn (auth.Refresh) hits the fake server's
// /oauth2/refresh, so this must succeed without ever calling the harness's
// forbidden LoginFn.
func TestAuthRefresh(t *testing.T) {
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/refresh" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT2","refresh_token":"RT2","token_type":"Bearer","expires_in":3600}`))
	}))
	v, text, isErr := call(t, cs, "auth", map[string]any{"action": "refresh"})
	if isErr {
		t.Fatalf("%s", text)
	}
	m, ok := v.(map[string]any)
	if !ok || m["status"] != "refreshed" {
		t.Fatalf("result = %v", v)
	}
}

func TestUnknownActionIsToolError(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "auth", map[string]any{"action": "explode"})
	if !isErr {
		t.Fatalf("want tool error, got %s", text)
	}
}

// TestCallRefreshesAndRetriesOn401 exercises session.Manager.Call's 401
// handling end to end through the real generated client: a data call with
// the harness's stored access token ("AT") gets 401, which must trigger
// exactly one refresh (via the harness's real RefreshFn = auth.Refresh, not
// a stub) and exactly one retry with the refreshed token ("AT2"), never a
// login (the harness forbids it).
func TestCallRefreshesAndRetriesOn401(t *testing.T) {
	var dataCalls int32
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/refresh":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"AT2","refresh_token":"RT2","token_type":"Bearer","expires_in":3600}`))
		case "/threat_models/TM":
			atomic.AddInt32(&dataCalls, 1)
			if r.Header.Get("Authorization") != "Bearer AT2" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(threatModelJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	v, text, isErr := call(t, cs, "threat_models", map[string]any{"action": "get", "id": "TM"})
	if isErr {
		t.Fatalf("%s", text)
	}
	if got := atomic.LoadInt32(&dataCalls); got != 2 {
		t.Fatalf("data calls = %d, want exactly 2 (initial 401 + retry)", got)
	}
	m, ok := v.(map[string]any)
	if !ok || m["id"] != "tm-1" {
		t.Fatalf("result = %v", v)
	}
}
