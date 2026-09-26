package session

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
	"github.com/ericfitz/tmi-mcp/internal/auth"
	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]*tokenstore.Tokens
}

func (s *memStore) Load(p string) (*tokenstore.Tokens, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.m[p], nil }
func (s *memStore) Save(p string, t *tokenstore.Tokens) error { s.mu.Lock(); defer s.mu.Unlock(); s.m[p] = t; return nil }
func (s *memStore) Delete(p string) error                      { s.mu.Lock(); defer s.mu.Unlock(); delete(s.m, p); return nil }

func cfg() *config.Config {
	return &config.Config{DefaultProfile: "a", Profiles: map[string]config.Profile{
		"a": {Server: "http://a"}, "b": {Server: "http://b"},
	}}
}

type harness struct {
	m          *Manager
	store      *memStore
	logins     atomic.Int32
	refreshs   atomic.Int32
	refreshErr error
}

func newHarness() *harness {
	h := &harness{store: &memStore{m: map[string]*tokenstore.Tokens{}}}
	h.m = New(cfg(), h.store, "")
	h.m.LoginFn = func(ctx context.Context, p config.Profile, n func(string)) (*tokenstore.Tokens, error) {
		h.logins.Add(1)
		time.Sleep(20 * time.Millisecond)
		return &tokenstore.Tokens{AccessToken: "login-" + p.Name, RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}
	h.m.RefreshFn = func(ctx context.Context, server, rt string) (*tokenstore.Tokens, error) {
		h.refreshs.Add(1)
		if h.refreshErr != nil {
			return nil, h.refreshErr
		}
		return &tokenstore.Tokens{AccessToken: "refreshed", RefreshToken: "rt2", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}
	return h
}

func tokenFrom(ctx context.Context) string { s, _ := ctx.Value(tmi.ContextAccessToken).(string); return s }

func TestLazyLoginThenCached(t *testing.T) {
	h := newHarness()
	for i := 0; i < 2; i++ {
		v, err := h.m.Call(context.Background(), "", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return tokenFrom(ctx), &http.Response{StatusCode: 200}, nil
		})
		if err != nil || v != "login-a" {
			t.Fatalf("%v %v", v, err)
		}
	}
	if h.logins.Load() != 1 {
		t.Fatalf("logins=%d", h.logins.Load())
	}
}

func TestConcurrentCallsShareOneLogin(t *testing.T) {
	h := newHarness()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return nil, &http.Response{StatusCode: 200}, nil
			})
		}()
	}
	wg.Wait()
	if h.logins.Load() != 1 {
		t.Fatalf("logins=%d, want 1", h.logins.Load())
	}
}

func TestExpiredUsesRefresh(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(10 * time.Second)}
	v, err := h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		return tokenFrom(ctx), &http.Response{StatusCode: 200}, nil
	})
	if err != nil || v != "refreshed" || h.logins.Load() != 0 {
		t.Fatalf("%v %v logins=%d", v, err, h.logins.Load())
	}
	if h.store.m["a"].RefreshToken != "rt2" {
		t.Fatal("refreshed tokens not saved")
	}
}

func TestRefreshFailureFallsBackToLogin(t *testing.T) {
	h := newHarness()
	h.refreshErr = &auth.APIError{Status: 401}
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now()}
	v, err := h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		return tokenFrom(ctx), &http.Response{StatusCode: 200}, nil
	})
	if err != nil || v != "login-a" {
		t.Fatalf("%v %v", v, err)
	}
}

func TestUnauthorizedRetriesOnce(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "stale", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	v, err := h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		calls++
		if tokenFrom(ctx) == "stale" {
			return nil, &http.Response{StatusCode: 401}, errors.New("401 Unauthorized")
		}
		return tokenFrom(ctx), &http.Response{StatusCode: 200}, nil
	})
	if err != nil || v != "refreshed" || calls != 2 {
		t.Fatalf("%v %v calls=%d", v, err, calls)
	}
}

func TestSecond401Surfaces(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "x", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	_, err := h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		calls++
		return nil, &http.Response{StatusCode: 401}, errors.New("401 Unauthorized")
	})
	var ae *auth.APIError
	if !errors.As(err, &ae) || ae.Status != 401 || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestUnknownProfile(t *testing.T) {
	h := newHarness()
	_, err := h.m.Call(context.Background(), "zzz", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("got %v", err)
	}
}

func TestLogoutRevokesAndDeletes(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "x", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	var revoked string
	h.m.RevokeFn = func(ctx context.Context, server, tok string) error { revoked = tok; return errors.New("server down") }
	if err := h.m.Logout(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if revoked != "rt" || h.store.m["a"] != nil {
		t.Fatalf("revoked=%q stored=%v", revoked, h.store.m["a"])
	}
}
