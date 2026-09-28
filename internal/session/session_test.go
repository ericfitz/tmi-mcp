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

// Another process rotated the single-use refresh token first: ours is
// rejected, but the store already holds its valid replacement.
func TestRefreshLostRaceUsesStoredTokens(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now()}
	h.m.RefreshFn = func(ctx context.Context, server, rt string) (*tokenstore.Tokens, error) {
		_ = h.store.Save("a", &tokenstore.Tokens{AccessToken: "other", RefreshToken: "rt2", ExpiresAt: time.Now().Add(time.Hour)})
		return nil, &auth.APIError{Status: 400}
	}
	v, err := h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		return tokenFrom(ctx), &http.Response{StatusCode: 200}, nil
	})
	if err != nil || v != "other" || h.logins.Load() != 0 {
		t.Fatalf("%v %v logins=%d", v, err, h.logins.Load())
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

func TestRefreshWithStoredToken(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	loggedIn, err := h.m.Refresh(context.Background(), "a", nil)
	if err != nil || loggedIn {
		t.Fatalf("loggedIn=%v err=%v", loggedIn, err)
	}
	if h.refreshs.Load() != 1 || h.logins.Load() != 0 {
		t.Fatalf("refreshs=%d logins=%d", h.refreshs.Load(), h.logins.Load())
	}
	if h.store.m["a"].AccessToken != "refreshed" {
		t.Fatalf("refreshed tokens not saved: %+v", h.store.m["a"])
	}
}

func TestRefreshFallsBackToLoginOnRefreshFailure(t *testing.T) {
	h := newHarness()
	h.refreshErr = &auth.APIError{Status: 401}
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	loggedIn, err := h.m.Refresh(context.Background(), "a", nil)
	if err != nil || !loggedIn {
		t.Fatalf("loggedIn=%v err=%v", loggedIn, err)
	}
	if h.logins.Load() != 1 {
		t.Fatalf("logins=%d", h.logins.Load())
	}
}

func TestRefreshNoStoredTokensLogsIn(t *testing.T) {
	h := newHarness()
	loggedIn, err := h.m.Refresh(context.Background(), "a", nil)
	if err != nil || !loggedIn {
		t.Fatalf("loggedIn=%v err=%v", loggedIn, err)
	}
	if h.logins.Load() != 1 || h.refreshs.Load() != 0 {
		t.Fatalf("logins=%d refreshs=%d", h.logins.Load(), h.refreshs.Load())
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
	var revoked, revokedAccess string
	h.m.RevokeFn = func(ctx context.Context, server, accessToken, tok string) error {
		revokedAccess, revoked = accessToken, tok
		return errors.New("server down")
	}
	if err := h.m.Logout(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if revoked != "rt" || revokedAccess != "x" || h.store.m["a"] != nil {
		t.Fatalf("revoked=%q revokedAccess=%q stored=%v", revoked, revokedAccess, h.store.m["a"])
	}
}

// A logout issued while a login is in flight must win: the login's tokens
// may not be saved back after the delete.
func TestLogoutWaitsForInFlightLogin(t *testing.T) {
	h := newHarness()
	started, release := make(chan struct{}), make(chan struct{})
	h.m.LoginFn = func(ctx context.Context, p config.Profile, n func(string)) (*tokenstore.Tokens, error) {
		close(started)
		<-release
		return &tokenstore.Tokens{AccessToken: "login", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}
	h.m.RevokeFn = func(context.Context, string, string, string) error { return nil }
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return nil, &http.Response{StatusCode: 200}, nil
		})
	}()
	<-started
	logoutDone := make(chan error)
	go func() { logoutDone <- h.m.Logout(context.Background(), "a") }()
	time.Sleep(20 * time.Millisecond) // let Logout reach the lock
	close(release)
	<-callDone
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	if h.store.m["a"] != nil {
		t.Fatalf("tokens survived logout: %+v", h.store.m["a"])
	}
}

// Concurrent calls that all get a 401 on the same stale token share one
// refresh: later ones reuse the token the first one stored.
func TestConcurrent401sShareOneRefresh(t *testing.T) {
	h := newHarness()
	h.store.m["a"] = &tokenstore.Tokens{AccessToken: "stale", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)}
	var got401 sync.WaitGroup
	got401.Add(8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			_, _ = h.m.Call(context.Background(), "a", nil, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				if tokenFrom(ctx) == "stale" {
					if first {
						first = false
						got401.Done()
						got401.Wait() // all eight hold the stale token before any refresh
					}
					return nil, &http.Response{StatusCode: 401}, errors.New("401 Unauthorized")
				}
				return nil, &http.Response{StatusCode: 200}, nil
			})
		}()
	}
	wg.Wait()
	if h.refreshs.Load() != 1 {
		t.Fatalf("refreshs=%d, want 1", h.refreshs.Load())
	}
}
