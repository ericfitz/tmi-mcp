// Package session manages per-profile TMI API sessions: lazy login, token
// refresh, and 401-triggered re-authentication.
package session

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
	"github.com/ericfitz/tmi-mcp/internal/auth"
	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
)

// Notify reports human-readable progress messages during login.
type Notify func(msg string)

// CallFunc is a TMI API call to run with an authenticated client.
type CallFunc func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error)

// TokenStore persists tokens per profile.
type TokenStore interface {
	Load(profile string) (*tokenstore.Tokens, error)
	Save(profile string, t *tokenstore.Tokens) error
	Delete(profile string) error
}

// Manager coordinates login, token refresh, and API calls across profiles.
type Manager struct {
	Cfg     *config.Config
	Store   TokenStore
	Default string // --profile override; "" means cfg.DefaultProfile

	// Seams (default to auth.Login / auth.Refresh / auth.Revoke / time.Now).
	LoginFn   func(ctx context.Context, p config.Profile, n func(string)) (*tokenstore.Tokens, error)
	RefreshFn func(ctx context.Context, server, rt string) (*tokenstore.Tokens, error)
	RevokeFn  func(ctx context.Context, server, token string) error
	Now       func() time.Time

	mu      sync.Mutex
	locks   map[string]*sync.Mutex
	clients map[string]*tmi.APIClient
}

// New returns a Manager wired to auth's real Login/Refresh/Revoke and
// time.Now.
func New(cfg *config.Config, store TokenStore, defaultProfile string) *Manager {
	return &Manager{
		Cfg:       cfg,
		Store:     store,
		Default:   defaultProfile,
		LoginFn:   auth.Login,
		RefreshFn: auth.Refresh,
		RevokeFn:  auth.Revoke,
		Now:       time.Now,
		locks:     map[string]*sync.Mutex{},
		clients:   map[string]*tmi.APIClient{},
	}
}

// Profile resolves name to a config.Profile: "" falls back to m.Default,
// then to the config's default profile.
func (m *Manager) Profile(name string) (config.Profile, error) {
	if name == "" {
		name = m.Default
	}
	return m.Cfg.Resolve(name)
}

func noop(string) {}

// lockFor returns the per-profile mutex, creating it if needed.
func (m *Manager) lockFor(name string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[name]
	if !ok {
		l = &sync.Mutex{}
		m.locks[name] = l
	}
	return l
}

// client returns the cached *tmi.APIClient for p, creating it if needed.
func (m *Manager) client(p config.Profile) *tmi.APIClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[p.Name]
	if !ok {
		c = auth.NewAPIClient(p.Server)
		m.clients[p.Name] = c
	}
	return c
}

// token returns a valid access token for p, holding the per-profile lock for
// the whole acquire so concurrent callers share one login/refresh.
func (m *Manager) token(ctx context.Context, p config.Profile, n Notify, forceRefresh bool) (*tokenstore.Tokens, error) {
	lock := m.lockFor(p.Name)
	lock.Lock()
	defer lock.Unlock()

	tok, err := m.Store.Load(p.Name)
	if err != nil {
		return nil, fmt.Errorf("load tokens for profile %s: %w", p.Name, err)
	}
	if tok != nil && !forceRefresh && tok.Valid(m.Now()) {
		return tok, nil
	}
	if tok != nil && tok.RefreshToken != "" {
		refreshed, err := m.RefreshFn(ctx, p.Server, tok.RefreshToken)
		if err == nil {
			if err := m.Store.Save(p.Name, refreshed); err != nil {
				return nil, fmt.Errorf("save refreshed tokens for profile %s: %w", p.Name, err)
			}
			return refreshed, nil
		}
		fmt.Fprintf(os.Stderr, "tmi-mcp: refresh failed for profile %s, falling back to login: %v\n", p.Name, err)
	}

	if n == nil {
		n = noop
	}
	newTok, err := m.LoginFn(ctx, p, n)
	if err != nil {
		return nil, err
	}
	if err := m.Store.Save(p.Name, newTok); err != nil {
		return nil, fmt.Errorf("save tokens for profile %s: %w", p.Name, err)
	}
	return newTok, nil
}

// Call resolves profile, acquires a valid access token, and runs fn. On a
// 401 response it forces a token refresh/login and retries fn once.
func (m *Manager) Call(ctx context.Context, profile string, n Notify, fn CallFunc) (any, error) {
	p, err := m.Profile(profile)
	if err != nil {
		return nil, err
	}

	tok, err := m.token(ctx, p, n, false)
	if err != nil {
		return nil, err
	}
	ctx2 := context.WithValue(ctx, tmi.ContextAccessToken, tok.AccessToken)
	v, resp, err := fn(ctx2, m.client(p))

	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		tok, tokErr := m.token(ctx, p, n, true)
		if tokErr != nil {
			return nil, tokErr
		}
		ctx2 = context.WithValue(ctx, tmi.ContextAccessToken, tok.AccessToken)
		v, resp, err = fn(ctx2, m.client(p))
	}

	if err != nil {
		return nil, auth.AsAPIError(err, resp)
	}
	return v, nil
}

// Login forces an interactive login for profile, overwriting any stored
// tokens without attempting a refresh first.
func (m *Manager) Login(ctx context.Context, profile string, n Notify) error {
	p, err := m.Profile(profile)
	if err != nil {
		return err
	}
	lock := m.lockFor(p.Name)
	lock.Lock()
	defer lock.Unlock()

	if n == nil {
		n = noop
	}
	tok, err := m.LoginFn(ctx, p, n)
	if err != nil {
		return err
	}
	return m.Store.Save(p.Name, tok)
}

// Logout best-effort revokes the stored refresh token, then deletes the
// stored tokens for profile.
func (m *Manager) Logout(ctx context.Context, profile string) error {
	p, err := m.Profile(profile)
	if err != nil {
		return err
	}
	tok, err := m.Store.Load(p.Name)
	if err != nil {
		return fmt.Errorf("load tokens for profile %s: %w", p.Name, err)
	}
	if tok != nil && tok.RefreshToken != "" {
		if err := m.RevokeFn(ctx, p.Server, tok.RefreshToken); err != nil {
			fmt.Fprintf(os.Stderr, "tmi-mcp: revoke failed for profile %s: %v\n", p.Name, err)
		}
	}
	return m.Store.Delete(p.Name)
}
