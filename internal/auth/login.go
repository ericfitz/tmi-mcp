package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
	"github.com/ericfitz/tmi-mcp/internal/config"
	"github.com/ericfitz/tmi-mcp/internal/tokenstore"
)

// LoginTimeout bounds the interactive login. Tests shorten it.
var LoginTimeout = 2 * time.Minute

// NewPKCE generates a PKCE verifier/challenge pair per RFC 7636: a 32-byte
// random verifier (base64url, no padding) and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type callbackResult struct {
	code string
	err  error
}

// errorPage renders the callback error page. errVal and desc come straight
// from the IdP redirect's query string, so both are HTML-escaped.
func errorPage(errVal, desc string) string {
	msg := html.EscapeString(errVal)
	if desc != "" {
		msg += ": " + html.EscapeString(desc)
	}
	return fmt.Sprintf("<html><body><h3>login failed: %s</h3></body></html>", msg)
}

// Login performs a PKCE loopback login for profile p, opening the user's
// browser to the TMI authorize endpoint and receiving the resulting
// authorization code on a local HTTP callback server. notify is called with
// human-readable progress messages (e.g. for surfacing to an MCP client).
func Login(ctx context.Context, p config.Profile, notify func(msg string)) (*tokenstore.Tokens, error) {
	server := strings.TrimRight(p.Server, "/")

	addr := "127.0.0.1:0"
	if p.CallbackPort != 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", p.CallbackPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if p.CallbackPort != 0 {
			return nil, fmt.Errorf("cannot listen on %s for the login callback (profile %s): %w; free the port or change callback_port",
				addr, p.Name, err)
		}
		return nil, fmt.Errorf("start loopback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	verifier, challenge, err := NewPKCE()
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	state, err := randomState()
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate state: %w", err)
	}

	q := url.Values{}
	if p.IDP != "" {
		q.Set("idp", p.IDP)
	}
	q.Set("client_callback", callback)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("scope", "openid profile email")
	if p.LoginHint != "" {
		q.Set("login_hint", p.LoginHint)
	}
	authURL := server + "/oauth2/authorize?" + q.Encode()

	if err := preflightAuthorize(ctx, authURL, server, p); err != nil {
		_ = ln.Close()
		return nil, err
	}

	result := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			// A stray or stale hit (e.g. a retried browser request, or noise
			// from an unrelated client) must not abort a login still waiting
			// for the real callback.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body><h3>state mismatch</h3></body></html>")
			return
		}
		var res callbackResult
		switch {
		case q.Get("error") != "":
			errVal, desc := q.Get("error"), q.Get("error_description")
			if desc != "" {
				res.err = fmt.Errorf("login failed: %s: %s", errVal, desc)
			} else {
				res.err = fmt.Errorf("login failed: %s", errVal)
			}
			_, _ = io.WriteString(w, errorPage(errVal, desc))
		case q.Get("code") == "":
			res.err = errors.New("login callback carried no authorization code")
			_, _ = io.WriteString(w, "<html><body><h3>login callback carried no authorization code</h3></body></html>")
		default:
			res.code = q.Get("code")
			_, _ = io.WriteString(w, "<html><body><h3>TMI login complete. You can close this tab.</h3></body></html>")
		}
		select {
		case result <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()

	notify(fmt.Sprintf("Opening browser for TMI login (profile %s)…", p.Name))
	fmt.Fprintf(os.Stderr, "tmi-mcp: open this URL to log in: %s\n", authURL)
	if err := OpenBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "tmi-mcp: failed to open browser automatically: %v\n", err)
	}

	var res callbackResult
	select {
	case res = <-result:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(LoginTimeout):
		return nil, fmt.Errorf("TMI login timed out after %s (profile %s)", LoginTimeout, p.Name)
	}
	if res.err != nil {
		return nil, res.err
	}

	req := tmi.NewExchangeOAuthCodeRequest("authorization_code")
	req.SetCode(res.code)
	req.SetCodeVerifier(verifier)
	req.SetRedirectUri(callback)
	req.SetState(state)
	call := NewAPIClient(server).AuthenticationAPI.ExchangeOAuthCode(ctx).ExchangeOAuthCodeRequest(*req)
	if p.IDP != "" {
		call = call.Idp(p.IDP)
	}
	tok, resp, err := call.Execute()
	if err != nil {
		return nil, AsAPIError(err, resp)
	}
	return &tokenstore.Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}, nil
}

// preflightAuthorize checks the authorize URL for a client_callback
// allowlist rejection before opening the browser, so a misconfigured server
// fails fast instead of leaving the user staring at an error page.
func preflightAuthorize(ctx context.Context, authURL, server string, p config.Profile) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("preflight authorize request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "allowlist") {
		if p.CallbackPort != 0 {
			return fmt.Errorf(`TMI rejected the login callback: add "http://127.0.0.1:%d/*" to auth.oauth.client_callback_allowlist on %s`,
				p.CallbackPort, server)
		}
		return fmt.Errorf(`TMI rejected the login callback: set callback_port (e.g. 8765) on profile %s and add "http://127.0.0.1:8765/*" to auth.oauth.client_callback_allowlist on %s`,
			p.Name, server)
	}
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode, Body: body}
	}
	return nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func Refresh(ctx context.Context, server, refreshToken string) (*tokenstore.Tokens, error) {
	req := tmi.TokenRefreshRequest{}
	req.SetRefreshToken(refreshToken)
	tok, resp, err := NewAPIClient(server).AuthenticationAPI.RefreshToken(ctx).TokenRefreshRequest(req).Execute()
	if err != nil {
		return nil, AsAPIError(err, resp)
	}
	newRefresh := tok.RefreshToken
	if newRefresh == "" {
		newRefresh = refreshToken
	}
	return &tokenstore.Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: newRefresh,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}, nil
}

// Revoke revokes token (RFC 7009) against server, authenticating the revoke
// request itself with accessToken: the TMI revoke handler requires either a
// Bearer access token or client_id/client_secret on the request, separate
// from the token being revoked.
func Revoke(ctx context.Context, server, accessToken, token string) error {
	server = strings.TrimRight(server, "/")
	ctx = context.WithValue(ctx, tmi.ContextAccessToken, accessToken)
	_, resp, err := NewAPIClient(server).AuthenticationAPI.RevokeToken(ctx).Token(token).TokenTypeHint("refresh_token").Execute()
	if err != nil {
		return AsAPIError(err, resp)
	}
	return nil
}
