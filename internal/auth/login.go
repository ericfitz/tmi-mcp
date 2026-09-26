package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

// Login performs a PKCE loopback login for profile p, opening the user's
// browser to the TMI authorize endpoint and receiving the resulting
// authorization code on a local HTTP callback server. notify is called with
// human-readable progress messages (e.g. for surfacing to an MCP client).
func Login(ctx context.Context, p config.Profile, notify func(msg string)) (*tokenstore.Tokens, error) {
	server := strings.TrimRight(p.Server, "/")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
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

	if err := preflightAuthorize(ctx, authURL, server); err != nil {
		_ = ln.Close()
		return nil, err
	}

	result := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res callbackResult
		switch {
		case q.Get("state") != state:
			res.err = fmt.Errorf("state mismatch")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body><h3>state mismatch</h3></body></html>")
		case q.Get("error") != "":
			res.err = fmt.Errorf("login failed: %s", q.Get("error"))
			_, _ = io.WriteString(w, fmt.Sprintf("<html><body><h3>login failed: %s</h3></body></html>", q.Get("error")))
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
func preflightAuthorize(ctx context.Context, authURL, server string) error {
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
		return fmt.Errorf(`TMI rejected the login callback: add "http://127.0.0.1:*" to auth.oauth.client_callback_allowlist on %s`, server)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("TMI rejected the login request: %d: %s", resp.StatusCode, body)
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

// Revoke revokes token (RFC 7009) against server.
//
// ponytail: the generated tmi.AuthenticationAPIService.RevokeToken call is
// broken — its Content-Type is forced to "application/json" (selectHeaderContentType
// in the vendored client always prefers json when present in the consumes
// list, ignoring declared order) but it only ever populates url.Values form
// params, never a JSON body, so the real request goes out with an empty body
// and the server's strict JSON binder rejects it with 400 "Missing required
// 'token' parameter" every time (confirmed by a live round trip against a
// no-op httptest server: Content-Type: application/json, Body: ""). This
// posts the RFC 7009 form body by hand instead of going through that call.
// Upgrade path: fix upstream in tmi-clients' OpenAPI codegen (selectHeaderContentType
// should not reorder past the spec's declared consumes order when there is no
// JSON body to send), regenerate, then delete this and call
// AuthenticationAPI.RevokeToken(ctx).Token(token).TokenTypeHint("refresh_token").Execute()
// as originally specified.
func Revoke(ctx context.Context, server, token string) error {
	server = strings.TrimRight(server, "/")
	form := url.Values{"token": {token}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/oauth2/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{Status: resp.StatusCode, Body: body}
	}
	return nil
}
