package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/tmi-mcp/internal/config"
)

type fakeTMI struct {
	*httptest.Server
	challenge   string
	rejectCB    bool
	denied      bool
	tokenCalls  atomic.Int32
	gotCallback string
}

func newFake(t *testing.T) *fakeTMI {
	f := &fakeTMI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if f.rejectCB {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"invalid_request","error_description":"client_callback is not in the allowlist"}`)
			return
		}
		if q.Get("code_challenge_method") != "S256" || q.Get("scope") != "openid profile email" {
			w.WriteHeader(400)
			return
		}
		f.challenge = q.Get("code_challenge")
		cb := q.Get("client_callback")
		f.gotCallback = cb
		if f.denied {
			http.Redirect(w, r, cb+"?error=access_denied&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
			return
		}
		http.Redirect(w, r, cb+"?code=thecode&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		sum := sha256.Sum256([]byte(body["code_verifier"].(string)))
		if body["code"] != "thecode" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"AT","refresh_token":"RT","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		// RFC 7009 form-encodes the revoke request; only accepting a form
		// body here (mirroring the real server) proves the generated client
		// actually sends one instead of an empty JSON body.
		if !strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			w.WriteHeader(400)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("token") == "" {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"invalid_request","error_description":"Missing required 'token' parameter"}`)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("/oauth2/refresh", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["refresh_token"] != "RT" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"AT2","refresh_token":"RT2","token_type":"Bearer","expires_in":3600}`)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// browserFollows simulates a browser: GET the URL and follow redirects to the loopback callback.
func browserFollows(t *testing.T) {
	old := OpenBrowser
	OpenBrowser = func(u string) error {
		go func() {
			resp, err := http.Get(u)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { OpenBrowser = old })
}

func asAPI(err error, target **APIError) bool { return errors.As(err, target) }

func TestPKCE(t *testing.T) {
	v, c, err := NewPKCE()
	if err != nil || len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier %q %v", v, err)
	}
	sum := sha256.Sum256([]byte(v))
	if c != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge mismatch")
	}
}

func TestLoginHappyPath(t *testing.T) {
	f := newFake(t)
	browserFollows(t)
	var notified string
	tok, err := Login(context.Background(), config.Profile{Name: "local", Server: f.URL, IDP: "tmi"}, func(m string) { notified = m })
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "AT" || tok.RefreshToken != "RT" || time.Until(tok.ExpiresAt) < 59*time.Minute {
		t.Fatalf("%+v", tok)
	}
	if !strings.Contains(notified, "local") {
		t.Fatalf("notify: %q", notified)
	}
}

func TestLoginAllowlistRejectedFailsFast(t *testing.T) {
	f := newFake(t)
	f.rejectCB = true
	OpenBrowser = func(string) error { t.Fatal("browser must not open"); return nil }
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })
	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err == nil ||
		!strings.Contains(err.Error(), "client_callback_allowlist") ||
		!strings.Contains(err.Error(), "callback_port") ||
		!strings.Contains(err.Error(), "profile p") ||
		!strings.Contains(err.Error(), "http://127.0.0.1:8765/*") ||
		strings.Contains(err.Error(), "http://127.0.0.1:*\"") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginAllowlistRejectedFailsFastWithCallbackPort(t *testing.T) {
	f := newFake(t)
	f.rejectCB = true
	OpenBrowser = func(string) error { t.Fatal("browser must not open"); return nil }
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })
	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL, CallbackPort: 9999}, func(string) {})
	if err == nil ||
		!strings.Contains(err.Error(), "client_callback_allowlist") ||
		!strings.Contains(err.Error(), "http://127.0.0.1:9999/*") ||
		strings.Contains(err.Error(), "callback_port") {
		t.Fatalf("got %v", err)
	}
}

// TestLoginStateMismatchDoesNotAbortLogin sends a stray callback hit with the
// wrong state before the real one arrives. It must get 400 and must not
// abort the login: the login still completes when the correct callback
// follows (see login.go's callback handler).
func TestLoginStateMismatchDoesNotAbortLogin(t *testing.T) {
	f := newFake(t)
	var strayStatus atomic.Int32
	OpenBrowser = func(u string) error {
		go func() {
			parsed, err := url.Parse(u)
			if err != nil {
				return
			}
			cb := parsed.Query().Get("client_callback")
			if resp, err := http.Get(cb + "?state=wrong-state&code=bogus"); err == nil {
				strayStatus.Store(int32(resp.StatusCode))
				_ = resp.Body.Close()
			}
			resp, err := http.Get(u)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })

	tok, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken != "AT" {
		t.Fatalf("%+v", tok)
	}
	if got := strayStatus.Load(); got != http.StatusBadRequest {
		t.Fatalf("stray callback status = %d, want 400", got)
	}
}

// TestErrorPageEscapesValuesAndIncludesDescription checks the callback error
// page HTML-escapes the error/error_description query values (they come
// straight from the IdP redirect, so are attacker-influenceable) and
// includes the description.
func TestErrorPageEscapesValuesAndIncludesDescription(t *testing.T) {
	got := errorPage("access_denied", "<script>bad</script>")
	if strings.Contains(got, "<script>bad</script>") {
		t.Fatalf("not escaped: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;bad&lt;/script&gt;") {
		t.Fatalf("missing escaped description: %s", got)
	}
}

// TestLoginDeniedIncludesDescription checks Login's returned error includes
// error_description alongside error.
func TestLoginDeniedIncludesDescription(t *testing.T) {
	f := newFake(t)
	OpenBrowser = func(u string) error {
		go func() {
			parsed, err := url.Parse(u)
			if err != nil {
				return
			}
			q := parsed.Query()
			resp, err := http.Get(q.Get("client_callback") + "?error=access_denied&error_description=" +
				url.QueryEscape("user said no") + "&state=" + url.QueryEscape(q.Get("state")))
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })

	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "access_denied") || !strings.Contains(err.Error(), "user said no") {
		t.Fatalf("got %v", err)
	}
}

// TestLoginCallbackEmptyCodeIsError checks a callback with no error and no
// code (a malformed or unexpected redirect) surfaces a specific error
// instead of proceeding to exchange an empty authorization code.
func TestLoginCallbackEmptyCodeIsError(t *testing.T) {
	f := newFake(t)
	OpenBrowser = func(u string) error {
		go func() {
			parsed, err := url.Parse(u)
			if err != nil {
				return
			}
			resp, err := http.Get(parsed.Query().Get("client_callback") + "?state=" + url.QueryEscape(parsed.Query().Get("state")))
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })

	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "no authorization code") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginDenied(t *testing.T) {
	f := newFake(t)
	f.denied = true
	browserFollows(t)
	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
	if f.tokenCalls.Load() != 0 {
		t.Fatal("must not exchange after denial")
	}
}

func TestLoginTimeout(t *testing.T) {
	f := newFake(t)
	OpenBrowser = func(string) error { return nil } // user never completes login
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })
	old := LoginTimeout
	LoginTimeout = 200 * time.Millisecond
	t.Cleanup(func() { LoginTimeout = old })
	_, err := Login(context.Background(), config.Profile{Name: "p", Server: f.URL}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
}

func TestRefresh(t *testing.T) {
	f := newFake(t)
	tok, err := Refresh(context.Background(), f.URL, "RT")
	if err != nil || tok.AccessToken != "AT2" || tok.RefreshToken != "RT2" {
		t.Fatalf("%+v %v", tok, err)
	}
	_, err = Refresh(context.Background(), f.URL, "bad")
	var ae *APIError
	if err == nil || !asAPI(err, &ae) || ae.Status != 401 {
		t.Fatalf("want APIError 401, got %v", err)
	}
}

// freePort returns a port that is free at the time of the call by briefly
// listening on :0 and closing it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestLoginFixedCallbackPort(t *testing.T) {
	f := newFake(t)
	browserFollows(t)
	port := freePort(t)
	tok, err := Login(context.Background(), config.Profile{Name: "local", Server: f.URL, CallbackPort: port}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "AT" {
		t.Fatalf("%+v", tok)
	}
	want := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	if f.gotCallback != want {
		t.Fatalf("client_callback = %q, want %q", f.gotCallback, want)
	}
}

func TestLoginBusyCallbackPortFails(t *testing.T) {
	f := newFake(t)
	port := freePort(t)
	held, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	OpenBrowser = func(string) error { t.Fatal("browser must not open"); return nil }
	t.Cleanup(func() { OpenBrowser = defaultOpenBrowser })

	_, err = Login(context.Background(), config.Profile{Name: "p", Server: f.URL, CallbackPort: port}, func(string) {})
	if err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("127.0.0.1:%d", port)) ||
		!strings.Contains(err.Error(), "profile p") ||
		!strings.Contains(err.Error(), "callback_port") {
		t.Fatalf("got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	f := newFake(t)
	if err := Revoke(context.Background(), f.URL, "RT"); err != nil {
		t.Fatal(err)
	}
	// An empty token is rejected by the generated client's own client-side
	// validation (min length 1) before any request goes out, so this is a
	// plain error rather than an *APIError from the fake server.
	if err := Revoke(context.Background(), f.URL, ""); err == nil {
		t.Fatal("want error for empty token")
	}
}
