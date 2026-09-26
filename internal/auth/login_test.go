package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	challenge  string
	rejectCB   bool
	denied     bool
	tokenCalls atomic.Int32
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
		// Mirrors the real server (auth/handlers_revocation.go RevokeToken):
		// JSON content type binds strictly; anything else is form-bound.
		var tok string
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(400)
				return
			}
			tok, _ = body["token"].(string)
		} else {
			_ = r.ParseForm()
			tok = r.Form.Get("token")
		}
		if tok == "" {
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
	if err == nil || !strings.Contains(err.Error(), "client_callback_allowlist") || !strings.Contains(err.Error(), "http://127.0.0.1:*") {
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

func TestRevoke(t *testing.T) {
	f := newFake(t)
	if err := Revoke(context.Background(), f.URL, "RT"); err != nil {
		t.Fatal(err)
	}
	err := Revoke(context.Background(), f.URL, "")
	var ae *APIError
	if err == nil || !asAPI(err, &ae) || ae.Status != 400 {
		t.Fatalf("want APIError 400, got %v", err)
	}
}
