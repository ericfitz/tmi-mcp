//go:build integration

package auth

import (
	"context"
	"net/http"
	"os"
	"testing"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
	"github.com/ericfitz/tmi-mcp/internal/config"
)

// TestIntegrationLoginRefreshRevoke runs a full login against a real TMI
// server using the dev-only "tmi" identity provider, which redirects
// straight to client_callback (tmi/auth/handlers_oauth.go:202) so no real
// browser is needed — this test follows the redirect itself, the same way
// browserFollows does for the fake server in login_test.go. It then confirms
// the token works (GetCurrentUser), refreshes it, and revokes it.
//
// Skipped unless TMI_MCP_INTEGRATION_SERVER is set, e.g.:
//
//	TMI_MCP_INTEGRATION_SERVER=http://localhost:8080 go test -tags integration -run Integration -v ./internal/auth/
func TestIntegrationLoginRefreshRevoke(t *testing.T) {
	server := os.Getenv("TMI_MCP_INTEGRATION_SERVER")
	if server == "" {
		t.Skip("TMI_MCP_INTEGRATION_SERVER not set")
	}

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

	p := config.Profile{Name: "integration", Server: server, IDP: "tmi", LoginHint: "alice"}
	tok, err := Login(context.Background(), p, func(msg string) { t.Log(msg) })
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("Login returned incomplete tokens: %+v", tok)
	}

	ctx := context.WithValue(context.Background(), tmi.ContextAccessToken, tok.AccessToken)
	if _, _, err := NewAPIClient(server).AuthenticationAPI.GetCurrentUser(ctx).Execute(); err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}

	refreshed, err := Refresh(context.Background(), server, tok.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatalf("Refresh returned incomplete tokens: %+v", refreshed)
	}

	if err := Revoke(context.Background(), server, refreshed.RefreshToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}
