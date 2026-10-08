// Package auth implements PKCE loopback login, token refresh, and revocation
// against the TMI server, plus construction of the generated TMI API client.
package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

// NewAPIClient returns a generated TMI client pointed at server (any trailing
// slash trimmed).
func NewAPIClient(server string) *tmi.APIClient {
	cfg := tmi.NewConfiguration()
	cfg.Servers = tmi.ServerConfigurations{{URL: strings.TrimRight(server, "/")}}
	cfg.UserAgent = "tmi-mcp"
	return tmi.NewAPIClient(cfg)
}

// APIError is a non-2xx response from the TMI server.
type APIError struct {
	Status int
	Body   []byte
}

func (e *APIError) Error() string {
	body := e.Body
	if len(body) > 500 {
		body = body[:500]
	}
	return fmt.Sprintf("TMI returned %d: %s", e.Status, body)
}

// AsAPIError converts a generated-client error plus its response into an
// *APIError when resp is non-nil and indicates a non-2xx status. Otherwise it
// returns err unchanged.
func AsAPIError(err error, resp *http.Response) error {
	if resp == nil || resp.StatusCode < 300 {
		return err
	}
	var body []byte
	var genErr *tmi.GenericOpenAPIError
	if errors.As(err, &genErr) {
		body = genErr.Body()
	} else {
		var genErrVal tmi.GenericOpenAPIError
		if errors.As(err, &genErrVal) {
			body = genErrVal.Body()
		}
	}
	return &APIError{Status: resp.StatusCode, Body: body}
}
