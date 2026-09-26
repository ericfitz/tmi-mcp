// Package tools implements the MCP tools exposed by tmi-mcp: a thin layer
// translating MCP tool calls into calls against the TMI API through a
// session.Manager.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
	"github.com/ericfitz/tmi-mcp/internal/auth"
	"github.com/ericfitz/tmi-mcp/internal/session"
)

// notifier returns a Notify that sends an MCP info log to the calling client
// and echoes to stderr.
func notifier(ctx context.Context, req *mcp.CallToolRequest) session.Notify {
	return func(msg string) {
		//nolint:staticcheck // SA1019: logging is deprecated (SEP-2577) but still functional; this is the SDK's only way to notify the client.
		_ = req.Session.Log(ctx, &mcp.LoggingMessageParams{Level: "info", Logger: "tmi-mcp", Data: msg})
		fmt.Fprintln(os.Stderr, "tmi-mcp:", msg)
	}
}

// patchOps converts fields to JSON Patch "add" ops, sorted by key for
// determinism. It errors if fields is empty.
func patchOps(fields map[string]any) ([]tmi.JsonPatchDocumentInner, error) {
	if len(fields) == 0 {
		return nil, errors.New("no fields to patch")
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ops := make([]tmi.JsonPatchDocumentInner, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, tmi.JsonPatchDocumentInner{Op: "add", Path: "/" + k, Value: fields[k]})
	}
	return ops, nil
}

// decodeFields JSON-round-trips fields into a generated input type T,
// wrapping any decode error so it names the offending field.
func decodeFields[T any](fields map[string]any) (T, error) {
	var out T
	b, err := json.Marshal(fields)
	if err != nil {
		return out, fmt.Errorf("encode fields: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("invalid fields: %w", err)
	}
	return out, nil
}

// compactKeys lists the fields kept for each item of a top-level array when
// compactList trims a list response down to size.
var compactKeys = []string{"id", "name", "key", "value", "status", "severity", "priority", "type", "threat_type", "modified_at"}

// compactList marshals v to JSON, and for every top-level array of objects
// keeps only compactKeys; scalar top-level fields (total, limit, offset) are
// kept as-is.
func compactList(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, val := range m {
		arr, ok := val.([]any)
		if !ok {
			continue
		}
		compacted := make([]any, len(arr))
		for i, item := range arr {
			obj, ok := item.(map[string]any)
			if !ok {
				compacted[i] = item
				continue
			}
			small := map[string]any{}
			for _, ck := range compactKeys {
				if cv, present := obj[ck]; present {
					small[ck] = cv
				}
			}
			compacted[i] = small
		}
		m[k] = compacted
	}
	return m, nil
}

// call runs fn against a session for profile, notifying req's caller, and
// tolerates unknown response fields on every tool via rawOnDecodeErr — every
// generated TMI model decodes with DisallowUnknownFields, so a server newer
// than the vendored client's spec would otherwise make any get/create/update
// fail to decode. This is the single place all tools route session calls
// through; add a new tool by calling this instead of d.S.Call directly.
func (d *Deps) call(ctx context.Context, req *mcp.CallToolRequest, profile string, fn session.CallFunc) (any, error) {
	return d.S.Call(ctx, profile, notifier(ctx, req), func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
		return rawOnDecodeErr(fn(ctx, c))
	})
}

// rawOnDecodeErr returns the raw 2xx response body as json.RawMessage when
// the generated client got a successful HTTP response but failed only to
// decode it into its target Go type. Otherwise it returns v, resp, and err
// unchanged. Every tool's session call is routed through this via d.call, so
// it covers all tools, not just diagrams.
//
// ponytail: works around a decode bug in tmi-clients v1_15_0's DfdDiagram.
// DfdDiagram embeds BaseDiagram and defines its own UnmarshalJSON, which
// decodes into a private shadow type (`_DfdDiagram`). That shadow type has
// no UnmarshalJSON of its own, so Go's method promotion makes it decode via
// the *embedded* BaseDiagram.UnmarshalJSON instead of plain field-by-field
// decoding — which requires "type" and rejects "cells" as unknown, so every
// real diagram response (cells is DfdDiagram's own required field) fails to
// decode. Also doubles as tolerance for a server that adds response fields
// ahead of the vendored client's spec. Delete the DfdDiagram-specific
// reasoning above once tmi-clients is regenerated with the fix; keep the
// helper for the general unknown-field case.
func rawOnDecodeErr(v any, resp *http.Response, err error) (any, *http.Response, error) {
	if err == nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return v, resp, err
	}
	var body []byte
	var pe *tmi.GenericOpenAPIError
	var ve tmi.GenericOpenAPIError
	switch {
	case errors.As(err, &pe):
		body = pe.Body()
	case errors.As(err, &ve):
		body = ve.Body()
	default:
		return v, resp, err
	}
	if len(body) == 0 || !json.Valid(body) {
		return v, resp, err
	}
	return json.RawMessage(body), resp, nil
}

// hintFor returns a user-facing hint for a TMI API error status, or "" if
// none applies.
func hintFor(status int) string {
	switch status {
	case 401:
		return "authentication failed; run the auth tool with action=login"
	case 403:
		return "you do not have access to this resource"
	case 404:
		return "not found; check the IDs"
	case 409, 412:
		return "the resource changed; get it again and retry"
	case 400:
		return "request rejected; check field names and values"
	default:
		return ""
	}
}

// toolErr turns an error into a user-facing error with a hint for
// *auth.APIError statuses. Other errors pass through unchanged.
func toolErr(err error) error {
	var ae *auth.APIError
	if !errors.As(err, &ae) {
		return err
	}
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	_ = json.Unmarshal(ae.Body, &body)

	errName := body.Error
	if errName == "" {
		raw := ae.Body
		if len(raw) > 500 {
			raw = raw[:500]
		}
		errName = strings.TrimSpace(string(raw))
	}
	desc := body.ErrorDescription
	if desc == "" {
		desc = body.Message
	}

	msg := fmt.Sprintf("TMI %d: %s: %s", ae.Status, errName, desc)
	if hint := hintFor(ae.Status); hint != "" {
		msg += "; " + hint
	}
	return errors.New(msg)
}

// need returns an error "action %q requires %s" naming every pairs entry
// (name, value, name, value, ...) whose value is empty. It returns nil if
// none are empty.
func need(action string, pairs ...string) error {
	var missing []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			missing = append(missing, pairs[i])
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("action %q requires %s", action, strings.Join(missing, ", "))
}
