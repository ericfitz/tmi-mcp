// Package tools implements the MCP tools exposed by tmi-mcp: a thin layer
// translating MCP tool calls into calls against the TMI API through a
// session.Manager.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// hintFor returns a user-facing hint for a TMI API error status, or "" if
// none applies.
func hintFor(status int) string {
	switch status {
	case 401:
		return "authentication failed after retry; run the auth tool with action=login"
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
		errName = strings.TrimSpace(string(ae.Body))
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
