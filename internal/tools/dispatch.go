package tools

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

// boundOps is subOps (subresource.go) or orgOps (projects.go) with any
// resource scoping (e.g. a threat model ID) already closed over, so dispatch
// itself needs no knowledge of SubInput, OrgInput, or scoping at all.
type boundOps struct {
	list   func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error)
	get    func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error)
	create func(ctx context.Context, c *tmi.APIClient, fields map[string]any) (any, *http.Response, error)
	patch  func(ctx context.Context, c *tmi.APIClient, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error)
	del    func(ctx context.Context, c *tmi.APIClient, id string) (*http.Response, error)
	// extra holds additional named actions (e.g. "get_model"); extra actions require id.
	extra map[string]func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error)
}

// validActionsFor lists the base list/get/create/update/delete actions plus
// ops.extra's keys, sorted, for the unknown-action error.
func validActionsFor(ops boundOps) string {
	actions := []string{"list", "get", "create", "update", "delete"}
	extras := make([]string, 0, len(ops.extra))
	for k := range ops.extra {
		extras = append(extras, k)
	}
	sort.Strings(extras)
	return strings.Join(append(actions, extras...), ", ")
}

// dispatch runs one resource tool call — list, get, create, update (JSON
// Patch built from fields), delete, or one of ops.extra — against ops. id
// and fields are the call's own arguments; any resource scoping (e.g. a
// threat model ID) must already be bound into ops's closures by the caller:
// addSubTool (subresource.go) binds ThreatModelID per call, addOrgTool
// (projects.go) binds nothing.
func dispatch(ctx context.Context, req *mcp.CallToolRequest, d *Deps, action, profile, id string, fields map[string]any, ops boundOps) (*mcp.CallToolResult, any, error) {
	switch action {
	case "list":
		v, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return ops.list(ctx, c)
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		out, err := compactList(v)
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, out, nil

	case "get":
		if err := need(action, "id", id); err != nil {
			return nil, nil, toolErr(err)
		}
		v, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return ops.get(ctx, c, id)
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, v, nil

	case "create":
		if len(fields) == 0 {
			return nil, nil, toolErr(errRequiresFields(action))
		}
		v, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return ops.create(ctx, c, fields)
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, v, nil

	case "update":
		if err := need(action, "id", id); err != nil {
			return nil, nil, toolErr(err)
		}
		if len(fields) == 0 {
			return nil, nil, toolErr(errRequiresFields(action))
		}
		patchDocs, err := patchOps(fields)
		if err != nil {
			return nil, nil, toolErr(err)
		}
		v, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return ops.patch(ctx, c, id, patchDocs)
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, v, nil

	case "delete":
		if err := need(action, "id", id); err != nil {
			return nil, nil, toolErr(err)
		}
		_, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			resp, err := ops.del(ctx, c, id)
			return nil, resp, err
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, map[string]any{"deleted": id}, nil

	default:
		extra, ok := ops.extra[action]
		if !ok {
			return nil, nil, fmt.Errorf("unknown action %q; valid actions: %s", action, validActionsFor(ops))
		}
		if err := need(action, "id", id); err != nil {
			return nil, nil, toolErr(err)
		}
		v, err := d.call(ctx, req, profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
			return extra(ctx, c, id)
		})
		if err != nil {
			return nil, nil, toolErr(err)
		}
		return nil, v, nil
	}
}
