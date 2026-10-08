package tools

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

// SubInput is the input for every threat-model-scoped resource tool.
type SubInput struct {
	Action        string         `json:"action" jsonschema:"one of: list, get, create, update, delete (diagrams also: get_model)"`
	Profile       string         `json:"profile,omitempty" jsonschema:"config profile; omit for the default"`
	ThreatModelID string         `json:"threat_model_id" jsonschema:"threat model UUID"`
	ID            string         `json:"id,omitempty" jsonschema:"resource UUID (get, update, delete, get_model)"`
	Fields        map[string]any `json:"fields,omitempty" jsonschema:"create: the new object; update: only the fields to change"`
	Limit         int32          `json:"limit,omitempty" jsonschema:"list page size"`
	Offset        int32          `json:"offset,omitempty" jsonschema:"list offset"`
}

// subOps wires a sub-resource tool's actions to generated-client calls.
type subOps struct {
	list   func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error)
	get    func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error)
	create func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error)
	patch  func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error)
	del    func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error)
	// extra holds additional named actions (e.g. "get_model"); extra actions require id.
	extra map[string]func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error)
}

// errRequiresFields reports that action needs a non-empty fields map.
func errRequiresFields(action string) error {
	return fmt.Errorf("action %q requires fields", action)
}

// addSubTool registers a tool named name that dispatches SubInput.Action to
// ops. It validates threat_model_id first, then binds it into every
// closure and hands off to the shared dispatch (dispatch.go).
func addSubTool(s *mcp.Server, d *Deps, name, description string, ops subOps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        name,
		Description: description,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in SubInput) (*mcp.CallToolResult, any, error) {
		if err := need(in.Action, "threat_model_id", in.ThreatModelID); err != nil {
			return nil, nil, toolErr(err)
		}

		bound := boundOps{
			list: func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.list(ctx, c, in)
			},
			get: func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error) {
				return ops.get(ctx, c, in.ThreatModelID, id)
			},
			create: func(ctx context.Context, c *tmi.APIClient, fields map[string]any) (any, *http.Response, error) {
				return ops.create(ctx, c, in.ThreatModelID, fields)
			},
			patch: func(ctx context.Context, c *tmi.APIClient, id string, patchDocs []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
				return ops.patch(ctx, c, in.ThreatModelID, id, patchDocs)
			},
			del: func(ctx context.Context, c *tmi.APIClient, id string) (*http.Response, error) {
				return ops.del(ctx, c, in.ThreatModelID, id)
			},
		}
		if len(ops.extra) > 0 {
			bound.extra = make(map[string]func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error), len(ops.extra))
			for action, fn := range ops.extra {
				bound.extra[action] = func(ctx context.Context, c *tmi.APIClient, _ string) (any, *http.Response, error) {
					return fn(ctx, c, in)
				}
			}
		}

		return dispatch(ctx, req, d, in.Action, in.Profile, in.ID, in.Fields, bound)
	})
}
