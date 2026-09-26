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

// validActions lists ops' supported actions, for the unknown-action error.
func validActions(ops subOps) string {
	actions := []string{"list", "get", "create", "update", "delete"}
	extras := make([]string, 0, len(ops.extra))
	for k := range ops.extra {
		extras = append(extras, k)
	}
	sort.Strings(extras)
	return strings.Join(append(actions, extras...), ", ")
}

// errRequiresFields reports that action needs a non-empty fields map.
func errRequiresFields(action string) error {
	return fmt.Errorf("action %q requires fields", action)
}

// addSubTool registers a tool named name that dispatches SubInput.Action to ops.
func addSubTool(s *mcp.Server, d *Deps, name, description string, ops subOps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        name,
		Description: description,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in SubInput) (*mcp.CallToolResult, any, error) {
		n := notifier(ctx, req)

		if err := need(in.Action, "threat_model_id", in.ThreatModelID); err != nil {
			return nil, nil, toolErr(err)
		}

		switch in.Action {
		case "list":
			v, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.list(ctx, c, in)
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
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.get(ctx, c, in.ThreatModelID, in.ID)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "create":
			if len(in.Fields) == 0 {
				return nil, nil, toolErr(errRequiresFields(in.Action))
			}
			v, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.create(ctx, c, in.ThreatModelID, in.Fields)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "update":
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
			if len(in.Fields) == 0 {
				return nil, nil, toolErr(errRequiresFields(in.Action))
			}
			patchDocs, err := patchOps(in.Fields)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.patch(ctx, c, in.ThreatModelID, in.ID, patchDocs)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "delete":
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
			_, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				resp, err := ops.del(ctx, c, in.ThreatModelID, in.ID)
				return nil, resp, err
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, map[string]any{"deleted": in.ID}, nil

		default:
			extra, ok := ops.extra[in.Action]
			if !ok {
				return nil, nil, fmt.Errorf("unknown action %q; valid actions: %s", in.Action, validActions(ops))
			}
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.S.Call(ctx, in.Profile, n, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return extra(ctx, c, in)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil
		}
	})
}
