package tools

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

// TMInput is the input for the threat_models tool.
type TMInput struct {
	Action           string         `json:"action" jsonschema:"one of: list, get, create, update"`
	Profile          string         `json:"profile,omitempty" jsonschema:"config profile; omit for the default"`
	ID               string         `json:"id,omitempty" jsonschema:"threat model UUID (get, update)"`
	Fields           map[string]any `json:"fields,omitempty" jsonschema:"create: the new object; update: only the fields to change"`
	Limit            int32          `json:"limit,omitempty" jsonschema:"list page size"`
	Offset           int32          `json:"offset,omitempty" jsonschema:"list offset"`
	Name             string         `json:"name,omitempty" jsonschema:"list filter: name"`
	Owner            string         `json:"owner,omitempty" jsonschema:"list filter: owner"`
	Status           string         `json:"status,omitempty" jsonschema:"list filter: status"`
	SecurityReviewer string         `json:"security_reviewer,omitempty" jsonschema:"list filter: security_reviewer"`
}

func registerThreatModels(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "threat_models",
		Description: "Threat models in TMI. Actions: list (filters: name, owner, status, security_reviewer, limit, offset), get (id), create (fields: name required; description, threat_model_framework, issue_uri, ...), update (id, fields: only the fields to change). There is no delete.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in TMInput) (*mcp.CallToolResult, any, error) {
		switch in.Action {
		case "list":
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				r := c.ThreatModelsAPI.ListThreatModels(ctx)
				if in.Limit != 0 {
					r = r.Limit(in.Limit)
				}
				if in.Offset != 0 {
					r = r.Offset(in.Offset)
				}
				if in.Name != "" {
					r = r.Name(in.Name)
				}
				if in.Owner != "" {
					r = r.Owner(in.Owner)
				}
				if in.Status != "" {
					r = r.Status([]string{in.Status})
				}
				if in.SecurityReviewer != "" {
					r = r.SecurityReviewer(in.SecurityReviewer)
				}
				return r.Execute()
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
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return c.ThreatModelsAPI.GetThreatModel(ctx, in.ID).Execute()
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "create":
			if len(in.Fields) == 0 {
				return nil, nil, toolErr(errRequiresFields(in.Action))
			}
			tmInput, err := decodeFields[tmi.ThreatModelInput](in.Fields)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return c.ThreatModelsAPI.CreateThreatModel(ctx).ThreatModelInput(tmInput).Execute()
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
			ops, err := patchOps(in.Fields)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return c.ThreatModelsAPI.PatchThreatModel(ctx, in.ID).JsonPatchDocumentInner(ops).Execute()
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		default:
			return nil, nil, fmt.Errorf("unknown action %q; valid actions: list, get, create, update", in.Action)
		}
	})
}
