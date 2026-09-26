package tools

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

// OrgInput is the input for every org-scoped resource tool (projects, teams).
type OrgInput struct {
	Action  string         `json:"action" jsonschema:"one of: list, get, create, update, delete"`
	Profile string         `json:"profile,omitempty" jsonschema:"config profile; omit for the default"`
	ID      string         `json:"id,omitempty" jsonschema:"resource UUID (get, update, delete)"`
	Fields  map[string]any `json:"fields,omitempty" jsonschema:"create: the new object; update: only the fields to change"`
	Limit   int32          `json:"limit,omitempty" jsonschema:"list page size"`
	Offset  int32          `json:"offset,omitempty" jsonschema:"list offset"`
	Name    string         `json:"name,omitempty" jsonschema:"list filter: name"`
	Status  string         `json:"status,omitempty" jsonschema:"list filter: status"`
}

// orgOps wires an org-scoped tool's actions to generated-client calls. It
// mirrors subOps (subresource.go) minus the threat-model ID.
type orgOps struct {
	list   func(ctx context.Context, c *tmi.APIClient, in OrgInput) (any, *http.Response, error)
	get    func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error)
	create func(ctx context.Context, c *tmi.APIClient, fields map[string]any) (any, *http.Response, error)
	patch  func(ctx context.Context, c *tmi.APIClient, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error)
	del    func(ctx context.Context, c *tmi.APIClient, id string) (*http.Response, error)
}

// addOrgTool registers a tool named name that dispatches OrgInput.Action to ops.
func addOrgTool(s *mcp.Server, d *Deps, name, description string, ops orgOps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        name,
		Description: description,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in OrgInput) (*mcp.CallToolResult, any, error) {
		switch in.Action {
		case "list":
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
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
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.get(ctx, c, in.ID)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "create":
			if len(in.Fields) == 0 {
				return nil, nil, toolErr(errRequiresFields(in.Action))
			}
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.create(ctx, c, in.Fields)
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
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.patch(ctx, c, in.ID, patchDocs)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "delete":
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
			_, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				resp, err := ops.del(ctx, c, in.ID)
				return nil, resp, err
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, map[string]any{"deleted": in.ID}, nil

		default:
			return nil, nil, fmt.Errorf("unknown action %q; valid actions: list, get, create, update, delete", in.Action)
		}
	})
}

const projectsDescription = "Projects in TMI. Actions: list (filters: name, status, limit, offset), get (id), " +
	"create (fields: name, team_id required; description, status, ...), update (id, fields: only the fields to " +
	"change), delete (id)."

func registerProjects(s *mcp.Server, d *Deps) {
	addOrgTool(s, d, "projects", projectsDescription, orgOps{
		list: func(ctx context.Context, c *tmi.APIClient, in OrgInput) (any, *http.Response, error) {
			r := c.ProjectsAPI.ListProjects(ctx)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			if in.Name != "" {
				r = r.Name(in.Name)
			}
			if in.Status != "" {
				r = r.Status(in.Status)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, id string) (any, *http.Response, error) {
			return c.ProjectsAPI.GetProject(ctx, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.ProjectInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ProjectsAPI.CreateProject(ctx).ProjectInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.ProjectsAPI.PatchProject(ctx, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, id string) (*http.Response, error) {
			return c.ProjectsAPI.DeleteProject(ctx, id).Execute()
		},
	})
}
