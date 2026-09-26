package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

const teamsDescription = "Teams in TMI. Actions: list (filters: name, status, limit, offset), get (id), " +
	"create (fields: name required; description, status, ...), update (id, fields: only the fields to change), " +
	"delete (id)."

func registerTeams(s *mcp.Server, d *Deps) {
	addOrgTool(s, d, "teams", teamsDescription, orgOps{
		list: func(ctx context.Context, c *tmi.APIClient, in OrgInput) (any, *http.Response, error) {
			r := c.TeamsAPI.ListTeams(ctx)
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
			return c.TeamsAPI.GetTeam(ctx, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.TeamInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.TeamsAPI.CreateTeam(ctx).TeamInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.TeamsAPI.PatchTeam(ctx, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, id string) (*http.Response, error) {
			return c.TeamsAPI.DeleteTeam(ctx, id).Execute()
		},
	})
}
