package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

const threatsDescription = "Threats scoped to a threat model in TMI. Actions: list (limit, offset), get (id), " +
	"create (fields: name required; threat_type array required, may be empty; description, severity, priority, " +
	"status, mitigation, mitigated, score, diagram_id, cell_id, asset_id), update (id, fields: only the fields " +
	"to change), delete (id). TMI rejects name, description, and mitigation text that looks like HTML or " +
	"template injection: an identifier followed by '=' (e.g. 'version = 2'), 'javascript:', '{{', '}}', '${', " +
	"'<%', '%>', '#{'. Rephrase such text (e.g. 'version 2')."

func registerThreats(s *mcp.Server, d *Deps) {
	addSubTool(s, d, "threats", threatsDescription, subOps{
		list: func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
			r := c.ThreatModelSubResourcesAPI.GetThreatModelThreats(ctx, in.ThreatModelID)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelThreat(ctx, tm, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.ThreatInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ThreatModelSubResourcesAPI.CreateThreatModelThreat(ctx, tm).ThreatInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.PatchThreatModelThreat(ctx, tm, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelThreat(ctx, tm, id).Execute()
		},
	})
}
