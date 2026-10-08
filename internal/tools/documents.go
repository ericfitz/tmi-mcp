package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

const documentsDescription = "Reference documents scoped to a threat model in TMI. Actions: list (limit, offset), " +
	"get (id), create (fields: name, uri required; description), update (id, fields: only the fields to change), " +
	"delete (id)."

func registerDocuments(s *mcp.Server, d *Deps) {
	addSubTool(s, d, "documents", documentsDescription, subOps{
		list: func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
			r := c.ThreatModelSubResourcesAPI.GetThreatModelDocuments(ctx, in.ThreatModelID)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelDocument(ctx, tm, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.DocumentInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ThreatModelSubResourcesAPI.CreateThreatModelDocument(ctx, tm).DocumentInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.DocumentsAPI.PatchThreatModelDocument(ctx, tm, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelDocument(ctx, tm, id).Execute()
		},
	})
}
