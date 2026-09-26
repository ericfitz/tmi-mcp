package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

const assetsDescription = "Assets (systems, data stores, etc.) scoped to a threat model in TMI. Actions: " +
	"list (limit, offset), get (id), create (fields: name, type required; description, criticality, " +
	"classification, sensitivity), update (id, fields: only the fields to change), delete (id)."

func registerAssets(s *mcp.Server, d *Deps) {
	addSubTool(s, d, "assets", assetsDescription, subOps{
		list: func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
			r := c.ThreatModelSubResourcesAPI.GetThreatModelAssets(ctx, in.ThreatModelID)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelAsset(ctx, tm, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.AssetInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ThreatModelSubResourcesAPI.CreateThreatModelAsset(ctx, tm).AssetInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.AssetsAPI.PatchThreatModelAsset(ctx, tm, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelAsset(ctx, tm, id).Execute()
		},
	})
}
