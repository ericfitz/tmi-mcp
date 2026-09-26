package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0"
)

const diagramsDescription = "Data flow diagrams scoped to a threat model in TMI. Actions: list (limit, offset), " +
	"get (id), create (fields: name, type required), update (id, fields: only the fields to change, including " +
	"cells to edit the diagram's nodes and edges), delete (id), get_model (id: returns a compact model of the " +
	"diagram's nodes and edges)."

func registerDiagrams(s *mcp.Server, d *Deps) {
	addSubTool(s, d, "diagrams", diagramsDescription, subOps{
		list: func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
			r := c.ThreatModelSubResourcesAPI.GetThreatModelDiagrams(ctx, in.ThreatModelID)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelDiagram(ctx, tm, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.CreateDiagramRequest](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ThreatModelSubResourcesAPI.CreateThreatModelDiagram(ctx, tm).CreateDiagramRequest(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.PatchThreatModelDiagram(ctx, tm, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelDiagram(ctx, tm, id).Execute()
		},
		extra: map[string]func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error){
			"get_model": func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
				return c.ThreatModelSubResourcesAPI.GetDiagramModel(ctx, in.ThreatModelID, in.ID).Execute()
			},
		},
	})
}
