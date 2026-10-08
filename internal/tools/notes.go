package tools

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

const notesDescription = "Free-text notes scoped to a threat model in TMI. Actions: list (limit, offset), " +
	"get (id), create (fields: name, content required; description), update (id, fields: only the fields to " +
	"change), delete (id)."

func registerNotes(s *mcp.Server, d *Deps) {
	addSubTool(s, d, "notes", notesDescription, subOps{
		list: func(ctx context.Context, c *tmi.APIClient, in SubInput) (any, *http.Response, error) {
			r := c.ThreatModelSubResourcesAPI.GetThreatModelNotes(ctx, in.ThreatModelID)
			if in.Limit != 0 {
				r = r.Limit(in.Limit)
			}
			if in.Offset != 0 {
				r = r.Offset(in.Offset)
			}
			return r.Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelNote(ctx, tm, id).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm string, fields map[string]any) (any, *http.Response, error) {
			v, err := decodeFields[tmi.NoteInput](fields)
			if err != nil {
				return nil, nil, err
			}
			return c.ThreatModelSubResourcesAPI.CreateThreatModelNote(ctx, tm).NoteInput(v).Execute()
		},
		patch: func(ctx context.Context, c *tmi.APIClient, tm, id string, ops []tmi.JsonPatchDocumentInner) (any, *http.Response, error) {
			return c.NotesAPI.PatchThreatModelNote(ctx, tm, id).JsonPatchDocumentInner(ops).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelNote(ctx, tm, id).Execute()
		},
	})
}
