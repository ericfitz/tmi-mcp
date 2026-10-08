package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
	"github.com/ericfitz/tmi-mcp/internal/auth"
)

const metadataDescription = "Key-value metadata attached to a TMI resource. Actions: list, get (key), " +
	"set (key, value), delete (key). target: threat_model, threat, diagram, asset, document, note, repository " +
	"(threat_model needs no id; every other target requires id)."

// MetaInput is the input for the metadata tool.
type MetaInput struct {
	Action        string `json:"action" jsonschema:"one of: list, get, set, delete"`
	Profile       string `json:"profile,omitempty" jsonschema:"config profile; omit for the default"`
	Target        string `json:"target" jsonschema:"one of: threat_model, threat, diagram, asset, document, note, repository"`
	ThreatModelID string `json:"threat_model_id" jsonschema:"threat model UUID"`
	ID            string `json:"id,omitempty" jsonschema:"resource UUID (required unless target=threat_model)"`
	Key           string `json:"key,omitempty" jsonschema:"metadata key (get, set, delete)"`
	Value         string `json:"value,omitempty" jsonschema:"metadata value (set)"`
}

// metaOps wires one metadata target's actions to generated-client calls. id
// is unused (empty) for the threat_model target.
type metaOps struct {
	list   func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error)
	get    func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error)
	update func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error)
	create func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error)
	del    func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error)
}

// metaTargets dispatches the metadata tool's target to generated-client
// calls. "set" always tries update (PUT by key) first: the TMI server's
// PUT-by-key handler is a pure SQL UPDATE (api/metadata_repository.go
// GormMetadataRepository.Update) that returns 404 when the key doesn't
// exist yet rather than upserting, so a first-time set falls back to the
// matching Create (POST) call.
var metaTargets = map[string]metaOps{
	"threat_model": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, _ string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelMetadata(ctx, tm).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, _, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelMetadataByKey(ctx, tm, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, _, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateThreatModelMetadataByKey(ctx, tm, key).
				UpdateThreatMetadataByKeyRequest(tmi.UpdateThreatMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, _, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateThreatModelMetadata(ctx, tm).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, _, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelMetadataByKey(ctx, tm, key).Execute()
		},
	},
	"threat": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateThreatMetadataByKey(ctx, tm, id, key).
				UpdateThreatMetadataByKeyRequest(tmi.UpdateThreatMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateThreatMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatMetadataByKey(ctx, tm, id, key).Execute()
		},
	},
	"diagram": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetDiagramMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetDiagramMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateDiagramMetadataByKey(ctx, tm, id, key).
				UpdateDiagramMetadataByKeyRequest(tmi.UpdateDiagramMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateDiagramMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteDiagramMetadataByKey(ctx, tm, id, key).Execute()
		},
	},
	"asset": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelAssetMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetThreatModelAssetMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateThreatModelAssetMetadata(ctx, tm, id, key).
				Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateThreatModelAssetMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteThreatModelAssetMetadata(ctx, tm, id, key).Execute()
		},
	},
	"document": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetDocumentMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetDocumentMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateDocumentMetadataByKey(ctx, tm, id, key).
				UpdateThreatMetadataByKeyRequest(tmi.UpdateThreatMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateDocumentMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteDocumentMetadataByKey(ctx, tm, id, key).Execute()
		},
	},
	"note": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetNoteMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetNoteMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateNoteMetadataByKey(ctx, tm, id, key).
				UpdateThreatMetadataByKeyRequest(tmi.UpdateThreatMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateNoteMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteNoteMetadataByKey(ctx, tm, id, key).Execute()
		},
	},
	"repository": {
		list: func(ctx context.Context, c *tmi.APIClient, tm, id string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetRepositoryMetadata(ctx, tm, id).Execute()
		},
		get: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.GetRepositoryMetadataByKey(ctx, tm, id, key).Execute()
		},
		update: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.UpdateRepositoryMetadataByKey(ctx, tm, id, key).
				UpdateThreatMetadataByKeyRequest(tmi.UpdateThreatMetadataByKeyRequest{Value: value}).Execute()
		},
		create: func(ctx context.Context, c *tmi.APIClient, tm, id, key, value string) (any, *http.Response, error) {
			return c.ThreatModelSubResourcesAPI.CreateRepositoryMetadata(ctx, tm, id).Metadata(*tmi.NewMetadata(key, value)).Execute()
		},
		del: func(ctx context.Context, c *tmi.APIClient, tm, id, key string) (*http.Response, error) {
			return c.ThreatModelSubResourcesAPI.DeleteRepositoryMetadataByKey(ctx, tm, id, key).Execute()
		},
	},
}

// validTargets lists metaTargets' keys, sorted, for the unknown-target error.
func validTargets() string {
	keys := make([]string, 0, len(metaTargets))
	for k := range metaTargets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// isNotFound reports whether err is a *auth.APIError with a 404 status.
func isNotFound(err error) bool {
	var ae *auth.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func registerMetadata(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "metadata",
		Description: metadataDescription,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in MetaInput) (*mcp.CallToolResult, any, error) {
		if err := need(in.Action, "threat_model_id", in.ThreatModelID); err != nil {
			return nil, nil, toolErr(err)
		}
		ops, ok := metaTargets[in.Target]
		if !ok {
			return nil, nil, fmt.Errorf("unknown target %q; valid targets: %s", in.Target, validTargets())
		}
		if in.Target != "threat_model" {
			if err := need(in.Action, "id", in.ID); err != nil {
				return nil, nil, toolErr(err)
			}
		}

		switch in.Action {
		case "list":
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.list(ctx, c, in.ThreatModelID, in.ID)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "get":
			if err := need(in.Action, "key", in.Key); err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.get(ctx, c, in.ThreatModelID, in.ID, in.Key)
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "set":
			if err := need(in.Action, "key", in.Key); err != nil {
				return nil, nil, toolErr(err)
			}
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return ops.update(ctx, c, in.ThreatModelID, in.ID, in.Key, in.Value)
			})
			if isNotFound(err) {
				v, err = d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
					return ops.create(ctx, c, in.ThreatModelID, in.ID, in.Key, in.Value)
				})
			}
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "delete":
			if err := need(in.Action, "key", in.Key); err != nil {
				return nil, nil, toolErr(err)
			}
			_, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				resp, err := ops.del(ctx, c, in.ThreatModelID, in.ID, in.Key)
				return nil, resp, err
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, map[string]any{"deleted": in.Key}, nil

		default:
			return nil, nil, fmt.Errorf("unknown action %q; valid actions: list, get, set, delete", in.Action)
		}
	})
}
