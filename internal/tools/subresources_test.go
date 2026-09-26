package tools

import (
	"encoding/json"
	"net/http"
	"testing"
)

// subCase describes one sub-resource tool for the table test below.
type subCase struct {
	tool     string // MCP tool name
	plural   string // path segment under /threat_models/TM/
	listJSON string // fixture returned for the list action
	itemJSON string // fixture returned for get/create/update
}

var subCases = []subCase{
	{tool: "diagrams", plural: "diagrams", listJSON: listDiagramsJSON, itemJSON: diagramJSON},
	{tool: "assets", plural: "assets", listJSON: listAssetsJSON, itemJSON: assetJSON},
	{tool: "documents", plural: "documents", listJSON: listDocumentsJSON, itemJSON: documentJSON},
	{tool: "notes", plural: "notes", listJSON: listNotesJSON, itemJSON: noteJSON},
	{tool: "repositories", plural: "repositories", listJSON: listRepositoriesJSON, itemJSON: repositoryJSON},
}

// updateCases is subCases minus diagrams: the vendored tmi-clients v1_15_0
// DfdDiagram type embeds BaseDiagram, and Go's method promotion makes
// *_DfdDiagram (the private shadow type its own UnmarshalJSON decodes into)
// pick up BaseDiagram's UnmarshalJSON instead of decoding its own fields.
// That nested decode has DisallowUnknownFields and no "cells" field, so any
// real diagram response (which always has "cells") fails to decode. This is
// a defect in the generated client, not in this tool's code; see
// TestDiagramsUpdateHitsKnownClientDecodeBug below, which pins the current
// (broken) behavior for the PATCH request/response path.
var updateCases = subCases[1:]

func TestSubResourceList(t *testing.T) {
	for _, tc := range subCases {
		t.Run(tc.tool, func(t *testing.T) {
			wantPath := "/threat_models/TM/" + tc.plural
			var gotMethod, gotPath string
			cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.listJSON))
			}))

			v, text, isErr := call(t, cs, tc.tool, map[string]any{
				"action":          "list",
				"threat_model_id": "TM",
			})
			if isErr {
				t.Fatalf("%s", text)
			}
			if gotMethod != http.MethodGet || gotPath != wantPath {
				t.Fatalf("method=%s path=%s", gotMethod, gotPath)
			}
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("result = %v", v)
			}
			if m["total"] != float64(1) {
				t.Fatalf("total = %v", m["total"])
			}
			// compactList keeps every top-level array; find it and check it
			// still has exactly one compacted item.
			var arr []any
			for _, val := range m {
				if a, ok := val.([]any); ok {
					arr = a
				}
			}
			if len(arr) != 1 {
				t.Fatalf("items = %v", arr)
			}
			item, ok := arr[0].(map[string]any)
			if !ok || item["id"] == nil {
				t.Fatalf("item = %v", arr[0])
			}
		})
	}
}

func TestSubResourceUpdate(t *testing.T) {
	for _, tc := range updateCases {
		t.Run(tc.tool, func(t *testing.T) {
			wantPath := "/threat_models/TM/" + tc.plural + "/ID"
			var gotMethod, gotPath string
			var gotBody []map[string]any
			cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.itemJSON))
			}))

			_, text, isErr := call(t, cs, tc.tool, map[string]any{
				"action":          "update",
				"threat_model_id": "TM",
				"id":              "ID",
				"fields":          map[string]any{"name": "NewName"},
			})
			if isErr {
				t.Fatalf("%s", text)
			}
			if gotMethod != http.MethodPatch || gotPath != wantPath {
				t.Fatalf("method=%s path=%s", gotMethod, gotPath)
			}
			if len(gotBody) != 1 || gotBody[0]["op"] != "add" || gotBody[0]["path"] != "/name" || gotBody[0]["value"] != "NewName" {
				t.Fatalf("body = %v", gotBody)
			}
		})
	}
}

// TestDiagramsUpdateHitsKnownClientDecodeBug pins the current behavior of
// the diagrams tool's update action: the request is built and sent
// correctly (right method, path, and JSON Patch body), but decoding any
// realistic response (containing "cells") fails because of the vendored
// tmi-clients v1_15_0 DfdDiagram/BaseDiagram decode defect described on
// updateCases above. If a future client release fixes this, this test will
// fail on the isErr check and should be merged back into TestSubResourceUpdate.
func TestDiagramsUpdateHitsKnownClientDecodeBug(t *testing.T) {
	wantPath := "/threat_models/TM/diagrams/ID"
	var gotMethod, gotPath string
	var gotBody []map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diagramJSON))
	}))

	_, text, isErr := call(t, cs, "diagrams", map[string]any{
		"action":          "update",
		"threat_model_id": "TM",
		"id":              "ID",
		"fields":          map[string]any{"name": "NewName"},
	})
	if gotMethod != http.MethodPatch || gotPath != wantPath {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if len(gotBody) != 1 || gotBody[0]["op"] != "add" || gotBody[0]["path"] != "/name" || gotBody[0]["value"] != "NewName" {
		t.Fatalf("body = %v", gotBody)
	}
	if !isErr {
		t.Fatalf("expected the known client decode bug to surface as a tool error, got success: %s", text)
	}
}

func TestSubResourceDelete(t *testing.T) {
	for _, tc := range subCases {
		t.Run(tc.tool, func(t *testing.T) {
			wantPath := "/threat_models/TM/" + tc.plural + "/ID"
			var gotMethod, gotPath string
			cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				w.WriteHeader(http.StatusNoContent)
			}))

			v, text, isErr := call(t, cs, tc.tool, map[string]any{
				"action":          "delete",
				"threat_model_id": "TM",
				"id":              "ID",
			})
			if isErr {
				t.Fatalf("%s", text)
			}
			if gotMethod != http.MethodDelete || gotPath != wantPath {
				t.Fatalf("method=%s path=%s", gotMethod, gotPath)
			}
			m, ok := v.(map[string]any)
			if !ok || m["deleted"] != "ID" {
				t.Fatalf("result = %v", v)
			}
		})
	}
}

func TestDiagramsGetModel(t *testing.T) {
	wantPath := "/threat_models/TM/diagrams/D/model"
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minimalDiagramModelJSON))
	}))

	v, text, isErr := call(t, cs, "diagrams", map[string]any{
		"action":          "get_model",
		"threat_model_id": "TM",
		"id":              "D",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodGet || gotPath != wantPath {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	m, ok := v.(map[string]any)
	if !ok || m["id"] != "dg-1" {
		t.Fatalf("result = %v", v)
	}
}
