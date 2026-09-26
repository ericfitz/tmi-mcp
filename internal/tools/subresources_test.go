package tools

import (
	"encoding/json"
	"net/http"
	"testing"
)

// subCase describes one sub-resource tool for the table test below.
type subCase struct {
	tool         string         // MCP tool name
	plural       string         // path segment under /threat_models/TM/
	listJSON     string         // fixture returned for the list action
	itemJSON     string         // fixture returned for get/create/update
	createFields map[string]any // fields for the create action; must satisfy the tool's required-field set
}

var subCases = []subCase{
	{tool: "diagrams", plural: "diagrams", listJSON: listDiagramsJSON, itemJSON: diagramJSON,
		createFields: map[string]any{"name": "NewDiagram", "type": "DFD"}},
	{tool: "assets", plural: "assets", listJSON: listAssetsJSON, itemJSON: assetJSON,
		createFields: map[string]any{"name": "NewAsset", "type": "software"}},
	{tool: "documents", plural: "documents", listJSON: listDocumentsJSON, itemJSON: documentJSON,
		createFields: map[string]any{"name": "NewDocument", "uri": "https://example.com/doc"}},
	{tool: "notes", plural: "notes", listJSON: listNotesJSON, itemJSON: noteJSON,
		createFields: map[string]any{"name": "NewNote", "content": "note text"}},
	{tool: "repositories", plural: "repositories", listJSON: listRepositoriesJSON, itemJSON: repositoryJSON,
		createFields: map[string]any{"uri": "https://github.com/example/repo"}},
}

// TestSubResourceCreate covers dispatch's "create" action (dispatch.go) for
// every threat-model-scoped resource tool: it must POST to
// /threat_models/TM/<plural> with a body carrying the fields given, and
// return the created item on success.
func TestSubResourceCreate(t *testing.T) {
	for _, tc := range subCases {
		t.Run(tc.tool, func(t *testing.T) {
			wantPath := "/threat_models/TM/" + tc.plural
			var gotMethod, gotPath string
			var gotBody map[string]any
			cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.itemJSON))
			}))

			_, text, isErr := call(t, cs, tc.tool, map[string]any{
				"action":          "create",
				"threat_model_id": "TM",
				"fields":          tc.createFields,
			})
			if isErr {
				t.Fatalf("%s", text)
			}
			if gotMethod != http.MethodPost || gotPath != wantPath {
				t.Fatalf("method=%s path=%s", gotMethod, gotPath)
			}
			for k, want := range tc.createFields {
				if got := gotBody[k]; got != want {
					t.Fatalf("body[%q] = %v, want %v (body = %v)", k, got, want, gotBody)
				}
			}
		})
	}
}

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
	for _, tc := range subCases {
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

// TestDiagramsGet exercises the "get" action end to end through the typed
// DfdDiagram decode (diagramJSON carries a real node and edge cell, not an
// empty cells array): it must return the diagram JSON, including "cells".
// TestDfdDiagramDecodesTypedWithRealCells (common_test.go) proves this
// decode succeeds without rawOnDecodeErr's help.
func TestDiagramsGet(t *testing.T) {
	wantPath := "/threat_models/TM/diagrams/D"
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diagramJSON))
	}))

	v, text, isErr := call(t, cs, "diagrams", map[string]any{
		"action":          "get",
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
	if _, ok := m["cells"]; !ok {
		t.Fatalf("cells missing from result: %v", m)
	}
}

// TestDiagramsUpdateReturnsFullDiagram is the diagrams-specific half of
// TestDiagramsGet: it must send the right PATCH request AND return the full
// diagram JSON, including "cells", via the same typed DfdDiagram decode.
func TestDiagramsUpdateReturnsFullDiagram(t *testing.T) {
	wantPath := "/threat_models/TM/diagrams/ID"
	var gotMethod, gotPath string
	var gotBody []map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diagramJSON))
	}))

	v, text, isErr := call(t, cs, "diagrams", map[string]any{
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
	m, ok := v.(map[string]any)
	if !ok || m["id"] != "dg-1" {
		t.Fatalf("result = %v", v)
	}
	if _, ok := m["cells"]; !ok {
		t.Fatalf("cells missing from result: %v", m)
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
