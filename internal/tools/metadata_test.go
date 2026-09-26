package tools

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// metadataJSON is a canned Metadata (required: key, value; see model_metadata.go).
const metadataJSON = `{"key":"k","value":"v"}`

func TestMetadataSetThreatSendsPutWithValue(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(metadataJSON))
	}))

	_, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "set",
		"target":          "threat",
		"threat_model_id": "TM",
		"id":              "T",
		"key":             "k",
		"value":           "v",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodPut || gotPath != "/threat_models/TM/threats/T/metadata/k" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if gotBody["value"] != "v" {
		t.Fatalf("body = %v", gotBody)
	}
}

func TestMetadataListThreatModelHitsMetadataPath(t *testing.T) {
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[` + metadataJSON + `]`))
	}))

	v, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "list",
		"target":          "threat_model",
		"threat_model_id": "TM",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodGet || gotPath != "/threat_models/TM/metadata" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("result = %v", v)
	}
}

func TestMetadataThreatWithoutIDIsToolError(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "get",
		"target":          "threat",
		"threat_model_id": "TM",
		"key":             "k",
	})
	if !isErr || !strings.Contains(text, "requires id") {
		t.Fatalf("%s", text)
	}
}

func TestMetadataUnknownTargetIsToolError(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "list",
		"target":          "spaceship",
		"threat_model_id": "TM",
	})
	if !isErr || !strings.Contains(text, "valid targets") {
		t.Fatalf("%s", text)
	}
}

func TestMetadataDeleteAssetHitsAssetMetadataPath(t *testing.T) {
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))

	v, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "delete",
		"target":          "asset",
		"threat_model_id": "TM",
		"id":              "A",
		"key":             "k",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodDelete || gotPath != "/threat_models/TM/assets/A/metadata/k" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	m, ok := v.(map[string]any)
	if !ok || m["deleted"] != "k" {
		t.Fatalf("result = %v", v)
	}
}

// TestMetadataSetFallsBackToCreateOn404 exercises the PUT-then-POST fallback:
// the TMI server's PUT-by-key handler is a pure update and 404s when the key
// doesn't exist yet (see metaTargets' doc comment in metadata.go), so a
// first-time set must retry as a create.
func TestMetadataSetFallsBackToCreateOn404(t *testing.T) {
	var gotMethods []string
	var gotPaths []string
	var gotCreateBody map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethods = append(gotMethods, r.Method)
		gotPaths = append(gotPaths, r.URL.Path)
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","error_description":"Metadata not found"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotCreateBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(metadataJSON))
	}))

	_, text, isErr := call(t, cs, "metadata", map[string]any{
		"action":          "set",
		"target":          "threat_model",
		"threat_model_id": "TM",
		"key":             "k",
		"value":           "v",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if len(gotMethods) != 2 || gotMethods[0] != http.MethodPut || gotMethods[1] != http.MethodPost {
		t.Fatalf("methods = %v", gotMethods)
	}
	if gotPaths[0] != "/threat_models/TM/metadata/k" || gotPaths[1] != "/threat_models/TM/metadata" {
		t.Fatalf("paths = %v", gotPaths)
	}
	if gotCreateBody["key"] != "k" || gotCreateBody["value"] != "v" {
		t.Fatalf("create body = %v", gotCreateBody)
	}
}
