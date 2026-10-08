package tools

import (
	"net/http"
	"strings"
	"testing"
)

func TestThreatsGetRequiresID(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "threats", map[string]any{"action": "get", "threat_model_id": "tm-1"})
	if !isErr || !strings.Contains(text, "requires id") {
		t.Fatalf("%s", text)
	}
}

// TestThreatsGetRequiresThreatModelID omits threat_model_id entirely: the
// MCP SDK rejects it against SubInput's generated JSON schema (the field has
// no `omitempty`) before our handler runs, so the message comes from schema
// validation rather than our own need() check — it still names the missing
// field.
func TestThreatsGetRequiresThreatModelID(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "threats", map[string]any{"action": "get", "id": "th-1"})
	if !isErr || !strings.Contains(text, "threat_model_id") {
		t.Fatalf("%s", text)
	}
}

func TestThreatsDelete(t *testing.T) {
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		if r.URL.Path != "/threat_models/TM/threats/TH" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	v, text, isErr := call(t, cs, "threats", map[string]any{
		"action":          "delete",
		"threat_model_id": "TM",
		"id":              "TH",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodDelete || gotPath != "/threat_models/TM/threats/TH" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	m, ok := v.(map[string]any)
	if !ok || m["deleted"] != "TH" {
		t.Fatalf("result = %v", v)
	}
}

// TestThreatsGetDropsUnknownField pins the generated client's handling of a
// response field newer than its spec: the tool succeeds and the field is
// dropped from the result. (Unknown enum values are a different case; see
// TestTeamsGetToleratesUnknownStatus.)
func TestThreatsGetDropsUnknownField(t *testing.T) {
	const threatWithExtraFieldJSON = `{"id":"th-1","name":"SQLi","threat_type":["injection"],"surprise_field":"new in server"}`
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(threatWithExtraFieldJSON))
	}))

	v, text, isErr := call(t, cs, "threats", map[string]any{
		"action":          "get",
		"threat_model_id": "TM",
		"id":              "TH",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	m, ok := v.(map[string]any)
	if !ok || m["id"] != "th-1" {
		t.Fatalf("result = %v", v)
	}
	if _, ok := m["surprise_field"]; ok {
		t.Fatalf("surprise_field should be dropped by the typed decode: %v", m)
	}
}

func TestThreatsCreateRejectsDangerousContent(t *testing.T) {
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_input","error_description":"Field 'mitigation' contains potentially dangerous content"}`))
	}))

	_, text, isErr := call(t, cs, "threats", map[string]any{
		"action":          "create",
		"threat_model_id": "tm-1",
		"fields": map[string]any{
			"name":        "SQLi",
			"threat_type": []any{"injection"},
			"mitigation":  "version = 2",
		},
	})
	if !isErr {
		t.Fatalf("want tool error, got %s", text)
	}
	if !strings.Contains(text, "dangerous content") || !strings.Contains(text, "400") {
		t.Fatalf("%s", text)
	}
}
