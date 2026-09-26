package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestThreatModelsListWithNameFilter(t *testing.T) {
	var gotQuery string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/threat_models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listThreatModelsJSON))
	}))

	v, text, isErr := call(t, cs, "threat_models", map[string]any{"action": "list", "name": "x", "limit": 5})
	if isErr {
		t.Fatalf("%s", text)
	}
	if !strings.Contains(gotQuery, "name=x") || !strings.Contains(gotQuery, "limit=5") {
		t.Fatalf("query = %q", gotQuery)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("result not a map: %v", v)
	}
	if m["total"] != float64(1) {
		t.Fatalf("total = %v", m["total"])
	}
	items, ok := m["threat_models"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("threat_models = %v", m["threat_models"])
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("item = %v", items[0])
	}
	if _, present := item["document_count"]; present {
		t.Fatalf("document_count should have been dropped: %v", item)
	}
	if item["id"] != "tm-1" || item["name"] != "TM1" {
		t.Fatalf("compact keys missing: %v", item)
	}
}

func TestThreatModelsCreate(t *testing.T) {
	var gotBody map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/threat_models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(threatModelJSON))
	}))

	v, text, isErr := call(t, cs, "threat_models", map[string]any{
		"action": "create",
		"fields": map[string]any{"name": "TM1"},
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotBody["name"] != "TM1" {
		t.Fatalf("body = %v", gotBody)
	}
	m, ok := v.(map[string]any)
	if !ok || m["name"] != "TM1" {
		t.Fatalf("result = %v", v)
	}
}

func TestThreatModelsUpdatePatchBody(t *testing.T) {
	var gotBody string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/threat_models/tm-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(threatModelJSON))
	}))

	_, text, isErr := call(t, cs, "threat_models", map[string]any{
		"action": "update",
		"id":     "tm-1",
		"fields": map[string]any{"description": "d", "name": "n"},
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	want := `[{"op":"add","path":"/description","value":"d"},{"op":"add","path":"/name","value":"n"}]`
	if strings.TrimSpace(gotBody) != want {
		t.Fatalf("body = %s, want %s", gotBody, want)
	}
}

func TestThreatModelsDeleteIsUnknownAction(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "threat_models", map[string]any{"action": "delete", "id": "tm-1"})
	if !isErr {
		t.Fatalf("want tool error, got %s", text)
	}
	if !strings.Contains(text, "valid actions") {
		t.Fatalf("%s", text)
	}
}
