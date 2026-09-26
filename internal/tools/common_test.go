package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ericfitz/tmi-mcp/internal/auth"
)

func TestPatchOpsSortedByKey(t *testing.T) {
	ops, err := patchOps(map[string]any{"name": "widget", "description": "a thing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("want 2 ops, got %d", len(ops))
	}
	if ops[0].Op != "add" || ops[0].Path != "/description" {
		t.Fatalf("ops[0] = %+v", ops[0])
	}
	if ops[1].Op != "add" || ops[1].Path != "/name" {
		t.Fatalf("ops[1] = %+v", ops[1])
	}
}

func TestPatchOpsPreservesNestedValue(t *testing.T) {
	nested := map[string]any{"x": 1, "y": []any{"a", "b"}}
	ops, err := patchOps(map[string]any{"metadata": nested})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ops[0].Value.(map[string]any)
	if !ok || got["x"] != 1 {
		t.Fatalf("value not preserved: %+v", ops[0].Value)
	}
}

func TestPatchOpsEmptyIsError(t *testing.T) {
	if _, err := patchOps(map[string]any{}); err == nil {
		t.Fatal("want error for empty fields")
	}
}

func TestCompactListKeepsScalarsAndCompactsArrays(t *testing.T) {
	in := map[string]any{
		"total": 2,
		"threats": []any{
			map[string]any{
				"id": "t1", "name": "SQLi", "severity": "high", "threat_type": "injection",
				"description": "a very long description that should be dropped",
				"created_at":  "2020-01-01", "created_by": "alice",
			},
		},
	}
	out, err := compactList(in)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("want map, got %T", out)
	}
	if m["total"] != float64(2) {
		t.Fatalf("total = %v", m["total"])
	}
	threats, ok := m["threats"].([]any)
	if !ok || len(threats) != 1 {
		t.Fatalf("threats = %v", m["threats"])
	}
	item, ok := threats[0].(map[string]any)
	if !ok {
		t.Fatalf("item = %v", threats[0])
	}
	if _, present := item["description"]; present {
		t.Fatalf("description should have been dropped: %v", item)
	}
	if _, present := item["created_by"]; present {
		t.Fatalf("created_by should have been dropped: %v", item)
	}
	if item["id"] != "t1" || item["name"] != "SQLi" || item["severity"] != "high" || item["threat_type"] != "injection" {
		t.Fatalf("compact keys missing: %v", item)
	}
}

func TestToolErrForbiddenAPIError(t *testing.T) {
	err := toolErr(&auth.APIError{Status: 403, Body: []byte(`{"error":"forbidden","error_description":"nope"}`)})
	msg := err.Error()
	if !strings.Contains(msg, "403") || !strings.Contains(msg, "nope") || !strings.Contains(msg, "you do not have access") {
		t.Fatalf("got %q", msg)
	}
}

func TestToolErrUnauthorizedHintsLogin(t *testing.T) {
	err := toolErr(&auth.APIError{Status: 401, Body: []byte(`{"error":"unauthorized"}`)})
	if !strings.Contains(err.Error(), "action=login") {
		t.Fatalf("got %q", err.Error())
	}
}

func TestToolErrPassesThroughNonAPIError(t *testing.T) {
	orig := &plainErr{"boom"}
	if got := toolErr(orig); got != orig {
		t.Fatalf("want passthrough, got %v", got)
	}
}

type plainErr struct{ s string }

func (e *plainErr) Error() string { return e.s }

func TestNeedReportsMissingField(t *testing.T) {
	err := need("get", "threat_model_id", "")
	if err == nil || err.Error() != `action "get" requires threat_model_id` {
		t.Fatalf("got %v", err)
	}
}

func TestNeedOKWhenPresent(t *testing.T) {
	if err := need("get", "threat_model_id", "tm-1"); err != nil {
		t.Fatalf("got %v", err)
	}
}

type decodeTarget struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestDecodeFieldsRoundTrip(t *testing.T) {
	got, err := decodeFields[decodeTarget](map[string]any{"name": "widget", "count": 3})
	if err != nil || got.Name != "widget" || got.Count != 3 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestDecodeFieldsBadTypeIsError(t *testing.T) {
	_, err := decodeFields[decodeTarget](map[string]any{"count": "not-a-number"})
	if err == nil {
		t.Fatal("want error for wrong field type")
	}
}

// execDiagramGet drives a real tmi.APIClient against fake, so the returned
// error (if any) is a genuine *tmi.GenericOpenAPIError from the generated
// client, not a hand-rolled stand-in (its fields are private, so it can't be
// constructed directly from this package).
func execDiagramGet(t *testing.T, fake http.Handler) (*http.Response, error) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	c := auth.NewAPIClient(srv.URL)
	_, resp, err := c.ThreatModelSubResourcesAPI.GetThreatModelDiagram(context.Background(), "TM", "D").Execute()
	return resp, err
}

// TestDfdDiagramDecodesTypedWithRealCells proves the generated DfdDiagram
// type itself decodes diagramJSON (a real node and a real edge cell) with no
// help from rawOnDecodeErr: it calls the generated client directly and
// requires a clean decode, unlike execDiagramGet's other callers which want
// a decode error.
func TestDfdDiagramDecodesTypedWithRealCells(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diagramJSON))
	}))
	t.Cleanup(srv.Close)
	c := auth.NewAPIClient(srv.URL)
	got, _, err := c.ThreatModelSubResourcesAPI.GetThreatModelDiagram(context.Background(), "TM", "D").Execute()
	if err != nil {
		t.Fatalf("typed decode failed: %v", err)
	}
	if len(got.Cells) != 2 || got.Cells[0].Node == nil || got.Cells[1].Edge == nil {
		t.Fatalf("cells not typed as Node/Edge: %+v", got.Cells)
	}
	if *got.Cells[0].Node.Shape != "actor" || got.Cells[1].Edge.Source.Cell != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("cell fields wrong: %+v", got.Cells)
	}
}

func TestRawOnDecodeErr2xxJSONBodyReturnsRaw(t *testing.T) {
	// diagramWithUnknownFieldJSON carries a field absent from the vendored
	// client's spec, which DisallowUnknownFields naturally turns into a
	// *tmi.GenericOpenAPIError this helper targets (see rawOnDecodeErr's doc
	// comment).
	resp, err := execDiagramGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diagramWithUnknownFieldJSON))
	}))
	if err == nil {
		t.Fatal("want an unknown-field decode error")
	}

	v, gotResp, gotErr := rawOnDecodeErr(nil, resp, err)
	if gotErr != nil {
		t.Fatalf("want nil error, got %v", gotErr)
	}
	if gotResp != resp {
		t.Fatalf("resp changed")
	}
	raw, ok := v.(json.RawMessage)
	if !ok {
		t.Fatalf("want json.RawMessage, got %T", v)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m["id"] != "dg-1" {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
}

func TestRawOnDecodeErr4xxUnchanged(t *testing.T) {
	resp, err := execDiagramGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad"}`))
	}))
	if err == nil {
		t.Fatal("want error for a 400 response")
	}

	_, _, gotErr := rawOnDecodeErr(nil, resp, err)
	if gotErr != err {
		t.Fatalf("want the error unchanged, got %v", gotErr)
	}
}

func TestRawOnDecodeErrNonJSONBodyUnchanged(t *testing.T) {
	resp, err := execDiagramGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	if err == nil {
		t.Fatal("want a decode error for a non-JSON body")
	}

	_, _, gotErr := rawOnDecodeErr(nil, resp, err)
	if gotErr != err {
		t.Fatalf("want the error unchanged, got %v", gotErr)
	}
}
