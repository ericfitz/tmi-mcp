package tools

import (
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
