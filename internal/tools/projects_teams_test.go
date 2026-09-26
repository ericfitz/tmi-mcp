package tools

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// projectListItemJSON is a canned ProjectListItem (required: id, name,
// team_id, created_at; see model_project_list_item.go).
const projectListItemJSON = `{"id":"p-1","name":"Project1","team_id":"team-1","created_at":"2024-01-01T00:00:00Z"}`

// listProjectsJSON is a canned ListProjectsResponse (required: projects,
// total, limit, offset; see model_list_projects_response.go).
const listProjectsJSON = `{"projects":[` + projectListItemJSON + `],"total":1,"limit":20,"offset":0}`

// teamJSON is a canned Team (required: name; see model_team.go).
const teamJSON = `{"id":"team-1","name":"Team1"}`

// teamListItemJSON is a canned TeamListItem (required: id, name,
// created_at; see model_team_list_item.go).
const teamListItemJSON = `{"id":"team-1","name":"Team1","created_at":"2024-01-01T00:00:00Z"}`

// listTeamsJSON is a canned ListTeamsResponse (required: teams, total,
// limit, offset; see model_list_teams_response.go).
const listTeamsJSON = `{"teams":[` + teamListItemJSON + `],"total":1,"limit":20,"offset":0}`

func TestProjectsListWithNameCompactsQuery(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listProjectsJSON))
	}))

	v, text, isErr := call(t, cs, "projects", map[string]any{
		"action": "list",
		"name":   "Widget",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodGet || gotPath != "/projects" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if !strings.Contains(gotQuery, "name=Widget") {
		t.Fatalf("query = %q", gotQuery)
	}
	m, ok := v.(map[string]any)
	if !ok || m["total"] != float64(1) {
		t.Fatalf("result = %v", v)
	}
}

func TestTeamsUpdateSendsPatch(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody []map[string]any
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(teamJSON))
	}))

	_, text, isErr := call(t, cs, "teams", map[string]any{
		"action": "update",
		"id":     "team-1",
		"fields": map[string]any{"name": "NewName"},
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodPatch || gotPath != "/teams/team-1" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if len(gotBody) != 1 || gotBody[0]["op"] != "add" || gotBody[0]["path"] != "/name" || gotBody[0]["value"] != "NewName" {
		t.Fatalf("body = %v", gotBody)
	}
}

func TestProjectsDelete(t *testing.T) {
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))

	v, text, isErr := call(t, cs, "projects", map[string]any{
		"action": "delete",
		"id":     "p-1",
	})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodDelete || gotPath != "/projects/p-1" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	m, ok := v.(map[string]any)
	if !ok || m["deleted"] != "p-1" {
		t.Fatalf("result = %v", v)
	}
}

func TestTeamsGetRequiresID(t *testing.T) {
	cs := harness(t, http.NotFoundHandler())
	_, text, isErr := call(t, cs, "teams", map[string]any{"action": "get"})
	if !isErr || !strings.Contains(text, "requires id") {
		t.Fatalf("%s", text)
	}
}

func TestTeamsList(t *testing.T) {
	var gotMethod, gotPath string
	cs := harness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listTeamsJSON))
	}))
	v, text, isErr := call(t, cs, "teams", map[string]any{"action": "list"})
	if isErr {
		t.Fatalf("%s", text)
	}
	if gotMethod != http.MethodGet || gotPath != "/teams" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	m, ok := v.(map[string]any)
	if !ok || m["total"] != float64(1) {
		t.Fatalf("result = %v", v)
	}
}
