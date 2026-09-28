package tools

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Instructions is sent to the harness in the initialize result: how the
// tools fit together, which the per-tool descriptions cannot say.
const Instructions = "Tools for threat modeling on a TMI server.\n" +
	"- Most work lives under a threat model: find or create it with `threat_models`, then pass its id as " +
	"threat_model_id to `threats`, `diagrams`, `assets`, `documents`, `notes`, and `repositories`. " +
	"`metadata` takes a target plus threat_model_id (and id for any target but the threat model itself). " +
	"`projects` and `teams` are top-level.\n" +
	"- update changes only the top-level keys in fields; omitted fields are untouched. " +
	"get first when changing a nested value.\n" +
	"- Threat models cannot be deleted through these tools.\n" +
	"- Login is automatic: the first call opens a browser, and an expired session is refreshed and the call " +
	"retried once. If a call still fails with an authentication error, call `auth` with action=login; " +
	"action=whoami shows the signed-in user.\n" +
	"- Every tool takes an optional profile naming a configured TMI server; `auth` action=list_profiles " +
	"lists them. Omit it for the default.\n" +
	"- list actions (except `metadata`) page with limit and offset."

// NewServer returns the tmi-mcp MCP server with every tool registered.
func NewServer(version string, d *Deps) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "tmi-mcp", Version: version}, &mcp.ServerOptions{Instructions: Instructions})
	Register(s, d)
	return s
}
