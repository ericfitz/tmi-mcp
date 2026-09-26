package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ericfitz/tmi-mcp/internal/session"
)

// Deps holds what handlers need.
type Deps struct{ S *session.Manager }

// Register registers every tool on s.
func Register(s *mcp.Server, d *Deps) {
	registerAuth(s, d)
	registerThreatModels(s, d)
	registerThreats(s, d)
}
