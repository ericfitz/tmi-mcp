package tools

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tmi "github.com/ericfitz/tmi-clients/go-client-generated/v2_0_0/v2"
)

// authInput is the input for the auth tool.
type authInput struct {
	Action  string `json:"action" jsonschema:"one of login, logout, refresh, whoami, list_profiles"`
	Profile string `json:"profile,omitempty" jsonschema:"profile name; empty uses the default profile"`
}

// profileSummary is one entry of the auth tool's list_profiles output.
type profileSummary struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	IDP    string `json:"idp"`
}

func registerAuth(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "auth",
		Description: "Manage TMI authentication: login, logout, refresh the access token, whoami, or list configured profiles.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in authInput) (*mcp.CallToolResult, any, error) {
		n := notifier(ctx, req)
		switch in.Action {
		case "login":
			if err := d.S.Login(ctx, in.Profile, n); err != nil {
				return nil, nil, toolErr(err)
			}
			p, err := d.S.Profile(in.Profile)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, map[string]any{"status": "logged in", "profile": p.Name}, nil

		case "refresh":
			loggedIn, err := d.S.Refresh(ctx, in.Profile, n)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			p, err := d.S.Profile(in.Profile)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			status := "refreshed"
			if loggedIn {
				status = "logged in"
			}
			return nil, map[string]any{"status": status, "profile": p.Name}, nil

		case "logout":
			p, err := d.S.Profile(in.Profile)
			if err != nil {
				return nil, nil, toolErr(err)
			}
			if err := d.S.Logout(ctx, in.Profile); err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, map[string]any{"status": "logged out", "profile": p.Name}, nil

		case "whoami":
			v, err := d.call(ctx, req, in.Profile, func(ctx context.Context, c *tmi.APIClient) (any, *http.Response, error) {
				return c.AuthenticationAPI.GetCurrentUser(ctx).Execute()
			})
			if err != nil {
				return nil, nil, toolErr(err)
			}
			return nil, v, nil

		case "list_profiles":
			def, err := d.S.Profile("")
			if err != nil {
				return nil, nil, toolErr(err)
			}
			profiles := make([]profileSummary, 0, len(d.S.Cfg.Profiles))
			for _, name := range d.S.Cfg.Names() {
				p := d.S.Cfg.Profiles[name]
				profiles = append(profiles, profileSummary{Name: name, Server: p.Server, IDP: p.IDP})
			}
			return nil, map[string]any{"default": def.Name, "profiles": profiles}, nil

		default:
			return nil, nil, fmt.Errorf("unknown auth action %q; valid actions: login, logout, refresh, whoami, list_profiles", in.Action)
		}
	})
}
