# Progress

Pushed work on `main` (github.com/ericfitz/tmi-mcp). Machine-local, in-flight state lives in `HANDOFF.md` (untracked).

## 2026-09-26 — v0 implemented and verified

- Design: `docs/superpowers/specs/2026-09-26-tmi-mcp-design.md` (seven human-made decisions recorded there). Plan: `docs/superpowers/plans/2026-09-26-tmi-mcp.md` (all 10 tasks done, whole-branch review and fix wave done).
- Local Go stdio MCP server wrapping `github.com/ericfitz/tmi-clients/go-client-generated/v1_15_0@v1.15.0`.
- Tools: `auth` (login, logout, refresh, whoami, list_profiles), `threat_models`, `threats`, `diagrams` (+ get_model), `assets`, `documents`, `notes`, `repositories`, `metadata`, `projects`, `teams`.
- Auth: lazy PKCE loopback browser login, per-profile lock so concurrent calls share one login, refresh then one retry on 401, tokens in the OS keychain with a mode-600 file fallback, optional fixed `callback_port` per profile.
- Workaround kept: generated models use DisallowUnknownFields, so undecodable 2xx responses are returned as raw JSON (`internal/tools/common.go` rawOnDecodeErr). Revoke and diagram workarounds were removed after tmi-clients v1.15.0 fixed the client.
- Verified: the live integration test passes against k3s dev (TMI 1.15.4, `tmi` provider) with a random port and with port 8765. Prod login on api.tmi.dev (allowlist `http://127.0.0.1:8765/*`) not yet exercised.
- Closed tmi#69 ("TMI as MCP server") as fixed by this repo.

## Open

- Exercise a real Google login against api.tmi.dev through the registered MCP server.
- If api.tmi.dev adds `http://127.0.0.1:*` (the RFC 8252 matcher shipped in TMI 1.15.1+), `callback_port` can be dropped from the prod profile.
- Deferred minor review findings (e.g. Logout not taking the profile lock; concurrent 401s each refreshing) — see the review notes in git history for the plan execution.
