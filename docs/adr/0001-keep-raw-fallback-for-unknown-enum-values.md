# ADR 0001: Keep the raw-JSON fallback for unknown enum values

- Status: Accepted
- Date: 2026-10-08
- Decision: made by Eric (human decision), released in v1.0.3

## Context

tmi-mcp talks to several TMI servers at once (prod, docker-desktop, k3s-rp),
so the server is often newer than the vendored tmi-clients Go client.

tmi-clients Go v2.0.1 relaxed decoding: unknown response fields are ignored.
It still rejects values outside a spec enum (for example `TeamStatus`, or the
`shape` of a diagram `Node`/`Edge`); one unknown node shape fails the whole
diagram. Issue #1 planned to delete `rawOnDecodeErr`
(`internal/tools/common.go`) once the client tolerated unknown fields.

Options considered:

1. Bump to v2.0.1 and keep `rawOnDecodeErr` for unknown enum values.
2. Bump and return the server's raw 2xx body on every call, so agents see
   every field.
3. Bump and delete `rawOnDecodeErr`, as Issue #1 said.

## Decision

Option 1. `rawOnDecodeErr` stays: a 2xx response that fails the typed decode
is returned as raw JSON instead of an error.

## Consequences

- Response fields newer than the client's spec are dropped from tool output
  (v1.0.2 returned them in raw JSON).
- Unknown enum values still reach the agent as raw JSON.
- Tests pin both behaviors: `TestTeamsGetToleratesUnknownStatus`,
  `TestRawOnDecodeErr2xxJSONBodyReturnsRaw`, `TestThreatsGetDropsUnknownField`,
  `TestDfdDiagramIgnoresUnknownField`.
- Revisit if the generated client starts tolerating unknown enum values, or if
  agents need fields newer than the client (option 2).
