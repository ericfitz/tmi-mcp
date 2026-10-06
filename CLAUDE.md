# tmi-mcp

Done gate: make lint build test

- No PRs on this repo. Work on a branch, then fast-forward main, push, and delete the branch once lint, build and tests pass.
- The `tmi` MCP server in this environment is the brew binary `/opt/homebrew/bin/tmi-mcp`, registered in Claude Code, Codex and Grok. Release: `git tag -a vX.Y.Z && git push origin vX.Y.Z && ./release/release.sh vX.Y.Z` (signed and notarized; the script updates the ericfitz/homebrew-tap formula).
