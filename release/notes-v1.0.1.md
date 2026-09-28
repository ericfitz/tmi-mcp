Bug-fix release for token handling when several sessions share a profile.

- tmi-mcp processes that share a profile now take turns logging in and refreshing tokens. A per-profile lock file sits next to the token files. TMI refresh tokens can only be used once, so two processes refreshing at the same moment could leave one of them holding a rejected token and opening a needless browser login. While one process has a login open, another process's calls wait for it to finish instead of opening a second browser.
- When several calls get a 401 at the same time, they now share one token refresh instead of each doing its own.
- Logging out while a login or refresh is still running no longer lets that login save its tokens after the logout deleted them.

Upgrade with `brew upgrade tmi-mcp`.
