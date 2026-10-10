@echo off
rem ============================================================================
rem  Cloudflare NAMED tunnel "window-mcp" (mcp.example.com -> 127.0.0.1:8770).
rem
rem  This file is kept only as a familiar entry point: it now simply delegates to
rem  supervise_tunnel.cmd, so the tunnel is always started THROUGH the watchdog
rem  and can never be connected twice (Cloudflare would happily accept a second
rem  connector for the same tunnel).
rem
rem  Canonical file : D:\window-mcp-v2\supervise_tunnel.cmd
rem  Logs           : logs\named-tunnel.log              (cloudflared output)
rem                   logs\supervise-named-tunnel.log    (watchdog events)
rem
rem  NOTE: do NOT launch cloudflared by hand for this tunnel instead of this
rem  file -- that bypasses the watchdog and can create a duplicate connector.
rem ============================================================================
call "D:\window-mcp-v2\supervise_tunnel.cmd" %*
exit /b %errorlevel%
