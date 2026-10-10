@echo off
rem ============================================================================
rem  v2 MCP server (127.0.0.1:8770).
rem
rem  This file is kept only as a familiar entry point: it now simply delegates to
rem  supervise_server.cmd, so the server is always started THROUGH the watchdog
rem  and can never be started twice (the watchdog refuses to start when port 8770
rem  is already listening).
rem
rem  Canonical file : D:\window-mcp-v2\supervise_server.cmd
rem  Logs           : logs\server.log              (the server's stdout/stderr)
rem                   logs\supervise-v2-server.log (watchdog events)
rem
rem  NOTE: do NOT run "E:\Python\python.exe -u -m mcp_server" by hand instead of
rem  this file -- that bypasses the watchdog and the single-instance guard.
rem ============================================================================
call "D:\window-mcp-v2\supervise_server.cmd" %*
exit /b %errorlevel%
