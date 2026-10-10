@echo off
rem ============================================================================
rem  Cloudflare NAMED tunnel "window-mcp" -- fixed address mcp.example.com -> 8770.
rem  Started WITH a watchdog.
rem
rem  THIS FILE IS THE SINGLE SOURCE OF TRUTH for how the tunnel is started.
rem  The logon scheduled task "WindowMCP-v2-Tunnel" runs exactly this file
rem  (hidden, through run_hidden.vbs).
rem
rem  Watchdog (supervise.py):
rem    * appends to logs\named-tunnel.log -- NEVER truncates it at startup
rem    * rotates by size at 20 MB, keeping 3 older copies
rem    * restarts cloudflared after a drop, backing off 2,4,8,16,32,60s;
rem      the backoff resets once it has stayed up for 300s
rem    * refuses to start if any process already carries the v2 tunnel config
rem      on its command line, so the tunnel can never be connected twice
rem      (Cloudflare would happily accept two connectors for one tunnel)
rem
rem  usage:  supervise_tunnel.cmd            start the watchdog (detached, hidden)
rem          supervise_tunnel.cmd status     what is running right now?
rem          supervise_tunnel.cmd stop       stop the watchdog AND the tunnel
rem          supervise_tunnel.cmd check      dry-run the guards, start nothing
rem
rem  v1's temporary tunnel (8765) and the CursorTouch tunnel (8001) are NOT touched.
rem ============================================================================
setlocal
set "V2=D:\window-mcp-v2"
set "CF=D:\window-mcp\tools\cloudflared.exe"
set "CFG=%V2%\tunnel\config.yml"
set "PY=E:\Python\python.exe"
set "PYW=E:\Python\pythonw.exe"
set "ARGS=--name named-tunnel --match window-mcp-v2\tunnel\config.yml --log %V2%\logs\named-tunnel.log"

if /i "%~1"=="status" (
  "%PY%" "%V2%\supervise.py" %ARGS% --status
  exit /b %errorlevel%
)
if /i "%~1"=="stop" (
  "%PY%" "%V2%\supervise.py" %ARGS% --stop
  exit /b %errorlevel%
)
if /i "%~1"=="check" (
  "%PY%" "%V2%\supervise.py" %ARGS% --check-only
  exit /b %errorlevel%
)

start "" /b "%PYW%" "%V2%\supervise.py" %ARGS% --cwd "%V2%" -- "%CF%" tunnel --config "%CFG%" --no-autoupdate run window-mcp
exit /b 0
