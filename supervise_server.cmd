@echo off
rem ============================================================================
rem  v2 MCP server (127.0.0.1:8770) -- started WITH a watchdog.
rem
rem  THIS FILE IS THE SINGLE SOURCE OF TRUTH for how the v2 server is started.
rem  The logon scheduled task "WindowMCP-v2-Server" runs exactly this file
rem  (hidden, through run_hidden.vbs), so changing the command below changes
rem  both the manual start and the autostart.  There is nothing else to edit.
rem
rem  Watchdog (supervise.py):
rem    * appends to logs\server.log -- NEVER truncates it at startup
rem    * rotates by size at 20 MB, keeping 3 older copies (server.log.1 .. .3)
rem    * restarts the server after a crash, backing off 2,4,8,16,32,60s;
rem      the backoff resets once the server has stayed up for 300s
rem    * refuses to start if port 8770 is already listening, so running this
rem      while the server is up can never create a second instance
rem
rem  usage:  supervise_server.cmd            start the watchdog (detached, hidden)
rem          supervise_server.cmd status     what is running right now?
rem          supervise_server.cmd stop       stop the watchdog AND the server
rem          supervise_server.cmd check      dry-run the guards, start nothing
rem
rem  v1 (D:\window-mcp, 8765) and the CursorTouch server (8001) are NOT touched.
rem ============================================================================
setlocal
set "V2=D:\window-mcp-v2"
set "PY=E:\Python\python.exe"
set "PYW=E:\Python\pythonw.exe"
set "ARGS=--name v2-server --port 8770 --log %V2%\logs\server.log"

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

start "" /b "%PYW%" "%V2%\supervise.py" %ARGS% --cwd "%V2%" -- "%PY%" -u -m mcp_server
exit /b 0
