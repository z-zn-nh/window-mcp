@echo off
rem ============================================================================
rem  Manage the logon autostart of the v2 MCP stack.
rem
rem    autostart.cmd install     register the two logon tasks (idempotent)
rem    autostart.cmd status      task state + watchdog state + listening ports
rem    autostart.cmd stop        stop watchdog + server + tunnel right now
rem                              (tasks stay registered: next logon starts again)
rem    autostart.cmd uninstall   remove the tasks (fully reversible)
rem
rem  Why scheduled tasks and not Windows services: the MCP server screenshots
rem  the desktop and injects input via SendInput.  A service runs in session 0,
rem  which has no desktop, so every GUI tool would break.  The tasks therefore
rem  trigger AtLogOn and run as the logged-on user in their interactive session.
rem
rem  v1 (D:\window-mcp, 8765) and CursorTouch (8001) are never touched here.
rem ============================================================================
setlocal
set "V2=D:\window-mcp-v2"
set "PS=powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%V2%\manage_autostart.ps1""

if /i "%~1"=="install"   goto :install
if /i "%~1"=="uninstall" goto :uninstall
if /i "%~1"=="status"    goto :status
if /i "%~1"=="stop"      goto :stop
goto :usage

:install
%PS% install
set "RC=%errorlevel%"
echo.
echo ==================== current state ====================
call "%V2%\autostart.cmd" status
exit /b %RC%

:uninstall
%PS% uninstall
exit /b %errorlevel%

:status
echo ==================== scheduled tasks ====================
%PS% status
echo.
echo ==================== v2 server (8770) ====================
call "%V2%\supervise_server.cmd" status
echo.
echo ==================== named tunnel (mcp.example.com) =====
call "%V2%\supervise_tunnel.cmd" status
exit /b 0

:stop
echo Stopping the v2 watchdog(s) and their children.
echo v1 (8765), CursorTouch (8001) and their tunnels are NOT touched.
echo.
call "%V2%\supervise_server.cmd" stop
echo.
call "%V2%\supervise_tunnel.cmd" stop
exit /b 0

:usage
echo usage: autostart.cmd [install^|uninstall^|status^|stop]
echo   install    register the logon tasks (starts nothing now)
echo   status     show task state and what is running
echo   stop       stop the v2 watchdog + server + tunnel now
echo   uninstall  remove the logon tasks
exit /b 2
