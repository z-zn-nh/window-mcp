' ============================================================================
'  run_hidden.vbs -- launch a batch file with NO visible console window.
'
'  Used by the logon scheduled tasks: a task action that calls cmd.exe directly
'  would keep a console window on the desktop forever, because the watchdog
'  lives as long as the session does.  wscript.exe is a GUI program, so there
'  is no console at all; Run(..., 0, False) then starts the batch file hidden
'  and returns immediately.
'
'  usage:  wscript.exe run_hidden.vbs "D:\window-mcp-v2\supervise_server.cmd"
'
'  NOTE: keep this file pure ASCII.  WSH reads .vbs as ANSI, and an editor that
'  saves UTF-8 without BOM would corrupt non-ASCII characters on a cp936 box.
' ============================================================================
Option Explicit

Dim sh, target

If WScript.Arguments.Count < 1 Then
    WScript.Quit 2
End If

target = WScript.Arguments(0)

Set sh = CreateObject("WScript.Shell")
sh.Run "cmd.exe /c """ & target & """", 0, False
