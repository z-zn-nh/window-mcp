# ============================================================================
#  manage_autostart.ps1 -- register / remove / inspect the two logon tasks that
#  keep the v2 MCP stack (server on 8770 + named tunnel mcp.example.com) running.
#
#      install    register (or refresh) WindowMCP-v2-Server / WindowMCP-v2-Tunnel
#      uninstall  remove both tasks
#      status     task state, last run result, next run time, action, run-as
#
#  WHY SCHEDULED TASKS AND NOT WINDOWS SERVICES
#  The v2 MCP server screenshots the desktop and injects keyboard / mouse input
#  with SendInput.  A Windows service runs in session 0, which has no desktop,
#  so every GUI tool would silently break.  These tasks therefore use an AtLogOn
#  trigger with LogonType Interactive, so the watchdog starts inside the user's
#  own interactive session, as that user, without elevation.
#
#  WHY wscript.exe + run_hidden.vbs
#  A task whose action calls cmd.exe directly would keep a console window on the
#  desktop for the whole session (the watchdog lives as long as the session).
#  wscript.exe is a GUI program, so no console is created; run_hidden.vbs then
#  starts the batch file with window style 0.  The .cmd wrappers remain the
#  single source of truth for the command lines.
#
#  WHY IgnoreNew
#  The watchdog already refuses to start a duplicate (lock file + port check +
#  command-line match), and MultipleInstances=IgnoreNew is a second, independent
#  guard against two tasks overlapping.
#
#  NOTE: keep this file pure ASCII.  Windows PowerShell 5.1 reads .ps1 files as
#  ANSI (cp936 here) unless they carry a UTF-8 BOM, which would corrupt any
#  non-ASCII character.
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'uninstall', 'status')]
    [string]$Action = 'status'
)

$ErrorActionPreference = 'Stop'

$V2     = 'D:\window-mcp-v2'
$Server = 'WindowMCP-v2-Server'
$Tunnel = 'WindowMCP-v2-Tunnel'
$Wscr   = Join-Path $env:SystemRoot 'System32\wscript.exe'
$User   = "$env:USERDOMAIN\$env:USERNAME"

function New-McpAction {
    param([string]$BatchFile)
    $vbs = Join-Path $V2 'run_hidden.vbs'
    New-ScheduledTaskAction -Execute $Wscr `
        -Argument ('"{0}" "{1}"' -f $vbs, (Join-Path $V2 $BatchFile)) `
        -WorkingDirectory $V2
}

function Install-McpTask {
    param([string]$Name, [string]$BatchFile)

    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $User

    $principal = New-ScheduledTaskPrincipal -UserId $User `
        -LogonType Interactive -RunLevel Limited

    # NOTE: demand start is left at its default (allowed), so the task can also
    # be run by hand from Task Scheduler.  ExecutionTimeLimit 0 = no time limit:
    # this is a daemon, it must never be killed for "running too long".
    $settings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -DontStopOnIdleEnd `
        -StartWhenAvailable

    Register-ScheduledTask -TaskName $Name `
        -Action (New-McpAction $BatchFile) `
        -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host ("registered : {0}  ->  {1}" -f $Name, $BatchFile)
}

function Show-McpTask {
    param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host ("{0}: NOT INSTALLED" -f $Name)
        return
    }
    $info = $task | Get-ScheduledTaskInfo
    Write-Host ("{0}" -f $Name)
    Write-Host ("    state     : {0}" -f $task.State)
    Write-Host ("    last run  : {0}   (result {1})" -f $info.LastRunTime, $info.LastTaskResult)
    Write-Host ("    next run  : {0}" -f $info.NextRunTime)
    Write-Host ("    action    : {0} {1}" -f $task.Actions[0].Execute, $task.Actions[0].Arguments)
    Write-Host ("    run as    : {0}   logon type: {1}" -f $task.Principal.UserId, $task.Principal.LogonType)
}

switch ($Action) {
    'install' {
        Install-McpTask -Name $Server -BatchFile 'supervise_server.cmd'
        Install-McpTask -Name $Tunnel -BatchFile 'supervise_tunnel.cmd'
        Write-Host ''
        Write-Host ("user    : {0}" -f $User)
        Write-Host 'trigger : AtLogOn (this user), interactive session, no elevation'
        Write-Host 'NOTHING WAS STARTED NOW -- the running instances stay as they are,'
        Write-Host 'and the watchdog only takes over at the next logon.'
    }
    'uninstall' {
        foreach ($n in @($Server, $Tunnel)) {
            if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $n -Confirm:$false
                Write-Host ("removed     : {0}" -f $n)
            }
            else {
                Write-Host ("not present : {0}" -f $n)
            }
        }
    }
    'status' {
        Show-McpTask -Name $Server
        Show-McpTask -Name $Tunnel
    }
}
