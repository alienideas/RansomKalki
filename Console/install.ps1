#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install VectorStryke Central Console on Windows (Scheduled Task)
.EXAMPLE
  .\install.ps1 -Port 9000
  .\install.ps1 -Port 9000 -Token "shared-secret"
#>
param(
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 9000,
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = $null
foreach ($c in @("python", "python3", "py")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source; break }
}
if (-not $Python) {
    Write-Host "ERROR: Python 3 is required on the console host." -ForegroundColor Red
    exit 1
}

Write-Host "=== VectorStryke Central Console Install (Windows) ===" -ForegroundColor Cyan
Write-Host "  Root   : $Root"
Write-Host "  Python : $Python"
Write-Host "  Bind   : ${HostAddress}:$Port"
Write-Host ""

New-Item -ItemType Directory -Path (Join-Path $Root "data") -Force | Out-Null

$envFile = Join-Path $Root "console.env"
@"
VECTORSTRYKE_CONSOLE_HOST=$HostAddress
VECTORSTRYKE_CONSOLE_PORT=$Port
VECTORSTRYKE_ENROLL_TOKEN=$Token
"@ | Set-Content $envFile -Encoding UTF8

$taskName = "VectorStrykeConsole"
$arg = "`"$Root\console.py`" --host $HostAddress --port $Port"
$action = New-ScheduledTaskAction -Execute $Python -Argument $arg -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

if ($Token) {
    [Environment]::SetEnvironmentVariable("VECTORSTRYKE_ENROLL_TOKEN", $Token, "Machine")
}

Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "  [+] Scheduled Task '$taskName' registered (At Startup / SYSTEM)" -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard:  http://localhost:$Port/" -ForegroundColor Green
Write-Host "Manage:     Get-ScheduledTask -TaskName $taskName"
Write-Host "Stop:       Stop-ScheduledTask -TaskName $taskName"
Write-Host "Uninstall:  Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false"
Write-Host ""
Write-Host "On each agent set ConsoleEnabled=true, ConsoleUrl=http://<this-host>:$Port, TenantId=<tenant>"
if ($Token) { Write-Host "  EnrollmentToken=$Token" }
Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
