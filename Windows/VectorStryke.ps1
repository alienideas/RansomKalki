#Requires -Version 5.1
<#
.SYNOPSIS
    VectorStryke - Modular Anti-Ransomware Engine for Windows
.DESCRIPTION
    Dependency-free. Modular OOP-style Modules\. Easy CLI for install/run/manage.
    ResponseMode: Automatic (no approvals) | Manual (approvals; timeout never auto-acts)
.EXAMPLE
    .\VectorStryke.ps1 install
    .\VectorStryke.ps1 start
    .\VectorStryke.ps1 mode -Id Automatic
    .\VectorStryke.ps1 status
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "start","stop","status","scan","approve","deny","install","uninstall",
        "mode","modes","auto-on","auto-off","ossec-mode","health","ossec-status","osscan","canary-init","canary-verify",
        "checkpoint","impact-clear","update-check","update-apply","rollback",
        "lkg-save","dashboard","help"
    )]
    [string]$Command = "help",

    [string]$Id = "",
    [int]$Port = 8787,
    [switch]$Force
)

$ErrorActionPreference = "SilentlyContinue"
$Global:VectorStrykeRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Load modules in order (dependency-free)
$modDir = Join-Path $Global:VectorStrykeRoot "Modules"
Get-ChildItem -Path $modDir -Filter "*.ps1" -ErrorAction SilentlyContinue |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Initialize-VSPaths

switch ($Command) {
    "start" {
        Start-VSEngine
    }
    "stop" {
        if (Test-Path $Global:VSPaths.PidFile) {
            try {
                $pidVal = [int](Get-Content $Global:VSPaths.PidFile -Raw).Trim()
                Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item $Global:VSPaths.PidFile -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped." -ForegroundColor Green
        } else {
            Write-Host "Not running." -ForegroundColor Yellow
        }
    }
    "status" { Show-VSStatus }
    "scan" {
        $cfg = Get-Config
        $snap = Invoke-VSCollect
        $findings = @(Invoke-VSDetect -Snapshot $snap -Config $cfg)
        $prelude = Test-VSEncryptionPrelude -Config $cfg -Processes $snap.processes
        if ($prelude) { $findings = @($prelude) + $findings }
        $findings | ConvertTo-Json -Depth 6
    }
    "approve" {
        if (-not $Id) { Write-Host "Usage: .\VectorStryke.ps1 approve -Id <AlertId>"; break }
        $a = Resolve-VSApproval -AlertId $Id -Decision "Approved"
        if (-not $a) { Write-Host "Alert not found"; break }
        $finding = @{}
        if ($a.Finding) {
            $a.Finding.PSObject.Properties | ForEach-Object { $finding[$_.Name] = $_.Value }
        }
        Invoke-VSAction -Finding $finding -Config (Get-Config) | Out-Null
        Write-Host "Approved and executed: $Id" -ForegroundColor Green
    }
    "deny" {
        if (-not $Id) { Write-Host "Usage: .\VectorStryke.ps1 deny -Id <AlertId>"; break }
        $a = Resolve-VSApproval -AlertId $Id -Decision "Denied"
        Write-Host $(if ($a) { "Denied" } else { "Alert not found" })
    }
    "mode" {
        $target = if ($Id) { $Id } else { "list" }
        if ($target -match '^(list|show|all)$') {
            $cfg = Get-Config
            Write-Host ("ResponseMode={0}" -f $(if ($cfg.ResponseMode) { $cfg.ResponseMode } else { "Automatic" }))
            Write-Host ("OsSecurityMode={0}" -f $(if ($cfg.OsSecurityMode) { $cfg.OsSecurityMode } else { "Auto" }))
        } else {
            try {
                $cfg = Set-VSResponseMode -Mode $target
                Write-Host "ResponseMode=$($cfg.ResponseMode)" -ForegroundColor Cyan
                if ($cfg.ResponseMode -eq "Manual") {
                    Write-Host "  Approvals required; timeout never auto-acts" -ForegroundColor Yellow
                } else {
                    Write-Host "  Fully automatic; no explicit approvals" -ForegroundColor Green
                }
            } catch {
                Write-Host "Usage: .\VectorStryke.ps1 mode -Id Automatic|Manual|list" -ForegroundColor Yellow
            }
        }
    }

    "modes" {
        $cfg = Get-Config
        Write-Host "=== VectorStryke modes ===" -ForegroundColor Cyan
        Write-Host ("  ResponseMode              : {0}" -f $(if ($cfg.ResponseMode) { $cfg.ResponseMode } else { "Automatic" }))
        Write-Host ("  OsSecurityMode            : {0}" -f $(if ($cfg.OsSecurityMode) { $cfg.OsSecurityMode } else { "Auto" }))
        Write-Host ("  OsSecurityDetectionOnly   : {0}" -f $cfg.OsSecurityDetectionOnly)
        Write-Host ("  OsSecurityFallbackEnabled : {0}" -f $cfg.OsSecurityFallbackEnabled)
        Write-Host ("  OsScanAutoQuarantine      : {0}" -f $cfg.OsScanAutoQuarantine)
        Write-Host ("  OsScanAutoDeleteMalicious : {0}" -f $cfg.OsScanAutoDeleteMalicious)
        Write-Host ""
        Write-Host "Set: .\VectorStryke.ps1 mode -Id Automatic|Manual"
        Write-Host "Set: .\VectorStryke.ps1 ossec-mode -Id Auto|Coexist|Fallback"
    }
    "ossec-mode" {
        $cfg = Get-Config
        $target = if ($Id) { $Id } else { "show" }
        switch -Regex ($target) {
            '^(Auto|auto|automatic)$' {
                $cfg.OsSecurityMode = "Auto"
                Save-Config $cfg
                Write-Host "OsSecurityMode=Auto (follow classification)" -ForegroundColor Green
            }
            '^(Coexist|coexist|observe)$' {
                $cfg.OsSecurityMode = "Coexist"
                $cfg.OsSecurityDetectionOnly = $true
                $cfg.OsSecurityFallbackEnabled = $false
                Save-Config $cfg
                Write-Host "OsSecurityMode=Coexist (observe only; fallback off)" -ForegroundColor Cyan
            }
            '^(Fallback|fallback|fb)$' {
                $cfg.OsSecurityMode = "Fallback"
                $cfg.OsSecurityDetectionOnly = $false
                $cfg.OsSecurityFallbackEnabled = $true
                Save-Config $cfg
                Write-Host "OsSecurityMode=Fallback (eligible when Absent)" -ForegroundColor Yellow
            }
            default {
                Write-Host ("Current OsSecurityMode={0}" -f $(if ($cfg.OsSecurityMode) { $cfg.OsSecurityMode } else { "Auto" }))
                Write-Host "Usage: .\VectorStryke.ps1 ossec-mode -Id Auto|Coexist|Fallback"
            }
        }
    }
    "auto-on" {
        Set-VSResponseMode -Mode Automatic | Out-Null
        Write-Host "ResponseMode=Automatic (fully automatic, no approvals)" -ForegroundColor Green
    }
    "auto-off" {
        Set-VSResponseMode -Mode Manual | Out-Null
        Write-Host "ResponseMode=Manual (approvals required; timeout never auto-acts)" -ForegroundColor Yellow
    }
    "osscan" {
        $cfg = Get-Config
        $full = $false
        if ($Id -eq "full") { $full = $true }
        if (Get-Command Invoke-VSOsScan -ErrorAction SilentlyContinue) {
            if ($Id -eq "baseline") {
                Invoke-VSOsScan -Config $cfg -BuildBaselineOnly | ConvertTo-Json -Depth 6
            } else {
                Invoke-VSOsScan -Config $cfg -Full:$full | ConvertTo-Json -Depth 8
            }
        } else { Write-Host "OsScan module not loaded" }
    }
    "ossec-status" {
        $cfg = Get-Config
        if (Get-Command Invoke-VSOsSecurityDetect -ErrorAction SilentlyContinue) {
            Invoke-VSOsSecurityDetect -Config $cfg | ConvertTo-Json -Depth 6
        } else { Write-Host "OsSecurity module not loaded" }
    }
    "health" {
        Invoke-VSSelfHealth -Config (Get-Config) | ConvertTo-Json -Depth 5
    }
    "canary-init" {
        Initialize-VSCanaries -Config (Get-Config) | ConvertTo-Json -Depth 5
    }
    "canary-verify" {
        Test-VSCanaries | ConvertTo-Json -Depth 5
    }
    "checkpoint" {
        New-VSCheckpoint -Reason "manual-cli" | ConvertTo-Json -Depth 5
    }
    "impact-clear" {
        $cfg = Get-Config
        if (-not $Force) {
            $v = Test-VSCanaries
            if (-not $v.ok -and -not $v.skipped) {
                @{ ok = $false; error = "canary_verify_failed"; verify = $v } | ConvertTo-Json -Depth 5
                break
            }
        }
        $cfg.ImpactPending = $false
        Save-Config $cfg
        @{ ok = $true } | ConvertTo-Json
    }
    "update-check" {
        Invoke-VSUpdateCheck -Config (Get-Config) | ConvertTo-Json -Depth 6
    }
    "update-apply" {
        $cfg = Get-Config
        $r = Invoke-VSUpdateApply -Config $cfg -Force:$Force
        if ($r.ok) { Save-Config $cfg }
        $r | ConvertTo-Json -Depth 6
    }
    "rollback" {
        Invoke-VSRollbackLkg | ConvertTo-Json -Depth 4
    }
    "lkg-save" {
        @{ ok = $true; path = (Save-VSLastKnownGood -Config (Get-Config)) } | ConvertTo-Json
    }
    "install" {
        Install-VSAgent
    }
    "uninstall" {
        try { Unregister-ScheduledTask -TaskName "VectorStryke" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        if (Test-Path $Global:VSPaths.PidFile) {
            try {
                $pidVal = [int](Get-Content $Global:VSPaths.PidFile -Raw).Trim()
                Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item $Global:VSPaths.PidFile -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Uninstalled scheduled task and stopped engine. Data retained under Data\" -ForegroundColor Cyan
    }
    "dashboard" {
        $dash = Join-Path $Global:VSPaths.Root "dashboard.html"
        if (Test-Path $dash) {
            Start-Process $dash
            Write-Host "Opened dashboard.html (static). Engine status: .\VectorStryke.ps1 status" -ForegroundColor Cyan
        } else {
            Write-Host "dashboard.html not found" -ForegroundColor Yellow
        }
    }
    default {
        Write-Host @"

VectorStryke v$($Global:VSPaths.Version) — Modular Anti-Ransomware (Windows)
No external dependencies. PowerShell 5.1+

Usage: .\VectorStryke.ps1 <command> [-Id <value>] [-Force]

Core:
  install | uninstall | start | stop | status | scan
  approve -Id <AlertId> | deny -Id <AlertId>

Response mode:
  mode -Id Automatic     Fully automatic — no explicit approvals
  mode -Id Manual        Approvals required — timeout never auto-acts
  auto-on / auto-off     Aliases for Automatic / Manual

Maturity:
  health | ossec-status | osscan [baseline|-Id full] | canary-init | canary-verify | checkpoint | impact-clear [-Force]
  update-check | update-apply [-Force] | lkg-save | rollback
  dashboard

Architecture: Modules\ (00-Paths … 12-Engine) — extend by adding sensors/detectors/responders

"@
    }
}
