# VectorStryke Engine orchestrator

function Test-VSEngineRunning {
    if (-not (Test-Path $Global:VSPaths.PidFile)) { return $false }
    try {
        $pidVal = [int](Get-Content $Global:VSPaths.PidFile -Raw).Trim()
        $p = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
        return ($null -ne $p)
    } catch { return $false }
}

function Save-VSStatus {
    param([hashtable]$Status)
    $Status | ConvertTo-Json -Depth 6 | Set-Content $Global:VSPaths.StatusFile -Encoding UTF8
}

function Get-VSStatus {
    if (-not (Test-Path $Global:VSPaths.StatusFile)) { return @{} }
    try { return Get-Content $Global:VSPaths.StatusFile -Raw | ConvertFrom-Json } catch { return @{} }
}

function Invoke-VSHandleFinding {
    param([hashtable]$Finding, [hashtable]$Config, [VSResponsePolicy]$Policy)
    $score = 0
    if ($Finding.ContainsKey("score")) { $score = [int]$Finding.score }
    if ($score -lt 60) { return }
    $Policy.Reload($Config)
    if ($Policy.ShouldActImmediately($Finding)) {
        Write-Log "AUTOMATIC action (mode=$($Policy.Mode())) score=$score : $($Finding.name)" "HIGH"
        Invoke-VSAction -Finding $Finding -Config $Config | Out-Null
        return
    }
    if ($Policy.RequiresHumanApproval($Finding)) {
        $isImpact = $false
        if ($Finding.ContainsKey("impact_class")) { $isImpact = [bool]$Finding.impact_class }
        $timeout = if ($isImpact -or $Finding.severity -eq "High") {
            [int]$Config.ApprovalTimeoutImpact
        } else {
            [int]$Config.ApprovalTimeoutNormal
        }
        Submit-VSApproval -Finding $Finding -TimeoutSec $timeout | Out-Null
    }
}

function Start-VSEngine {
    if (Test-VSEngineRunning) {
        Write-Host "VectorStryke is already running." -ForegroundColor Yellow
        return
    }
    $pidVal = $PID
    Set-Content -Path $Global:VSPaths.PidFile -Value $pidVal -Encoding UTF8
    $cfg = Get-Config
    $cfg = Ensure-VSAgentId -Config $cfg
    Write-Log "VectorStryke engine started (PID $pidVal) mode=$($cfg.ResponseMode)" "INFO"
    if ($cfg.ConsoleEnabled) {
        $cfg = Invoke-VSConsoleEnroll -Config $cfg
    }
    $policy = [VSResponsePolicy]::new($cfg)
    $alertMode = $false

    while ($true) {
        try {
            $cfg = Get-Config
            $policy.Reload($cfg)

            # Advance first-run
            if ($cfg.FirstRunState -eq "PendingConfig" -and $cfg.AgentId) {
                $cfg.FirstRunState = "Enrolled"
                Save-Config $cfg
            }
            if ($cfg.FirstRunState -eq "Enrolled") {
                $h = Invoke-VSSelfHealth -Config $cfg
                if ($h.Ok -and (Test-Path $Global:VSPaths.StatusFile)) {
                    $cfg.FirstRunState = "Steady"
                    Save-Config $cfg
                }
            }

            $health = Invoke-VSSelfHealth -Config $cfg
            if (-not $health.Ok) {
                Write-Log "Self-health issues: $($health.Issues -join ', ')" "WARN"
            }

            # Manual-only timeout handling
            Process-VSTimeoutsManualOnly

            $snap = Invoke-VSCollect
            $findings = @(Invoke-VSDetect -Snapshot $snap -Config $cfg)

            $prelude = Test-VSEncryptionPrelude -Config $cfg -Processes $snap.processes
            if ($prelude) {
                $findings = @($prelude) + $findings
                if (-not $cfg.ImpactPending) {
                    $meta = New-VSCheckpoint -Reason ("ImpactPending:" + $prelude.name)
                    $cfg.ImpactPending = $true
                    $cfg.LastCheckpointId = $meta.CheckpointId
                    Save-Config $cfg
                    if ($policy.IsAutomatic()) {
                        Invoke-VSAction -Finding $prelude -Config $cfg | Out-Null
                    }
                }
            }

            if ($findings.Count -gt 0 -and $cfg.AgentEnabled) {
                $alertMode = $true
                foreach ($f in $findings) {
                    Invoke-VSHandleFinding -Finding $f -Config $cfg -Policy $policy
                }
            } else {
                $pending = @(Get-VSPendingApprovals)
                $alertMode = ($pending.Count -gt 0)
            }

            $status = @{
                Engine          = "Running"
                Pid             = $pidVal
                LastCycle       = (Get-Date).ToUniversalTime().ToString("o")
                MemoryUsedPct   = $snap.memory_used_pct
                FindingsCount   = $findings.Count
                PendingAlerts   = (@(Get-VSPendingApprovals)).Count
                Mode            = $(if ($alertMode) { "Alert" } else { "Idle" })
                ResponseMode    = $cfg.ResponseMode
                Version         = $cfg.Version
                Platform        = "Windows"
                Profile         = $cfg.Profile
                FirstRunState   = $cfg.FirstRunState
                HealthOk        = $health.Ok
                ImpactPending   = [bool]$cfg.ImpactPending
                LastCheckpointId = $cfg.LastCheckpointId
                AgentId         = $cfg.AgentId
                TenantId        = $cfg.TenantId
            }
            Save-VSStatus $status
            Invoke-VSConsoleHeartbeat -Config $cfg -Status $status | Out-Null

            $sleep = if ($alertMode) { [int]$cfg.PollIntervalAlertSec } else { [int]$cfg.PollIntervalIdleSec }
            Start-Sleep -Seconds $sleep
        } catch {
            Write-Log "Cycle error: $_" "ERROR"
            Start-Sleep -Seconds 30
        }
    }
}

function Install-VSService {
    $root = $Global:VSPaths.Root
    $script = Join-Path $root "VectorStryke.ps1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" start"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "VectorStryke" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "  [+] Scheduled Task: VectorStryke" -ForegroundColor Green
}

function Install-VSAgent {
    Initialize-VSPaths
    $cfg = Get-Config
    $cfg = Ensure-VSAgentId -Config $cfg
    $cfg.Version = $Global:VSPaths.Version
    if ($cfg.FirstRunState -eq "PendingConfig") { $cfg.FirstRunState = "Enrolled" }
    if (-not $cfg.ResponseMode) { $cfg.ResponseMode = "Automatic" }
    if ($cfg.ResponseMode -eq "Manual") {
        $cfg.AutoApproveOnTimeout = $false
        $cfg.AutoApproveEnabled = $false
    }
    Save-Config $cfg
    Initialize-VSCanaries -Config $cfg | Out-Null
    Save-VSLastKnownGood -Config $cfg | Out-Null
    try { Install-VSService } catch { Write-Host "  [!] Scheduled Task (run as Admin): $_" -ForegroundColor Yellow }
    $day1 = Join-Path $Global:VSPaths.Root "DAY1_OPS.txt"
    @"
VectorStryke Day-1 Operations (Windows)
=======================================
1. .\VectorStryke.ps1 status
2. .\VectorStryke.ps1 mode -Id Automatic
3. .\VectorStryke.ps1 mode -Id Manual
4. .\VectorStryke.ps1 health
5. .\VectorStryke.ps1 start

Response modes:
  Automatic — fully automatic, no approvals
  Manual    — approvals required; timeout never auto-acts
"@ | Set-Content $day1 -Encoding UTF8
    Write-Host "  [+] Config: $($Global:VSPaths.ConfigFile)" -ForegroundColor Green
    Write-Host "  [+] Day-1: $day1" -ForegroundColor Green
    Write-Host "Installation complete." -ForegroundColor Cyan
}

function Show-VSStatus {
    $cfg = Get-Config
    $running = Test-VSEngineRunning
    $st = Get-VSStatus
    Write-Host ""
    Write-Host "=== VECTORSTRYKE STATUS ===" -ForegroundColor Cyan
    Write-Host "  Version      : $($cfg.Version)"
    Write-Host "  ResponseMode : $($cfg.ResponseMode)"
    Write-Host "  Status       : $(if ($running) { 'ONLINE' } else { 'STOPPED' })"
    Write-Host "  Profile      : $($cfg.Profile)"
    Write-Host "  FirstRun     : $($cfg.FirstRunState)"
    Write-Host "  AgentId      : $($cfg.AgentId)"
    Write-Host "  TenantId     : $($cfg.TenantId)"
    Write-Host "  ImpactPending: $($cfg.ImpactPending)"
    if ($st.Mode) {
        Write-Host "  Engine Mode  : $($st.Mode)"
        Write-Host "  Findings     : $($st.FindingsCount)"
        Write-Host "  Pending      : $($st.PendingAlerts)"
        Write-Host "  HealthOk     : $($st.HealthOk)"
    }
    Write-Host "  Policy note  : timeout never auto-acts; Automatic = no approvals"
    Write-Host ""
}
