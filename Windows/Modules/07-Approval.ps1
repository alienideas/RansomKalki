# VectorStryke ApprovalManager — Manual mode only; timeout never auto-acts

function Submit-VSApproval {
    param([hashtable]$Finding, [int]$TimeoutSec)
    $alertId = [guid]::NewGuid().ToString("N").Substring(0,12)
    $expires = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSec).ToString("o")
    $package = @{
        AlertId     = $alertId
        Finding     = $Finding
        Status      = "Pending"
        SubmittedAt = (Get-Date).ToUniversalTime().ToString("o")
        ExpiresAt   = $expires
        TimeoutSec  = $TimeoutSec
    }
    $path = Join-Path $Global:VSPaths.AlertDir "$alertId.json"
    $package | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
    Write-Log "Pending approval $alertId for $($Finding.name) score=$($Finding.score)" "HIGH"
    return $alertId
}

function Get-VSPendingApprovals {
    $out = @()
    Get-ChildItem -Path $Global:VSPaths.AlertDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $a = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if ($a.Status -eq "Pending") {
                $out += @{
                    AlertId     = $a.AlertId
                    Status      = $a.Status
                    SubmittedAt = $a.SubmittedAt
                    ExpiresAt   = $a.ExpiresAt
                    TimeoutSec  = $a.TimeoutSec
                    Finding     = $a.Finding
                }
            }
        } catch {}
    }
    return $out
}

function Resolve-VSApproval {
    param([string]$AlertId, [string]$Decision)
    $path = Join-Path $Global:VSPaths.AlertDir "$AlertId.json"
    if (-not (Test-Path $path)) {
        Get-ChildItem -Path $Global:VSPaths.AlertDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $a = Get-Content $_.FullName -Raw | ConvertFrom-Json
                if ($a.AlertId -eq $AlertId) { $path = $_.FullName }
            } catch {}
        }
    }
    if (-not (Test-Path $path)) { return $null }
    try {
        $a = Get-Content $path -Raw | ConvertFrom-Json
        $obj = @{
            AlertId     = $a.AlertId
            Finding     = $a.Finding
            Status      = $Decision
            SubmittedAt = $a.SubmittedAt
            ExpiresAt   = $a.ExpiresAt
            ResolvedAt  = (Get-Date).ToUniversalTime().ToString("o")
        }
        $obj | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
        return $obj
    } catch { return $null }
}

function Process-VSTimeoutsManualOnly {
    # Timeout never auto-acts — expire only
    $now = (Get-Date).ToUniversalTime()
    foreach ($p in @(Get-VSPendingApprovals)) {
        try {
            $exp = [datetime]::Parse([string]$p.ExpiresAt).ToUniversalTime()
            if ($now -gt $exp) {
                Resolve-VSApproval -AlertId $p.AlertId -Decision "Timeout-Expired-ManualOnly" | Out-Null
                Write-Log "Timeout expired (manual-only, no auto-action) for $($p.AlertId)" "WARN"
            }
        } catch {}
    }
}
