# VectorStryke Self-Health

function Invoke-VSSelfHealth {
    param([hashtable]$Config)
    $issues = @()
    $ok = $true
    foreach ($k in @("Root","ConfigDir","DataDir","LogDir","QuarantineDir","CanaryDir","CheckpointDir","LkgDir")) {
        if (-not (Test-Path $Global:VSPaths[$k])) {
            $issues += "missing_path:$k"
            $ok = $false
        }
    }
    if (-not (Test-Path $Global:VSPaths.ConfigFile)) {
        $issues += "missing_config"
        $ok = $false
    }
    foreach ($key in @("Profile","FirstRunState","ResponseMode","RecoveryEnabled")) {
        if (-not $Config.ContainsKey($key)) {
            $issues += "schema_missing:$key"
            $ok = $false
        }
    }
    if ($Config.ConsoleEnabled -and -not [string]$Config.ConsoleUrl) {
        $issues += "console_enabled_without_url"
        $ok = $false
    }
    $ossec = @{ Class = "Unknown"; FallbackEligible = $false; FallbackActive = $false }
    try {
        if (Get-Command Invoke-VSOsSecurityDetect -ErrorAction SilentlyContinue) {
            $ossec = Invoke-VSOsSecurityDetect -Config $Config
        }
    } catch { $ossec = @{ Class = "Unknown"; Errors = @("$_") } }
    $result = @{
        Ok            = $ok
        Version       = $Config.Version
        Profile       = $Config.Profile
        FirstRunState = $Config.FirstRunState
        ResponseMode  = $Config.ResponseMode
        Issues        = $issues
        OsSecurity    = $ossec
        CheckedAt     = (Get-Date).ToUniversalTime().ToString("o")
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content $Global:VSPaths.HealthFile -Encoding UTF8
    return $result
}
