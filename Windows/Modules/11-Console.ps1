# VectorStryke Console client — fails soft offline

function Invoke-VSConsoleJson {
    param([string]$Method, [string]$Url, [hashtable]$Payload = $null, [string]$Token = "", [int]$TimeoutSec = 5)
    try {
        $headers = @{ "User-Agent" = "VectorStryke-Agent/1.7" }
        if ($Token) { $headers["X-Enrollment-Token"] = $Token }
        $body = $null
        if ($Payload) { $body = $Payload | ConvertTo-Json -Depth 8 -Compress }
        $resp = Invoke-RestMethod -Uri $Url -Method $Method -Headers $headers -Body $body -ContentType "application/json" -TimeoutSec $TimeoutSec -ErrorAction Stop
        return $resp
    } catch {
        return $null
    }
}

function Ensure-VSAgentId {
    param([hashtable]$Config)
    if ($Config.AgentId) { return $Config }
    $raw = "$env:COMPUTERNAME|$env:PROCESSOR_IDENTIFIER|$env:SystemDrive"
    $bytes = [Text.Encoding]::UTF8.GetBytes($raw)
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    $Config.AgentId = "win-" + $hash.Substring(0, 12)
    Save-Config $Config
    return $Config
}

function Invoke-VSConsoleEnroll {
    param([hashtable]$Config)
    if (-not $Config.ConsoleEnabled -or -not $Config.ConsoleUrl) { return $Config }
    $base = $Config.ConsoleUrl.TrimEnd("/")
    $hostName = if ($Config.HostnameOverride) { $Config.HostnameOverride } else { $env:COMPUTERNAME }
    $r = Invoke-VSConsoleJson -Method POST -Url "$base/api/enroll" -Token $Config.EnrollmentToken -Payload @{
        TenantId = $Config.TenantId
        AgentId  = $Config.AgentId
        Hostname = $hostName
        Platform = "Windows"
        Version  = $Config.Version
    }
    if ($r -and $r.AgentId -and -not $Config.AgentId) {
        $Config.AgentId = $r.AgentId
        Save-Config $Config
    }
    return $Config
}

function Invoke-VSConsoleHeartbeat {
    param([hashtable]$Config, [hashtable]$Status)
    if (-not $Config.ConsoleEnabled -or -not $Config.ConsoleUrl) { return @() }
    $base = $Config.ConsoleUrl.TrimEnd("/")
    $hostName = if ($Config.HostnameOverride) { $Config.HostnameOverride } else { $env:COMPUTERNAME }
    $r = Invoke-VSConsoleJson -Method POST -Url "$base/api/heartbeat" -Token $Config.EnrollmentToken -Payload @{
        TenantId = $Config.TenantId
        AgentId  = $Config.AgentId
        Hostname = $hostName
        Platform = "Windows"
        Version  = $Config.Version
        Status   = $Status
    }
    if ($r -and $r.commands) { return @($r.commands) }
    return @()
}
