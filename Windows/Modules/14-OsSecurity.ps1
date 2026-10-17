# VectorStryke OS Security — detect-first (Present | Partial | Absent)
# Never disables Defender/EDR. Fallback apply gated (not auto by default).

function Get-VSOsSecurityKnownAgents {
    param([hashtable]$Config)
    $list = @(
        "MsMpEng", "MSSense", "WinDefend",
        "CSFalconService", "CSFalconContainer",
        "SentinelAgent", "SentinelStaticEngine",
        "xagt", "mfetp", "mcshield", "savservice",
        "bdagent", "SophosHealth", "Elastic Agent", "osqueryd"
    )
    foreach ($n in @($Config.OsSecurityKnownAgentNames)) {
        if ($n) { $list += $n }
    }
    return $list
}

function Invoke-VSOsSecurityDetect {
    param([hashtable]$Config)
    $signals = @{
        DefenderPresent = $false
        RealTimeOn      = $null
        CFA             = $null
        Firewall        = @{}
        Agents          = @()
        Platform        = "Windows"
        Errors          = @()
    }
    if ($Config.ContainsKey("OsSecurityEnabled") -and $Config.OsSecurityEnabled -eq $false) {
        return @{ Skipped = $true; Class = "Unknown"; Signals = $signals; FallbackEligible = $false; FallbackActive = $false; Recommendations = @() }
    }

    # Defender process/service
    try {
        $p = Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue
        if ($p) { $signals.DefenderPresent = $true; $signals.Agents += "MsMpEng" }
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            $signals.DefenderPresent = $true
            if ($signals.Agents -notcontains "WinDefend") { $signals.Agents += "WinDefend" }
        }
    } catch { $signals.Errors += "defender_probe:$_" }

    # MpComputerStatus
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($st) {
                $signals.DefenderPresent = $true
                $signals.RealTimeOn = [bool]$st.RealTimeProtectionEnabled
            }
        }
    } catch { $signals.Errors += "mpstatus:$_" }

    # CFA
    if ($Config.OsSecurityControlledFolderAccessCheck -ne $false) {
        try {
            if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
                $pref = Get-MpPreference -ErrorAction SilentlyContinue
                if ($null -ne $pref.EnableControlledFolderAccess) {
                    $v = [int]$pref.EnableControlledFolderAccess
                    $signals.CFA = @{ 0 = "Disabled"; 1 = "Enabled"; 2 = "Audit" }[$v]
                    if (-not $signals.CFA) { $signals.CFA = "$v" }
                }
            }
        } catch { $signals.Errors += "cfa:$_" }
    }

    # Firewall
    if ($Config.OsSecurityFirewallProfileCheck -ne $false) {
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $fw = @{}
            foreach ($pr in @($profiles)) {
                $fw[$pr.Name] = [bool]$pr.Enabled
            }
            $signals.Firewall = $fw
        } catch { $signals.Errors += "firewall:$_" }
    }

    # Third-party agents
    try {
        $known = Get-VSOsSecurityKnownAgents -Config $Config
        $procs = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique
        foreach ($k in $known) {
            $kl = $k.ToLower()
            foreach ($pn in $procs) {
                if ($pn.ToLower() -like "*$kl*" -or $kl -like "*$($pn.ToLower())*") {
                    if ($signals.Agents -notcontains $pn) { $signals.Agents += $pn }
                }
            }
        }
    } catch { $signals.Errors += "agents:$_" }

    $klass = Invoke-VSOsSecurityClassify -Signals $signals -Config $Config
    $recs = Invoke-VSOsSecurityRecommend -Class $klass -Signals $signals
    $detectionOnly = $true
    if ($Config.ContainsKey("OsSecurityDetectionOnly")) { $detectionOnly = [bool]$Config.OsSecurityDetectionOnly }
    $fbEnabled = $false
    if ($Config.ContainsKey("OsSecurityFallbackEnabled")) { $fbEnabled = [bool]$Config.OsSecurityFallbackEnabled }
    $eligible = ($klass -eq "Absent") -and $fbEnabled -and (-not $detectionOnly)

    return @{
        Class             = $klass
        Signals           = $signals
        Recommendations   = $recs
        FallbackEligible  = $eligible
        FallbackActive    = $false
        Skipped           = $false
    }
}

function Invoke-VSOsSecurityClassify {
    param($Signals, [hashtable]$Config)
    if ($Signals.RealTimeOn -eq $true) { return "Present" }
    if ($Signals.DefenderPresent -and $Signals.RealTimeOn -ne $false) {
        # Present if defender present unless realtime explicitly off
        if ($Signals.RealTimeOn -eq $false) { return "Partial" }
        return "Present"
    }
    if ($Signals.CFA -eq "Enabled") { return "Present" }
    $agents = @($Signals.Agents)
    if ($agents.Count -gt 0) { return "Present" }
    if ($Signals.CFA -eq "Audit") { return "Partial" }
    $fwOn = $false
    foreach ($k in @($Signals.Firewall.Keys)) {
        if ($Signals.Firewall[$k]) { $fwOn = $true; break }
    }
    if ($fwOn) { return "Partial" }
    if ($Signals.DefenderPresent -and $Signals.RealTimeOn -eq $false) { return "Partial" }
    return "Absent"
}

function Invoke-VSOsSecurityRecommend {
    param([string]$Class, $Signals)
    $recs = @()
    if ($Class -eq "Partial") {
        if ($Signals.RealTimeOn -eq $false) { $recs += "EnableRealtimeProtection" }
        if ($Signals.CFA -eq "Disabled" -or $Signals.CFA -eq $null) { $recs += "EnableControlledFolderAccess" }
        $fwOn = $false
        foreach ($k in @($Signals.Firewall.Keys)) { if ($Signals.Firewall[$k]) { $fwOn = $true } }
        if (-not $fwOn) { $recs += "EnableHostFirewall" }
    }
    if ($Class -eq "Absent") {
        $recs += "NoOsSecurityDetected_ConsiderFallbackOrInstallAV"
    }
    return $recs
}
