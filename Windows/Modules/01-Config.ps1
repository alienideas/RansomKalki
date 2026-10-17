# VectorStryke ConfigManager — encapsulated defaults + ResponseMode

function Get-VSDefaultConfig {
    return @{
        Version                   = "1.7.0"
        Profile                   = "Server"
        FirstRunState             = "PendingConfig"
        ResponseMode              = "Automatic"   # Automatic | Manual
        PollIntervalIdleSec       = 60
        PollIntervalAlertSec      = 15
        ApprovalTimeoutImpact     = 600
        ApprovalTimeoutNormal     = 3600
        HighMemoryMB              = 700
        HighThreadCount           = 90
        AdminEmail                = "admin@company.com"
        EnableEmail               = $false
        AutoApproveEnabled        = $false
        AutoApproveScoreThreshold = 80
        AutoApproveOnTimeout      = $false        # never auto-act on timeout
        RequireApprovalForImpact  = $true
        AutoApproveRemovals       = $false
        AutoApproveEncryptionStop = $false
        ConsoleEnabled            = $false
        ConsoleUrl                = ""
        TenantId                  = "default"
        AgentId                   = ""
        EnrollmentToken           = ""
        HostnameOverride          = ""
        AgentEnabled              = $true
        AllowlistProcesses        = @()
        AllowlistPaths            = @()
        UpdateChannel             = "stable"
        UpdateAutoApply           = $false
        UpdateCheckUrl            = ""
        UpdateDeferDays           = 0
        UpdateRing                = "Ring2"
        RecoveryEnabled           = $true
        CanaryEnabled             = $true
        CanaryPaths               = @()
        CheckpointWebhook         = ""
        SoftContainmentEnabled    = $true
        ImpactPending             = $false
        OsSecurityEnabled         = $true
        OsSecurityDetectionOnly   = $true
        OsSecurityFallbackEnabled = $false
        OsSecurityFallbackAutoOnAbsent = $false
        OsSecurityMode            = "Auto"
        OsSecurityKnownAgentNames = @()
        OsSecurityControlledFolderAccessCheck = $true
        OsSecurityFirewallProfileCheck = $true
        OsScanMaxFiles              = 2000
        OsScanAutoQuarantine        = $true
        OsScanAutoDeleteMalicious   = $false
        OsScanExtraExclusions       = @()
        LastCheckpointId          = ""
    }
}

function Get-Config {
    $default = Get-VSDefaultConfig
    $cfgFile = $Global:VSPaths.ConfigFile
    if (Test-Path $cfgFile) {
        try {
            $raw = Get-Content $cfgFile -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($k in @($default.Keys)) {
                if ($null -ne $raw.$k) { $default[$k] = $raw.$k }
            }
        } catch {}
    }
    $mode = [string]$default.ResponseMode
    if ($mode -notin @("Automatic","Manual")) { $mode = "Automatic"; $default.ResponseMode = $mode }
    if ($mode -eq "Manual") {
        $default.AutoApproveOnTimeout = $false
        $default.AutoApproveEnabled = $false
    }
    return $default
}

function Save-Config {
    param([hashtable]$Config)
    $mode = [string]$Config.ResponseMode
    if ($mode -eq "Manual") {
        $Config.AutoApproveOnTimeout = $false
        $Config.AutoApproveEnabled = $false
    }
    $dir = Split-Path $Global:VSPaths.ConfigFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Config | ConvertTo-Json -Depth 8 | Set-Content -Path $Global:VSPaths.ConfigFile -Encoding UTF8
}

function Set-VSResponseMode {
    param([Parameter(Mandatory)][ValidateSet("Automatic","Manual","auto","manual")][string]$Mode)
    if ($Mode -eq "auto") { $Mode = "Automatic" }
    if ($Mode -eq "manual") { $Mode = "Manual" }
    $cfg = Get-Config
    $cfg.ResponseMode = $Mode
    if ($Mode -eq "Manual") {
        $cfg.AutoApproveOnTimeout = $false
        $cfg.AutoApproveEnabled = $false
    }
    Save-Config $cfg
    return $cfg
}
