# VectorStryke Paths — dependency-free layout
$script:VSRoot = $Global:VectorStrykeRoot
if (-not $script:VSRoot) { $script:VSRoot = Split-Path -Parent $PSScriptRoot }

$Global:VSPaths = [ordered]@{
    Root          = $script:VSRoot
    DataDir       = Join-Path $script:VSRoot "Data"
    LogDir        = Join-Path $script:VSRoot "Logs"
    ConfigDir     = Join-Path $script:VSRoot "Config"
    ConfigFile    = Join-Path $script:VSRoot "Config\engine.json"
    StatusFile    = Join-Path $script:VSRoot "Data\status.json"
    AlertDir      = Join-Path $script:VSRoot "Data\alerts"
    QuarantineDir = Join-Path $script:VSRoot "Data\Quarantine"
    IntelFile     = Join-Path $script:VSRoot "Data\threat_intel.txt"
    PidFile       = Join-Path $script:VSRoot "Data\vectorstryke.pid"
    LogFile       = Join-Path $script:VSRoot "Logs\engine.log"
    LkgDir        = Join-Path $script:VSRoot "Data\last_known_good"
    UpdateDir     = Join-Path $script:VSRoot "Data\updates"
    CanaryDir     = Join-Path $script:VSRoot "Data\canaries"
    CheckpointDir = Join-Path $script:VSRoot "Data\checkpoints"
    HealthFile    = Join-Path $script:VSRoot "Data\health.json"
    Version       = "1.7.0"
}

function Initialize-VSPaths {
    foreach ($k in @("DataDir","LogDir","ConfigDir","AlertDir","QuarantineDir","LkgDir","UpdateDir","CanaryDir","CheckpointDir")) {
        $p = $Global:VSPaths[$k]
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}
