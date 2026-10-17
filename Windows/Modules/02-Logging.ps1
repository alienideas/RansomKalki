# VectorStryke logging

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    try { Add-Content -Path $Global:VSPaths.LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($Level -in @("HIGH","ERROR","WARN")) {
        Write-Host $line -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "HIGH") { "Magenta" } else { "Yellow" })
    }
}
