# VectorStryke Responders

function Invoke-VSAction {
    param([hashtable]$Finding, [hashtable]$Config)
    if (-not $Config.AgentEnabled) {
        Write-Log "Agent disabled — skip action" "WARN"
        return $false
    }
    $name = ([string]$Finding.name).ToLower()
    $exe  = ([string]$Finding.exe).ToLower()
    foreach ($n in @($Config.AllowlistProcesses)) {
        if ($n -and $name -like "*$($n.ToLower())*") {
            Write-Log "Allowlisted process: $name" "INFO"
            return $false
        }
    }
    foreach ($p in @($Config.AllowlistPaths)) {
        if ($p -and $exe -like "*$($p.ToLower())*") {
            Write-Log "Allowlisted path: $exe" "INFO"
            return $false
        }
    }
    $pidVal = 0
    if ($Finding.ContainsKey("pid")) { $pidVal = [int]$Finding.pid }
    if ($pidVal -gt 0) {
        try {
            Stop-Process -Id $pidVal -Force -ErrorAction Stop
            Write-Log "Killed PID $pidVal ($($Finding.name))" "HIGH"
        } catch {
            Write-Log "Kill failed PID $pidVal : $_" "ERROR"
        }
    }
    if ($Finding.exe -and (Test-Path $Finding.exe)) {
        $sysRoots = @("$env:SystemRoot\System32","$env:SystemRoot\SysWOW64","$env:SystemRoot")
        $isSystem = $false
        foreach ($r in $sysRoots) {
            if ($Finding.exe.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { $isSystem = $true; break }
        }
        if (-not $isSystem) {
            try {
                $dest = Join-Path $Global:VSPaths.QuarantineDir ("{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), [IO.Path]::GetFileName($Finding.exe))
                Move-Item -Path $Finding.exe -Destination $dest -Force -ErrorAction Stop
                Write-Log "Quarantined $($Finding.exe) -> $dest" "HIGH"
            } catch {
                Write-Log "Quarantine failed: $_" "ERROR"
            }
        }
    }
    return $true
}
