# VectorStryke Detection engines

function Get-VSBuiltInIntel {
    return @{
        process_names = @("xmrig","minerd","mimikatz","cobalt","ransom","encrypt","locker","wannacry","ryuk","conti")
        path_patterns = @("\Temp\","\AppData\Local\Temp\","\Users\Public\")
    }
}

function Get-VSThreatIntel {
    $intel = Get-VSBuiltInIntel
    $f = $Global:VSPaths.IntelFile
    if (Test-Path $f) {
        Get-Content $f -ErrorAction SilentlyContinue | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#")) {
                $intel.process_names += $line.ToLower()
            }
        }
    }
    return $intel
}

function Invoke-VSDetect {
    param([hashtable]$Snapshot, [hashtable]$Config)
    $findings = @()
    $fid = 0
    $intel = Get-VSThreatIntel
    $highMem = [int]$Config.HighMemoryMB
    $highThr = [int]$Config.HighThreadCount
    $critical = @("System","Idle","svchost","csrss","smss","wininit","services","lsass","explorer","powershell","pwsh")

    foreach ($p in @($Snapshot.processes)) {
        $name = [string]$p.name
        if ($critical -contains $name) { continue }
        $score = 0
        $reasons = @()
        $nl = $name.ToLower()
        $exe = ([string]$p.exe).ToLower()
        foreach ($bad in $intel.process_names) {
            if ($nl -like "*$bad*") { $score += 40; $reasons += "Threat intel name: $bad"; break }
        }
        foreach ($pat in $intel.path_patterns) {
            if ($exe -like "*$($pat.ToLower())*") { $score += 25; $reasons += "Suspicious path"; break }
        }
        if ([double]$p.memory_mb -gt $highMem) { $score += 15; $reasons += "High memory $($p.memory_mb) MB" }
        if ([int]$p.threads -gt $highThr) { $score += 15; $reasons += "High threads $($p.threads)" }
        if ($score -ge 40) {
            $fid++
            $findings += @{
                id        = $fid
                type      = "Process"
                name      = $name
                pid       = $p.pid
                exe       = $p.exe
                memory_mb = $p.memory_mb
                score     = $score
                reasons   = ($reasons -join " | ")
                severity  = $(if ($score -ge 70) { "High" } else { "Medium" })
                timestamp = (Get-Date).ToUniversalTime().ToString("o")
            }
        }
    }
    if ([double]$Snapshot.memory_used_pct -ge 90) {
        $fid++
        $findings += @{
            id = $fid; type = "System"; name = "HighMemoryPressure"; pid = 0; exe = ""
            memory_mb = 0; score = 50; reasons = "Memory $($Snapshot.memory_used_pct)%"
            severity = "High"; timestamp = (Get-Date).ToUniversalTime().ToString("o")
        }
    }
    return $findings
}
