# VectorStryke OS Security Scanner (Windows)
# Quarantine-first, exclusion-aware, integrates with OS-SEC detect-first layers.
# No external dependencies. Optional VirusTotal only if API key configured.

function Initialize-VSOsScanEnv {
    param([hashtable]$Config)
    $work = if ($Config.OsScanTempDir) { $Config.OsScanTempDir } else { Join-Path $env:TEMP "VectorStryke_AVScan" }
    if (-not (Test-Path $work)) {
        New-Item -ItemType Directory -Path $work -Force | Out-Null
    }
    $q = if ($Config.OsScanQuarantineDir) { $Config.OsScanQuarantineDir } else { Join-Path $Global:VSPaths.DataDir "OsScanQuarantine" }
    if (-not (Test-Path $q)) { New-Item -ItemType Directory -Path $q -Force | Out-Null }
    $baseline = Join-Path $Global:VSPaths.DataDir "osscan_baseline.csv"
    $exclFile = if ($Config.OsScanExclusionsFile) { $Config.OsScanExclusionsFile } else { Join-Path $Global:VSPaths.DataDir "osscan_exclusions.txt" }
    if (-not (Test-Path $exclFile)) {
        @"
# VectorStryke OS scan exclusions (one path prefix or pattern per line)
C:\Windows\WinSxS
C:\`$Recycle.Bin
"@ | Set-Content $exclFile -Encoding UTF8
    }
    return @{
        WorkDir       = $work
        QuarantineDir = $q
        BaselineCsv   = $baseline
        ExclusionsFile = $exclFile
        ManifestLog   = Join-Path $q "quarantine.log"
    }
}

function Get-VSOsScanSafeZones {
    return @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        ${env:ProgramFiles},
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ -and (Test-Path $_) }
}

function Get-VSOsScanExclusions {
    param($Env, [hashtable]$Config)
    $list = @(Get-VSOsScanSafeZones)
    if (Test-Path $Env.ExclusionsFile) {
        Get-Content $Env.ExclusionsFile -ErrorAction SilentlyContinue | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#")) { $list += $line }
        }
    }
    foreach ($p in @($Config.OsScanExtraExclusions)) { if ($p) { $list += $p } }
    return $list
}

function Test-VSOsScanExcluded {
    param([string]$Path, [string[]]$Exclusions)
    $full = $Path
    foreach ($ex in $Exclusions) {
        if (-not $ex) { continue }
        if ($full.StartsWith($ex, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($full -like $ex) { return $true }
    }
    return $false
}

function Get-VSFileSha256 {
    param([string]$Path)
    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch { return $null }
}

function Initialize-VSOsScanBaseline {
    param($Env, [hashtable]$Config)
    # Hash sample of critical system files (not entire tree — practical baseline)
    $rows = @("filepath,sha256")
    $count = 0
    $max = if ($Config.OsScanBaselineMaxFiles) { [int]$Config.OsScanBaselineMaxFiles } else { 200 }
    foreach ($zone in (Get-VSOsScanSafeZones)) {
        Get-ChildItem -Path $zone -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(exe|dll|sys)$' } |
            Select-Object -First ([math]::Max(1, [int]($max / 4))) |
            ForEach-Object {
                $h = Get-VSFileSha256 $_.FullName
                if ($h) {
                    $rows += ('"{0}",{1}' -f ($_.FullName -replace '"','""'), $h)
                    $count++
                }
            }
        if ($count -ge $max) { break }
    }
    $rows | Set-Content -Path $Env.BaselineCsv -Encoding UTF8
    Write-Log "OS scan baseline written ($count files) → $($Env.BaselineCsv)" "INFO"
    return @{ ok = $true; files = $count; path = $Env.BaselineCsv }
}

function Get-VSFileEntropy {
    param([string]$Path, [int]$MaxBytes = 65536)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $buf = New-Object byte[] ([math]::Min($MaxBytes, $fs.Length))
            $read = $fs.Read($buf, 0, $buf.Length)
            if ($read -le 0) { return 0.0 }
            $freq = New-Object int[] 256
            for ($i = 0; $i -lt $read; $i++) { $freq[$buf[$i]]++ }
            $ent = 0.0
            for ($i = 0; $i -lt 256; $i++) {
                if ($freq[$i] -eq 0) { continue }
                $p = $freq[$i] / $read
                $ent -= $p * [math]::Log($p, 2)
            }
            return [math]::Round($ent, 3)
        } finally { $fs.Close() }
    } catch { return 0.0 }
}

function Test-VSSuspiciousStrings {
    param([string]$Path)
    $hits = @()
    $patterns = @("powershell -enc", "downloadstring", "frombase64string", "invoke-expression",
                  "eval(", "cmd /c", "reg add", "schtasks", "mimikatz", "virtualalloc")
    try {
        if ((Get-Item $Path).Length -gt 5MB) { return $hits }
        $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::ASCII)
        $lower = $text.ToLowerInvariant()
        foreach ($p in $patterns) {
            if ($lower.Contains($p.ToLowerInvariant())) { $hits += $p }
        }
    } catch {}
    return $hits
}

function Get-VSSignatureStatus {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if (-not $sig) { return "Missing" }
        switch ($sig.Status) {
            "Valid" { return "Valid" }
            "NotSigned" { return "Missing" }
            default { return "Invalid" }
        }
    } catch { return "Unknown" }
}

function Get-VSThreatScore {
    param([string]$SigStatus, [double]$Entropy, [int]$StringHits, [bool]$ExternalHit)
    $score = 0
    switch ($SigStatus) {
        "Valid" { $score += 0 }
        "Invalid" { $score += 50 }
        "Missing" { $score += 40 }
        default { $score += 20 }
    }
    if ($Entropy -gt 7.0) {
        $over = $Entropy - 7.0
        $score += [int]([math]::Floor($over / 0.5) * 10)
    }
    $score += ($StringHits * 5)
    if ($ExternalHit) { $score += 50 }
    if ($score -gt 100) { $score = 100 }
    return $score
}

function Invoke-VSOsScan {
    param(
        [hashtable]$Config,
        [string[]]$Roots = @(),
        [switch]$Full,
        [switch]$BuildBaselineOnly
    )
    $envScan = Initialize-VSOsScanEnv -Config $Config
    if ($BuildBaselineOnly) {
        return Initialize-VSOsScanBaseline -Env $envScan -Config $Config
    }

    # Layer integration: always detect OS security first
    $ossec = @{ Class = "Unknown" }
    if (Get-Command Invoke-VSOsSecurityDetect -ErrorAction SilentlyContinue) {
        $ossec = Invoke-VSOsSecurityDetect -Config $Config
        Write-Log "OS-SEC pre-scan class=$($ossec.Class)" "INFO"
    }

    $exclusions = @(Get-VSOsScanExclusions -Env $envScan -Config $Config)
    if (-not $Roots -or $Roots.Count -eq 0) {
        if ($Full) {
            $Roots = @("$env:SystemDrive\")
        } else {
            $Roots = @(
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Desktop",
                "$env:TEMP",
                "$env:PUBLIC"
            ) | Where-Object { Test-Path $_ }
        }
    }

    $extExec = @(".exe", ".dll", ".sys", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".scr", ".com")
    $results = @()
    $scanned = 0
    $maxFiles = if ($Config.OsScanMaxFiles) { [int]$Config.OsScanMaxFiles } else { 2000 }

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($scanned -ge $maxFiles) { return }
            $fp = $_.FullName
            if (Test-VSOsScanExcluded -Path $fp -Exclusions $exclusions) { return }
            $scanned++
            $ext = $_.Extension.ToLowerInvariant()
            $isExec = $extExec -contains $ext
            $sig = if ($isExec) { Get-VSSignatureStatus -Path $fp } else { "N/A" }
            $ent = if ($isExec) { Get-VSFileEntropy -Path $fp } else { 0.0 }
            $hits = if ($isExec -or $ext -in @(".ps1",".vbs",".js")) { @(Test-VSSuspiciousStrings -Path $fp) } else { @() }
            $hash = Get-VSFileSha256 -Path $fp
            $score = Get-VSThreatScore -SigStatus $sig -Entropy $ent -StringHits $hits.Count -ExternalHit $false
            # Data files: heuristic only, never auto high score from entropy alone
            if (-not $isExec -and $score -gt 40) { $score = 40 }
            $tier = if ($score -le 30) { "Clean" } elseif ($score -le 70) { "Suspicious" } else { "Malicious" }
            if ($tier -eq "Clean") { return }
            $results += @{
                Path = $fp; Size = $_.Length; Score = $score; Tier = $tier
                Signature = $sig; Entropy = $ent; StringHits = $hits
                Sha256 = $hash; OsSecClass = $ossec.Class
            }
        }
    }

    # Quarantine Suspicious/Malicious — never delete original first
    $autoQuarantine = $true
    if ($Config.ContainsKey("OsScanAutoQuarantine")) { $autoQuarantine = [bool]$Config.OsScanAutoQuarantine }
    $autoDeleteMalicious = $false
    if ($Config.ContainsKey("OsScanAutoDeleteMalicious")) { $autoDeleteMalicious = [bool]$Config.OsScanAutoDeleteMalicious }

    $actions = @()
    foreach ($r in $results) {
        if ($r.Tier -eq "Clean") { continue }
        if ($autoQuarantine) {
            $guid = [guid]::NewGuid().ToString("N")
            $dest = Join-Path $envScan.QuarantineDir $guid
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                $leaf = [IO.Path]::GetFileName($r.Path)
                Move-Item -Path $r.Path -Destination (Join-Path $dest $leaf) -Force -ErrorAction Stop
                $line = "{0}|{1}|{2}|{3}|{4}" -f (Get-Date -Format o), $r.Path, (Join-Path $dest $leaf), $r.Score, $r.Tier
                Add-Content -Path $envScan.ManifestLog -Value $line -Encoding UTF8
                $r.Quarantined = $true
                $r.QuarantinePath = Join-Path $dest $leaf
                $actions += "Quarantined:$($r.Path)"
                Write-Log "OS scan quarantined score=$($r.Score) $($r.Path)" "HIGH"
            } catch {
                $r.Quarantined = $false
                $r.Error = "$_"
                Write-Log "OS scan quarantine failed $($r.Path): $_" "ERROR"
            }
        }
        # Auto-delete only if explicitly enabled AND Malicious AND already quarantined
        # Default OFF — user confirmation required per algorithm
        if ($autoDeleteMalicious -and $r.Tier -eq "Malicious" -and $r.Quarantined) {
            # File already moved; original path gone — permanent delete of quarantine copy is separate policy
            $actions += "MaliciousQuarantinedAwaitingReview:$($r.Path)"
        }
    }

    $report = @{
        ScannedFiles   = $scanned
        Findings       = $results
        Actions        = $actions
        OsSecClass     = $ossec.Class
        OsSecFallbackEligible = $ossec.FallbackEligible
        QuarantineDir  = $envScan.QuarantineDir
        CompletedAt    = (Get-Date).ToUniversalTime().ToString("o")
        ExitCode       = 0
    }
    $reportPath = Join-Path $Global:VSPaths.DataDir ("osscan_report_{0}.json" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $report | ConvertTo-Json -Depth 8 | Set-Content $reportPath -Encoding UTF8
    $report.ReportPath = $reportPath
    return $report
}

function Restore-VSOsScanQuarantine {
    param([string]$QuarantineFile, [string]$OriginalPath)
    if (-not (Test-Path $QuarantineFile)) { return @{ ok = $false; error = "not_found" } }
    try {
        $parent = Split-Path $OriginalPath -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Move-Item -Path $QuarantineFile -Destination $OriginalPath -Force
        return @{ ok = $true; restored = $OriginalPath }
    } catch {
        return @{ ok = $false; error = "$_" }
    }
}
