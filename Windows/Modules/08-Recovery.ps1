# VectorStryke Recovery — canaries, checkpoints, ImpactPending

function Initialize-VSCanaries {
    param([hashtable]$Config)
    $dir = $Global:VSPaths.CanaryDir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $paths = @(
        (Join-Path $dir "VS_CANARY_IMPORTANT.txt"),
        (Join-Path $dir "documents\VS_CANARY_DOC.txt"),
        (Join-Path $dir "finance\VS_CANARY_FIN.txt")
    )
    foreach ($extra in @($Config.CanaryPaths)) {
        if ($extra) { $paths += $extra }
    }
    $created = @()
    $content = "VectorStryke canary file — do not modify.`nCreated=$(Get-Date -Format o)`n"
    foreach ($p in $paths) {
        $parent = Split-Path $p -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        if (-not (Test-Path $p)) {
            Set-Content -Path $p -Value $content -Encoding UTF8
            $created += $p
        }
        $hash = (Get-FileHash -Path $p -Algorithm SHA256).Hash.ToLower()
        Set-Content -Path (Join-Path $dir ("$([IO.Path]::GetFileName($p)).sha256")) -Value $hash -Encoding UTF8
    }
    $existing = @($paths | Where-Object { Test-Path $_ })
    @{ paths = $existing; InitializedAt = (Get-Date).ToUniversalTime().ToString("o") } |
        ConvertTo-Json | Set-Content (Join-Path $dir "manifest.json") -Encoding UTF8
    return @{ ok = $true; created = $created; paths = $existing }
}

function Test-VSCanaries {
    $manPath = Join-Path $Global:VSPaths.CanaryDir "manifest.json"
    if (-not (Test-Path $manPath)) { return @{ ok = $true; skipped = $true } }
    $man = Get-Content $manPath -Raw | ConvertFrom-Json
    $failures = @()
    foreach ($ps in @($man.paths)) {
        if (-not (Test-Path $ps)) { $failures += @{ path = $ps; reason = "missing" }; continue }
        $hp = Join-Path $Global:VSPaths.CanaryDir ("$([IO.Path]::GetFileName($ps)).sha256")
        if (Test-Path $hp) {
            $expect = (Get-Content $hp -Raw).Trim().ToLower()
            $actual = (Get-FileHash -Path $ps -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expect) { $failures += @{ path = $ps; reason = "hash_mismatch" } }
        }
    }
    return @{ ok = ($failures.Count -eq 0); failures = $failures }
}

function New-VSCheckpoint {
    param([string]$Reason = "manual")
    $cid = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0,6))
    $dest = Join-Path $Global:VSPaths.CheckpointDir $cid
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $copied = @()
    if (Test-Path $Global:VSPaths.CanaryDir) {
        $cDest = Join-Path $dest "canaries"
        New-Item -ItemType Directory -Path $cDest -Force | Out-Null
        Copy-Item -Path (Join-Path $Global:VSPaths.CanaryDir "*") -Destination $cDest -Recurse -Force -ErrorAction SilentlyContinue
        $copied = @(Get-ChildItem $cDest -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }
    $notes = @()
    try {
        if (Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue) { $notes += "vss_storage_present" }
    } catch {}
    $meta = @{
        CheckpointId   = $cid
        Reason         = $Reason
        CreatedAt      = (Get-Date).ToUniversalTime().ToString("o")
        CopiedCanaries = $copied
        Notes          = $notes
        Host           = $env:COMPUTERNAME
    }
    $meta | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dest "meta.json") -Encoding UTF8
    Write-Log "Checkpoint created $cid" "HIGH"
    return $meta
}

function Test-VSEncryptionPrelude {
    param([hashtable]$Config, $Processes)
    if (-not $Config.RecoveryEnabled) { return $null }
    $score = 0
    $reasons = @()
    $v = Test-VSCanaries
    if (-not $v.ok -and -not $v.skipped) {
        $score += 50
        $reasons += "CanaryIntegrityFailed:$($v.failures.Count)"
    }
    foreach ($p in @($Processes)) {
        $n = ([string]$p.name).ToLower()
        if ($n -match "encrypt|ransom|locker|crypt") {
            $score += 30; $reasons += "SuspiciousProcess:$($p.name):$($p.pid)"
        }
        if ($n -in @("vssadmin","wbadmin") -or $n -match "shadow") {
            $score += 25; $reasons += "BackupTamperTool:$($p.name)"
        }
    }
    try {
        $hits = @(Get-ChildItem $Global:VSPaths.CanaryDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(locked|encrypted|crypted|onion)$' }).Count
        if ($hits -gt 0) { $score += 20; $reasons += "EncryptedExtensions=$hits" }
    } catch {}
    if ($score -lt 40) { return $null }
    return @{
        id = 9001; type = "ImpactPrelude"; name = "EncryptionPrelude"
        pid = 0; exe = ""; memory_mb = 0; score = [Math]::Min($score, 100)
        reasons = ($reasons -join " | "); severity = "High"
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        impact_class = $true
    }
}
