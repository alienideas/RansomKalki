# VectorStryke Update + LKG

function Save-VSLastKnownGood {
    param([hashtable]$Config)
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $dest = Join-Path $Global:VSPaths.LkgDir $stamp
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    if (Test-Path $Global:VSPaths.ConfigFile) {
        Copy-Item $Global:VSPaths.ConfigFile (Join-Path $dest "engine.json") -Force
    }
    @{
        Version      = $Config.Version
        SavedAt      = (Get-Date).ToUniversalTime().ToString("o")
        Profile      = $Config.Profile
        ResponseMode = $Config.ResponseMode
    } | ConvertTo-Json | Set-Content (Join-Path $dest "meta.json") -Encoding UTF8
    Set-Content -Path (Join-Path $Global:VSPaths.LkgDir "CURRENT") -Value $dest -Encoding UTF8
    Write-Log "LKG saved at $dest" "INFO"
    return $dest
}

function Invoke-VSRollbackLkg {
    $cur = Join-Path $Global:VSPaths.LkgDir "CURRENT"
    $dest = $null
    if (Test-Path $cur) {
        $dest = (Get-Content $cur -Raw).Trim()
    } else {
        $dirs = Get-ChildItem $Global:VSPaths.LkgDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        if ($dirs) { $dest = $dirs[0].FullName }
    }
    if (-not $dest -or -not (Test-Path (Join-Path $dest "engine.json"))) {
        return @{ ok = $false; error = "no_lkg" }
    }
    Copy-Item (Join-Path $dest "engine.json") $Global:VSPaths.ConfigFile -Force
    Write-Log "Rolled back config from LKG $dest" "WARN"
    return @{ ok = $true; restored_from = $dest }
}

function Invoke-VSUpdateCheck {
    param([hashtable]$Config)
    $result = @{
        CurrentVersion = $Config.Version
        Channel        = $Config.UpdateChannel
        Available      = $false
        Manifest       = $null
        Error          = ""
    }
    $local = Join-Path $Global:VSPaths.UpdateDir "manifest.json"
    if (Test-Path $local) {
        try {
            $man = Get-Content $local -Raw | ConvertFrom-Json
            $result.Manifest = $man
            if ($man.Version -and $man.Version -ne $result.CurrentVersion) {
                $result.Available = $true
            }
        } catch {
            $result.Error = "local_manifest:$_"
        }
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Global:VSPaths.UpdateDir "last_check.json") -Encoding UTF8
    return $result
}

function Invoke-VSUpdateApply {
    param([hashtable]$Config, [switch]$Force)
    if ($Config.FirstRunState -ne "Steady" -and -not $Force) {
        return @{ ok = $false; error = "first_run_not_steady" }
    }
    $check = Invoke-VSUpdateCheck -Config $Config
    $man = $check.Manifest
    if (-not $check.Available -and -not $Force) {
        return @{ ok = $false; error = "no_update_available"; check = $check }
    }
    $files = @()
    if ($man.Files) { $files = @($man.Files) }
    elseif ($man.files) { $files = @($man.files) }
    $packageRoot = Join-Path $Global:VSPaths.UpdateDir "package"
    foreach ($item in $files) {
        $rel = if ($item.path) { $item.path } elseif ($item.Path) { $item.Path } else { "" }
        $expect = if ($item.sha256) { $item.sha256 } elseif ($item.Sha256) { $item.Sha256 } else { "" }
        $fp = Join-Path $packageRoot $rel
        if (-not (Test-Path $fp)) { return @{ ok = $false; error = "missing_file:$rel" } }
        if ($expect) {
            $h = (Get-FileHash -Path $fp -Algorithm SHA256).Hash.ToLower()
            if ($h -ne $expect.ToLower()) { return @{ ok = $false; error = "hash_mismatch:$rel" } }
        }
    }
    $lkg = Save-VSLastKnownGood -Config $Config
    $applied = @()
    foreach ($item in $files) {
        $rel = if ($item.path) { $item.path } elseif ($item.Path) { $item.Path } else { "" }
        $src = Join-Path $packageRoot $rel
        if ([IO.Path]::GetFileName($rel) -eq "threat_intel.txt") {
            $dst = $Global:VSPaths.IntelFile
        } else {
            $dst = Join-Path $Global:VSPaths.Root $rel
        }
        try {
            $parent = Split-Path $dst -Parent
            if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Copy-Item $src $dst -Force
            $applied += $rel
        } catch {
            Invoke-VSRollbackLkg | Out-Null
            return @{ ok = $false; error = "apply:$rel:$_"; lkg = $lkg }
        }
    }
    if ($man.Version) { $Config.Version = $man.Version }
    return @{ ok = $true; applied = $applied; version = $Config.Version; lkg = $lkg }
}
