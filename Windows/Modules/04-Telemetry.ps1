# VectorStryke Telemetry sensors

function Invoke-VSCollect {
    $procs = @()
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $exe = ""
            try { $exe = $_.Path } catch {}
            $procs += @{
                pid       = $_.Id
                name      = $_.ProcessName
                exe       = $exe
                memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 1)
                threads   = $_.Threads.Count
            }
        }
    } catch {}
    $memPct = 0
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $memPct = [math]::Round(100 * ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize, 1)
        }
    } catch {}
    return @{
        processes        = $procs
        memory_used_pct  = $memPct
        collected_at     = (Get-Date).ToUniversalTime().ToString("o")
    }
}
