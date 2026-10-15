#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RansomKalki - Anti-Ransomware + System Cleaner Engine for Windows
.DESCRIPTION
    Low-resource, dependency-free security engine.
    Supports: start / stop / status / monit / logs / approve / deny
    Copyright © RansomKalki
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("start","stop","status","monit","logs","scan","approve","deny","install","uninstall","dashboard","simulate","capture","pcap","help")]
    [string]$Command = "help",

    [string]$Id = "",
    [int]$Port = 8787,
    [ValidateSet("baseline","exfil","c2","ransomware","mixed")]
    [string]$SimMode = "mixed",
    [int]$DurationSec = 60,
    [int]$SampleSec = 5,
    [string]$Filter = "",
    [switch]$Full,
    [switch]$Daemon
)

$ErrorActionPreference = "SilentlyContinue"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Global:RansomKalkiRoot = $ScriptRoot

# Paths
$Global:DataDir     = Join-Path $ScriptRoot "Data"
$Global:LogDir      = Join-Path $ScriptRoot "Logs"
$Global:ConfigFile  = Join-Path $ScriptRoot "Config\engine.json"
$Global:StatusFile  = Join-Path $DataDir "status.json"
$Global:AlertDir    = Join-Path $DataDir "alerts"
$Global:IntelFile   = Join-Path $DataDir "threat_intel.txt"
$Global:PidFile     = Join-Path $DataDir "ransomkalki.pid"
$Global:LogFile     = Join-Path $LogDir  "engine.log"

# Ensure directories
@($DataDir, $LogDir, $AlertDir, (Join-Path $ScriptRoot "Config")) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# -------------------- Helpers --------------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Level -eq "ERROR") { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $line -ForegroundColor Yellow }
    elseif ($Level -eq "HIGH") { Write-Host $line -ForegroundColor Magenta }
    else { Write-Host $line -ForegroundColor Gray }
}

function Get-Config {
    $default = @{
        PollIntervalIdleSec      = 60
        PollIntervalAlertSec     = 15
        ApprovalTimeoutImpact    = 600    # 10 min for high-severity
        ApprovalTimeoutNormal    = 3600   # 60 min for medium
        HighMemoryMB             = 700
        HighThreadCount          = 90
        AdminEmail               = "admin@company.com"
        EnableEmail              = $false
        QuarantineDir            = (Join-Path $DataDir "Quarantine")
        # --- Auto-Approval settings ---
        AutoApproveEnabled       = $true   # Master switch for auto-approval
        AutoApproveScoreThreshold= 80      # Score >= this → auto-approve & act immediately (no wait)
        AutoApproveOnTimeout     = $true   # If still pending when timeout expires → auto-act
        RequireApprovalForImpact = $true   # Force approval path for encryption/impact-class events even if score high
    }
    if (Test-Path $ConfigFile) {
        try {
            $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            foreach ($k in $default.Keys) {
                if ($null -ne $cfg.$k) { $default[$k] = $cfg.$k }
            }
        } catch {}
    } else {
        # Write default config on first run so admins can edit it
        $default | ConvertTo-Json -Depth 4 | Set-Content $ConfigFile -Encoding UTF8
    }
    return $default
}

function Save-Status {
    param($Status)
    $Status | ConvertTo-Json -Depth 6 | Set-Content $StatusFile -Encoding UTF8
}

function Get-Status {
    if (Test-Path $StatusFile) {
        try { return Get-Content $StatusFile -Raw | ConvertFrom-Json } catch {}
    }
    return $null
}

function Test-EngineRunning {
    if (-not (Test-Path $PidFile)) { return $false }
    $pid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if (-not $pid) { return $false }
    $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
    return ($null -ne $p)
}

# -------------------- Critical process protection --------------------
$CriticalProcesses = @(
    "System","Idle","smss","csrss","wininit","winlogon","services","lsass",
    "svchost","explorer","dwm","fontdrvhost","Registry","conhost","sihost",
    "taskhostw","RuntimeBroker","MsMpEng","NisSrv","SecurityHealthService",
    "powershell","pwsh","RansomKalki"
)

# -------------------- Threat Intel (simplified from AutoRAMGuard) --------------------
function Get-BuiltInIntel {
    return @{
        ProcessNames = @(
            "xmrig","minerd","cpuminer","nicehash","ethminer","phoenixminer","nbminer",
            "gminer","t-rex","lolminer","miner","coinminer","cryptominer","hashrate",
            "searchprotect","conduit","genieo","dealply","babylon","yontoo","opencandy",
            "installcore","superfish","coupon","toolbar","optimizer","cleanerpro",
            "systemupdate","browserupdate","chromeupdate","softwareupdate"
        )
        PathPatterns = @(
            "\\Temp\\","\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\",
            "\\Users\\Public\\","\\ProgramData\\","\\Windows\\Temp\\","\\Downloads\\"
        )
    }
}

function Load-ThreatIntel {
    $intel = Get-BuiltInIntel
    if (Test-Path $IntelFile) {
        $section = ""
        Get-Content $IntelFile -ErrorAction SilentlyContinue | ForEach-Object {
            $line = $_.Trim()
            if ($line -match '^#' -or $line -eq "") { return }
            if ($line -match '^\[(.+)\]$') { $section = $Matches[1].ToUpper(); return }
            if ($section -eq "PROCESS_NAMES") { $intel.ProcessNames += $line }
            if ($section -eq "PATH_PATTERNS") { $intel.PathPatterns += $line }
        }
    }
    return $intel
}

# -------------------- Real Network Flow Capture (no external deps) --------------------
# Captures connection table + interface byte counters. Full payload capture would need Npcap.
function Test-PrivateIP {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $true }
    if ($IP -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|fe80:|fc00:|fd)') { return $true }
    if ($IP -eq '0.0.0.0' -or $IP -eq '::') { return $true }
    return $false
}

function Get-InterfaceBytes {
    $sent = [int64]0; $recv = [int64]0
    try {
        Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object {
            $s = Get-NetAdapterStatistics -Name $_.Name -ErrorAction SilentlyContinue
            if ($s) { $sent += $s.SentBytes; $recv += $s.ReceivedBytes }
        }
    } catch {}
    return @{ Sent = $sent; Recv = $recv }
}

function Invoke-NetworkCapture {
    param([int]$SampleSeconds = 5)

    $bytes1 = Get-InterfaceBytes
    $t1 = Get-Date

    # Connection snapshot (real OS table)
    $extConns = @()
    try {
        $extConns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-PrivateIP $_.RemoteAddress) } |
            Select-Object RemoteAddress, RemotePort, LocalPort, OwningProcess,
                @{N='ProcessName';E={ try { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName } catch { '?' } }})
    } catch {}

    Start-Sleep -Seconds $SampleSeconds

    $bytes2 = Get-InterfaceBytes
    $elapsed = [math]::Max(0.001, ((Get-Date) - $t1).TotalSeconds)
    $sentDelta = [math]::Max(0, $bytes2.Sent - $bytes1.Sent)
    $recvDelta = [math]::Max(0, $bytes2.Recv - $bytes1.Recv)
    $mbPerMin = [math]::Round(($sentDelta / 1MB) * (60.0 / $elapsed), 2)
    $mbInPerMin = [math]::Round(($recvDelta / 1MB) * (60.0 / $elapsed), 2)

    $uniqueIPs = @($extConns | Select-Object -ExpandProperty RemoteAddress -Unique)
    $topRemotes = $extConns | Group-Object RemoteAddress | Sort-Object Count -Descending |
        Select-Object -First 8 | ForEach-Object {
            $sample = $_.Group[0]
            [PSCustomObject]@{
                IP = $_.Name
                Conns = $_.Count
                Ports = (@($_.Group | Select-Object -ExpandProperty RemotePort -Unique) -join ',')
                Process = $sample.ProcessName
            }
        }

    $suspicious = $false
    $reasons = @()
    if ($mbPerMin -ge 300) { $suspicious = $true; $reasons += "High outbound volume ${mbPerMin} MB/min" }
    if ($uniqueIPs.Count -ge 25) { $suspicious = $true; $reasons += "Many unique external IPs ($($uniqueIPs.Count))" }
    if ($extConns.Count -ge 80) { $suspicious = $true; $reasons += "High external connection count ($($extConns.Count))" }

    return [PSCustomObject]@{
        Timestamp       = (Get-Date).ToString("o")
        SampleSec       = $SampleSeconds
        NetMBPerMin     = $mbPerMin
        NetMBInPerMin   = $mbInPerMin
        NetExternalConns= $extConns.Count
        NetUniqueIPs    = $uniqueIPs.Count
        NetRemotes      = @($uniqueIPs | Select-Object -First 15)
        NetTopRemotes   = @($topRemotes)
        NetSuspicious   = $suspicious
        NetReasons      = ($reasons -join " | ")
        BytesSentDelta  = $sentDelta
        BytesRecvDelta  = $recvDelta
        Connections     = $extConns
    }
}

function Start-NetworkCapture {
    param([int]$Seconds = 120, [int]$SampleSeconds = 5)

    Write-Host ""
    Write-Host "=== RansomKalki Real Network Capture ===" -ForegroundColor Cyan
    Write-Host "  Duration : ${Seconds}s  |  Sample window : ${SampleSeconds}s" -ForegroundColor White
    Write-Host "  Source   : OS connection table + adapter byte counters (no Npcap required)" -ForegroundColor Gray
    Write-Host "  Dashboard: .\RansomKalki.ps1 dashboard   (watch Net* metrics live)" -ForegroundColor Gray
    Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
    Write-Host ""

    $end = (Get-Date).AddSeconds($Seconds)
    $tick = 0
    while ((Get-Date) -lt $end) {
        $tick++
        $cap = Invoke-NetworkCapture -SampleSeconds $SampleSeconds

        $status = [ordered]@{
            Engine           = "Running"
            Pid              = $PID
            LastCycle        = $cap.Timestamp
            MemoryUsedPct    = try { $os = Get-CimInstance Win32_OperatingSystem; [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1) } catch { 0 }
            DiskTimePct      = 0
            FindingsCount    = if ($cap.NetSuspicious) { 1 } else { 0 }
            PendingAlerts    = @(Get-PendingApprovals).Count
            Mode             = if ($cap.NetSuspicious) { "Alert" } else { "Idle" }
            AutoApprove      = $true
            Version          = "1.3.0-capture"
            Platform         = "Windows"
            SimActive        = $false
            CaptureActive    = $true
            SimPattern       = if ($cap.NetSuspicious) { $cap.NetReasons } else { "Live capture – normal" }
            SimMode          = "live-capture"
            NetMBPerMin      = $cap.NetMBPerMin
            NetMBInPerMin    = $cap.NetMBInPerMin
            NetExternalConns = $cap.NetExternalConns
            NetUniqueIPs     = $cap.NetUniqueIPs
            NetRemotes       = $cap.NetRemotes
            NetSuspicious    = $cap.NetSuspicious
            SimTick          = $tick
            SimRemainingSec  = [math]::Max(0, [int]($end - (Get-Date)).TotalSeconds)
        }
        Save-Status $status

        if ($cap.NetSuspicious -and $cap.NetMBPerMin -ge 300) {
            $alertId = "cap" + [guid]::NewGuid().ToString("N").Substring(0, 8)
            $alertFile = Join-Path $AlertDir "$alertId.json"
            if (-not (Test-Path $alertFile)) {
                $finding = [PSCustomObject]@{
                    ID = 1; Type = "Network"; Name = "HighOutboundVolume"
                    Path = ""; PID = 0; MemoryMB = 0; Score = 80; Severity = "High"
                    Reasons = $cap.NetReasons
                    Timestamp = $cap.Timestamp
                }
                @{
                    AlertId = $alertId; Finding = $finding
                    SubmittedAt = $cap.Timestamp; TimeoutSec = 600; Status = "Pending"
                    ExpiresAt = (Get-Date).AddMinutes(10).ToString("o")
                    Capture = $true
                } | ConvertTo-Json -Depth 6 | Set-Content $alertFile -Encoding UTF8
                Write-Log "CAPTURE ALERT $alertId : $($cap.NetReasons)" "HIGH"
            }
        }

        $color = if ($cap.NetSuspicious) { "Magenta" } else { "Green" }
        Write-Host ("  [{0}] out={1,8} MB/min  in={2,7} MB/min  ext_conns={3,4}  unique_ips={4,3}  {5}" -f `
            (Get-Date).ToString("HH:mm:ss"), $cap.NetMBPerMin, $cap.NetMBInPerMin, `
            $cap.NetExternalConns, $cap.NetUniqueIPs, $(if ($cap.NetReasons) { $cap.NetReasons } else { "ok" })) -ForegroundColor $color

        if ($cap.NetTopRemotes -and $cap.NetTopRemotes.Count -gt 0) {
            foreach ($r in ($cap.NetTopRemotes | Select-Object -First 3)) {
                Write-Host ("           → {0,-18} conns={1} ports={2} proc={3}" -f $r.IP, $r.Conns, $r.Ports, $r.Process) -ForegroundColor DarkGray
            }
        }
    }

    $st = Get-Status
    if ($st) { $st.CaptureActive = $false; $st.Mode = "Idle"; $st.SimPattern = "Capture ended"; Save-Status $st }
    Write-Host "`nCapture complete." -ForegroundColor Cyan
}

# -------------------- Full Packet Capture (Windows – pktmon built-in) --------------------
function Start-FullPacketCapture {
    param(
        [int]$Seconds = 60,
        [string]$PacketFilter = ""
    )

    $captureDir = Join-Path $DataDir "captures"
    if (-not (Test-Path $captureDir)) { New-Item -ItemType Directory -Path $captureDir -Force | Out-Null }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $etlPath = Join-Path $captureDir "ransomkalki_$stamp.etl"
    $pcapPath = Join-Path $captureDir "ransomkalki_$stamp.pcap"
    $summaryPath = Join-Path $captureDir "ransomkalki_$stamp.summary.txt"

    Write-Host ""
    Write-Host "=== RansomKalki FULL Packet Capture (Windows) ===" -ForegroundColor Cyan
    Write-Host "  Duration : ${Seconds}s" -ForegroundColor White
    Write-Host "  Engine   : pktmon (built into Windows 10 1809+ / Server 2019+)" -ForegroundColor Gray
    Write-Host "  Output   : $captureDir" -ForegroundColor Gray
    Write-Host ""

    $pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    if (-not $pktmon) {
        Write-Host "pktmon.exe not found on this system." -ForegroundColor Red
        Write-Host "Full packet capture requires Windows 10 version 1809+ or Windows Server 2019+." -ForegroundColor Yellow
        Write-Host "Falling back to flow-level capture..." -ForegroundColor Yellow
        Start-NetworkCapture -Seconds $Seconds -SampleSeconds 5
        return
    }

    # Reset and start pktmon
    try {
        & pktmon stop 2>$null | Out-Null
        & pktmon filter remove 2>$null | Out-Null

        if ($PacketFilter) {
            # Example filters: "TCP Port 443", "IPv4.Address 8.8.8.8"
            & pktmon filter add -d $PacketFilter 2>$null
            Write-Host "  Filter   : $PacketFilter" -ForegroundColor White
        }

        Write-Host "  [1/4] Starting pktmon capture..." -ForegroundColor Cyan
        & pktmon start -c --pkt-size 0 -f $etlPath 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            # Try simpler syntax for older pktmon
            & pktmon start --capture --pkt-size 0 -f $etlPath 2>&1 | Out-Null
        }

        Write-Host "  [2/4] Capturing for ${Seconds}s (Ctrl+C will stop early)..." -ForegroundColor Cyan

        $end = (Get-Date).AddSeconds($Seconds)
        $tick = 0
        try {
            while ((Get-Date) -lt $end) {
                $tick++
                $remaining = [math]::Max(0, [int]($end - (Get-Date)).TotalSeconds)
                # Light status update for dashboard while capturing
                $flow = $null
                try {
                    $ext = @(Get-NetTCPConnection -State Established -EA SilentlyContinue |
                        Where-Object { -not (Test-PrivateIP $_.RemoteAddress) })
                    $status = [ordered]@{
                        Engine = "Running"; Pid = $PID
                        LastCycle = (Get-Date).ToString("o")
                        Mode = "Alert"; Version = "1.4.0-pcap"; Platform = "Windows"
                        CaptureActive = $true; PcapActive = $true
                        SimPattern = "FULL packet capture in progress"
                        SimMode = "pcap"; SimRemainingSec = $remaining
                        NetExternalConns = $ext.Count
                        NetUniqueIPs = @($ext | Select-Object -ExpandProperty RemoteAddress -Unique).Count
                        NetRemotes = @($ext | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 10)
                        PcapFile = $etlPath
                    }
                    Save-Status $status
                } catch {}
                Write-Host ("  [{0}] full pcap active  remaining={1}s  file={2}" -f (Get-Date).ToString("HH:mm:ss"), $remaining, (Split-Path $etlPath -Leaf)) -ForegroundColor Magenta
                Start-Sleep -Seconds 5
            }
        } catch {
            Write-Host "  Capture interrupted." -ForegroundColor Yellow
        }

        Write-Host "  [3/4] Stopping pktmon..." -ForegroundColor Cyan
        & pktmon stop 2>&1 | Out-Null

        Write-Host "  [4/4] Converting ETL → PCAP (if supported)..." -ForegroundColor Cyan
        $converted = $false
        try {
            & pktmon etl2pcap $etlPath $pcapPath 2>&1 | Out-Null
            if (Test-Path $pcapPath) { $converted = $true }
        } catch {}
        if (-not $converted) {
            try {
                & pktmon format $etlPath -o $summaryPath -f text 2>&1 | Out-Null
            } catch {}
        }

        # Write summary
        $etlSize = if (Test-Path $etlPath) { [math]::Round((Get-Item $etlPath).Length / 1MB, 2) } else { 0 }
        $pcapSize = if (Test-Path $pcapPath) { [math]::Round((Get-Item $pcapPath).Length / 1MB, 2) } else { 0 }
        $summary = @"
RansomKalki Full Packet Capture Summary
=====================================
Started   : $stamp
Duration  : ${Seconds}s
ETL file  : $etlPath ($etlSize MB)
PCAP file : $(if ($converted) { "$pcapPath ($pcapSize MB)" } else { "(conversion not available – use ETL with Microsoft Message Analyzer / Network Monitor / pktmon format)" })
Filter    : $(if ($PacketFilter) { $PacketFilter } else { "(none – all traffic)" })
Host      : $env:COMPUTERNAME
"@
        $summary | Set-Content $summaryPath -Encoding UTF8

        Write-Host ""
        Write-Host "  Capture complete." -ForegroundColor Green
        Write-Host "  ETL  : $etlPath ($etlSize MB)" -ForegroundColor White
        if ($converted) {
            Write-Host "  PCAP : $pcapPath ($pcapSize MB)" -ForegroundColor Green
        } else {
            Write-Host "  PCAP : not converted (open ETL with pktmon format or Message Analyzer)" -ForegroundColor Yellow
        }
        Write-Host "  Log  : $summaryPath" -ForegroundColor Gray
        Write-Host ""
        Write-Log "Full packet capture saved: $etlPath" "INFO"

        $st = Get-Status
        if ($st) {
            $st.PcapActive = $false
            $st.CaptureActive = $false
            $st.Mode = "Idle"
            $st.SimPattern = "PCAP complete: $(Split-Path $etlPath -Leaf)"
            $st.PcapFile = $etlPath
            Save-Status $st
        }
    }
    catch {
        Write-Host "Full packet capture failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempting cleanup..." -ForegroundColor Yellow
        & pktmon stop 2>$null | Out-Null
    }
}

# -------------------- Collector --------------------
function Invoke-Collect {
    $mem = Get-CimInstance Win32_OperatingSystem
    $totalGB = [math]::Round($mem.TotalVisibleMemorySize/1MB, 2)
    $freeGB  = [math]::Round($mem.FreePhysicalMemory/1MB, 2)
    $usedPct = [math]::Round((($totalGB-$freeGB)/$totalGB)*100, 1)

    $diskQueue = 0; $diskTime = 0
    try {
        $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
        if ($d) { $diskQueue = $d.CurrentDiskQueueLength; $diskTime = $d.PercentDiskTime }
    } catch {}

    $procs = Get-Process | Where-Object { $_.WorkingSet64 -gt 0 } | 
             Select-Object Id, ProcessName, Path, 
                 @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,1)}},
                 @{N='Threads';E={$_.Threads.Count}}

    # Lightweight real network snapshot (no sleep – point-in-time connections only)
    $extCount = 0; $uniqueExt = 0; $remoteSample = @()
    try {
        $ext = @(Get-NetTCPConnection -State Established -EA SilentlyContinue |
            Where-Object { -not (Test-PrivateIP $_.RemoteAddress) })
        $extCount = $ext.Count
        $remoteSample = @($ext | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 10)
        $uniqueExt = $remoteSample.Count
    } catch {}

    return [PSCustomObject]@{
        Timestamp    = (Get-Date).ToString("o")
        MemoryUsedPct= $usedPct
        MemoryTotalGB= $totalGB
        DiskQueue    = $diskQueue
        DiskTimePct  = $diskTime
        Processes    = $procs
        NetExternalConns = $extCount
        NetUniqueIPs     = $uniqueExt
        NetRemotes       = $remoteSample
    }
}

# -------------------- Detector --------------------
function Invoke-Detect {
    param($Snapshot, $Intel, $Config)

    $findings = [System.Collections.Generic.List[object]]::new()
    $id = 0

    foreach ($p in $Snapshot.Processes) {
        if ($CriticalProcesses -contains $p.ProcessName) { continue }

        $score = 0
        $reasons = @()

        foreach ($bad in $Intel.ProcessNames) {
            if ($p.ProcessName -like "*$bad*") {
                $score += 40
                $reasons += "Name matches threat intel: $bad"
                break
            }
        }

        if ($p.Path) {
            foreach ($pat in $Intel.PathPatterns) {
                if ($p.Path -like "*$pat*") {
                    $score += 25
                    $reasons += "Running from suspicious path"
                    break
                }
            }
            if ($p.Path -notmatch "System32|SysWOW64|Program Files") {
                $score += 10
                $reasons += "Unusual location"
            }
        }

        if ($p.MemoryMB -gt $Config.HighMemoryMB) {
            $score += 15
            $reasons += "High memory ($($p.MemoryMB) MB)"
        }
        if ($p.Threads -gt $Config.HighThreadCount) {
            $score += 15
            $reasons += "High thread count ($($p.Threads))"
        }

        if ($score -ge 40) {
            $id++
            $findings.Add([PSCustomObject]@{
                ID        = $id
                Type      = "Process"
                Name      = $p.ProcessName
                Path      = $p.Path
                PID       = $p.Id
                MemoryMB  = $p.MemoryMB
                Score     = $score
                Reasons   = ($reasons -join " | ")
                Severity  = if ($score -ge 70) { "High" } else { "Medium" }
                Timestamp = (Get-Date).ToString("o")
            })
        }
    }

    # High system pressure
    if ($Snapshot.MemoryUsedPct -ge 90) {
        $id++
        $findings.Add([PSCustomObject]@{
            ID = $id; Type = "System"; Name = "HighMemoryPressure"
            Path = ""; PID = 0; MemoryMB = 0; Score = 50
            Reasons = "System memory usage $($Snapshot.MemoryUsedPct)%"; Severity = "High"
            Timestamp = (Get-Date).ToString("o")
        })
    }
    if ($Snapshot.DiskTimePct -gt 90 -or $Snapshot.DiskQueue -gt 8) {
        $id++
        $findings.Add([PSCustomObject]@{
            ID = $id; Type = "System"; Name = "HighDiskActivity"
            Path = ""; PID = 0; MemoryMB = 0; Score = 45
            Reasons = "Disk time $($Snapshot.DiskTimePct)% / queue $($Snapshot.DiskQueue)"
            Severity = "Medium"; Timestamp = (Get-Date).ToString("o")
        })
    }

    return $findings
}

# -------------------- Actions --------------------
function Invoke-Action {
    param($Finding, $Config)

    $quarantineDir = $Config.QuarantineDir
    if (-not (Test-Path $quarantineDir)) { New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null }

    try {
        if ($Finding.Type -eq "Process" -and $Finding.PID -gt 0) {
            if ($CriticalProcesses -contains $Finding.Name) {
                Write-Log "Refused to act on critical process $($Finding.Name)" "WARN"
                return $false
            }
            Stop-Process -Id $Finding.PID -Force -ErrorAction Stop
            Write-Log "Killed process $($Finding.Name) (PID $($Finding.PID))" "HIGH"
            Start-Sleep -Milliseconds 500
            if ($Finding.Path -and (Test-Path $Finding.Path) -and $Finding.Path -notmatch "System32|SysWOW64") {
                $dest = Join-Path $quarantineDir ("{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), [IO.Path]::GetFileName($Finding.Path))
                Move-Item -Path $Finding.Path -Destination $dest -Force -ErrorAction SilentlyContinue
                Write-Log "Quarantined file → $dest" "HIGH"
            }
            return $true
        }
    } catch {
        Write-Log "Action failed on $($Finding.Name): $($_.Exception.Message)" "ERROR"
    }
    return $false
}

# -------------------- Approval Gateway --------------------
function Submit-ForApproval {
    param($Finding, $TimeoutSec)

    $alertId = [guid]::NewGuid().ToString("N").Substring(0,12)
    $alertFile = Join-Path $AlertDir "$alertId.json"
    $package = @{
        AlertId     = $alertId
        Finding     = $Finding
        SubmittedAt = (Get-Date).ToString("o")
        TimeoutSec  = $TimeoutSec
        Status      = "Pending"
        ExpiresAt   = (Get-Date).AddSeconds($TimeoutSec).ToString("o")
    }
    $package | ConvertTo-Json -Depth 6 | Set-Content $alertFile -Encoding UTF8
    Write-Log "Alert $alertId submitted for approval (timeout ${TimeoutSec}s) - $($Finding.Name)" "HIGH"
    return $alertId
}

function Get-PendingApprovals {
    Get-ChildItem $AlertDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $a = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if ($a.Status -eq "Pending") { $a }
        } catch {}
    }
}

function Resolve-Approval {
    param([string]$AlertId, [string]$Decision)  # Decision = Approve | Deny
    $file = Join-Path $AlertDir "$AlertId.json"
    if (-not (Test-Path $file)) { return $false }
    $a = Get-Content $file -Raw | ConvertFrom-Json
    $a.Status = $Decision
    $a.ResolvedAt = (Get-Date).ToString("o")
    $a | ConvertTo-Json -Depth 6 | Set-Content $file -Encoding UTF8
    Write-Log "Alert $AlertId resolved as $Decision" "INFO"
    return $true
}

# -------------------- Main Engine Loop --------------------
function Start-Engine {
    param($Config)

    if (Test-EngineRunning) {
        Write-Host "RansomKalki is already running (PID $(Get-Content $PidFile))" -ForegroundColor Yellow
        return
    }

    $pid | Set-Content $PidFile
    Write-Log "RansomKalki engine started (PID $pid)" "INFO"

    $intel = Load-ThreatIntel
    $alertMode = $false
    $lastFindings = @()

    while ($true) {
        try {
            # Check for expired approvals → auto-action (if enabled)
            foreach ($pending in (Get-PendingApprovals)) {
                $expires = [datetime]$pending.ExpiresAt
                if ((Get-Date) -gt $expires) {
                    if ($Config.AutoApproveOnTimeout) {
                        Write-Log "Approval timeout for $($pending.AlertId) - AUTO-EXECUTING action" "HIGH"
                        Invoke-Action -Finding $pending.Finding -Config $Config | Out-Null
                        Resolve-Approval -AlertId $pending.AlertId -Decision "Timeout-Auto"
                    } else {
                        Write-Log "Approval timeout for $($pending.AlertId) - auto-action disabled, marking expired" "WARN"
                        Resolve-Approval -AlertId $pending.AlertId -Decision "Timeout-Expired"
                    }
                }
            }

            $snap = Invoke-Collect
            $findings = Invoke-Detect -Snapshot $snap -Intel $intel -Config $Config
            $lastFindings = $findings

            $status = [ordered]@{
                Engine           = "Running"
                Pid              = $pid
                LastCycle        = (Get-Date).ToString("o")
                MemoryUsedPct    = $snap.MemoryUsedPct
                DiskTimePct      = $snap.DiskTimePct
                FindingsCount    = $findings.Count
                PendingAlerts    = @(Get-PendingApprovals).Count
                Mode             = if ($alertMode) { "Alert" } else { "Idle" }
                AutoApprove      = $Config.AutoApproveEnabled
                Version          = "1.3.0"
                Platform         = "Windows"
                CaptureActive    = $true
                NetExternalConns = $snap.NetExternalConns
                NetUniqueIPs     = $snap.NetUniqueIPs
                NetRemotes       = $snap.NetRemotes
                SimPattern       = "Live capture (connection table)"
            }
            Save-Status $status

            if ($findings.Count -gt 0) {
                $alertMode = $true
                foreach ($f in $findings) {
                    if ($f.Score -lt 60) { continue }

                    # --- AUTO-APPROVAL LOGIC ---
                    $isImpact = ($f.Type -match "Encrypt|Impact|Corruption|Shadow|Backup" -or $f.Reasons -match "encrypt|shadow|vssadmin|wbadmin")
                    $shouldAuto = $false

                    if ($Config.AutoApproveEnabled -and $f.Score -ge $Config.AutoApproveScoreThreshold) {
                        if ($isImpact -and $Config.RequireApprovalForImpact) {
                            $shouldAuto = $false   # Force human approval for impact-class even if score high
                        } else {
                            $shouldAuto = $true
                        }
                    }

                    if ($shouldAuto) {
                        Write-Log "AUTO-APPROVED (score $($f.Score) >= $($Config.AutoApproveScoreThreshold)): $($f.Name)" "HIGH"
                        Invoke-Action -Finding $f -Config $Config | Out-Null
                        # Still record an alert for audit trail
                        $aid = Submit-ForApproval -Finding $f -TimeoutSec 1
                        Resolve-Approval -AlertId $aid -Decision "Auto-Approved"
                    } else {
                        # Submit for human approval / timeout path
                        $timeout = if ($f.Severity -eq "High" -or $isImpact) { $Config.ApprovalTimeoutImpact } else { $Config.ApprovalTimeoutNormal }
                        Submit-ForApproval -Finding $f -TimeoutSec $timeout | Out-Null
                    }
                }
            } else {
                $alertMode = $false
            }

            $sleep = if ($alertMode) { $Config.PollIntervalAlertSec } else { $Config.PollIntervalIdleSec }
            Start-Sleep -Seconds $sleep
        }
        catch {
            Write-Log "Engine cycle error: $($_.Exception.Message)" "ERROR"
            Start-Sleep -Seconds 30
        }
    }
}

# -------------------- Status Console (pm2-style) --------------------
function Show-Status {
    $running = Test-EngineRunning
    $status  = Get-Status
    $pending = @(Get-PendingApprovals)

    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│                     RANSOMKALKI SECURITY ENGINE STATUS                          │" -ForegroundColor Cyan
    Write-Host "└──────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""

    if (-not $running) {
        Write-Host "  Status    : " -NoNewline; Write-Host "STOPPED" -ForegroundColor Red
        Write-Host "  Use:  .\RansomKalki.ps1 start" -ForegroundColor Yellow
        Write-Host ""
        return
    }

    $pid = Get-Content $PidFile
    Write-Host "  Status    : " -NoNewline; Write-Host "ONLINE" -ForegroundColor Green
    Write-Host "  PID       : $pid"
    Write-Host "  Mode      : $($status.Mode)"
    Write-Host "  Last Cycle: $($status.LastCycle)"
    Write-Host "  Memory    : $($status.MemoryUsedPct)% used"
    Write-Host "  Disk Time : $($status.DiskTimePct)%"
    Write-Host "  Findings  : $($status.FindingsCount)"
    Write-Host "  Pending   : $($pending.Count) approval(s)"
    Write-Host "  AutoApprove: $($status.AutoApprove)  (threshold from config)"
    Write-Host "  Platform  : Windows | Version $($status.Version)"
    Write-Host ""

    if ($pending.Count -gt 0) {
        Write-Host "  ┌─ PENDING APPROVALS ─────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        foreach ($p in $pending) {
            Write-Host "  │ ID: $($p.AlertId)  |  $($p.Finding.Name)  |  Score: $($p.Finding.Score)  |  Exp: $($p.ExpiresAt)" -ForegroundColor Yellow
        }
        Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host "  Approve : .\RansomKalki.ps1 approve -Id <AlertId>" -ForegroundColor Gray
        Write-Host "  Deny    : .\RansomKalki.ps1 deny    -Id <AlertId>" -ForegroundColor Gray
    }
    Write-Host ""
}

function Show-Monit {
    Write-Host "RansomKalki Live Monitor - Press Ctrl+C to exit" -ForegroundColor Cyan
    Write-Host ""
    while ($true) {
        Clear-Host
        Show-Status
        Write-Host "Updated: $(Get-Date -Format 'HH:mm:ss')  |  Refreshing every 5s" -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
    }
}

function Show-Logs {
    param([int]$Lines = 40)
    if (Test-Path $LogFile) {
        Get-Content $LogFile -Tail $Lines -ErrorAction SilentlyContinue
    } else {
        Write-Host "No log file yet." -ForegroundColor Yellow
    }
}

function Install-Service {
    Write-Host "=== RansomKalki Auto-Installation ===" -ForegroundColor Cyan
    Write-Host ""

    # 1. Ensure folder structure + default config
    @($DataDir, $LogDir, $AlertDir, (Join-Path $ScriptRoot "Config"), (Join-Path $DataDir "Quarantine")) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "  [+] Created $_" -ForegroundColor Green
        }
    }
    $null = Get-Config   # writes default engine.json if missing
    Write-Host "  [+] Config ready: $ConfigFile" -ForegroundColor Green

    # 2. Create / update Scheduled Task
    $taskName = "RansomKalkiEngine"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" start -Daemon"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 365)

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description "RansomKalki Anti-Ransomware + System Cleaner Engine (auto-start at boot)" | Out-Null
    Write-Host "  [+] Scheduled Task '$taskName' registered (runs as SYSTEM at startup)" -ForegroundColor Green

    # 3. Start it now
    try {
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds 2
        Write-Host "  [+] Engine started via Scheduled Task" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Could not auto-start task (will run at next boot): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Installation complete." -ForegroundColor Green
    Write-Host "  Status :  .\RansomKalki.ps1 status" -ForegroundColor Gray
    Write-Host "  Logs   :  .\RansomKalki.ps1 logs" -ForegroundColor Gray
    Write-Host "  Config :  $ConfigFile  (edit AutoApprove* settings here)" -ForegroundColor Gray
    Write-Host ""
}

# -------------------- Real-time GUI Dashboard (HttpListener) --------------------
function Start-Dashboard {
    param([int]$ListenPort = 8787)

    $htmlPath = Join-Path $ScriptRoot "..\dashboard.html"
    if (-not (Test-Path $htmlPath)) {
        $htmlPath = Join-Path $ScriptRoot "dashboard.html"
    }
    if (-not (Test-Path $htmlPath)) {
        # Fallback: look one level up (RansomKalki/dashboard.html)
        $htmlPath = Join-Path (Split-Path $ScriptRoot -Parent) "dashboard.html"
    }
    if (-not (Test-Path $htmlPath)) {
        Write-Host "dashboard.html not found. Place it next to RansomKalki.ps1 or in the RansomKalki root." -ForegroundColor Red
        return
    }
    $htmlContent = Get-Content $htmlPath -Raw -Encoding UTF8

    $prefix = "http://localhost:$ListenPort/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix)
    try {
        $listener.Start()
    } catch {
        Write-Host "Cannot bind to $prefix - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Try a different port: .\RansomKalki.ps1 dashboard -Port 8790" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  RansomKalki Dashboard running at  $prefix" -ForegroundColor Green
    Write-Host "  Press Ctrl+C to stop the dashboard." -ForegroundColor Gray
    Write-Host ""
    Start-Process $prefix

    try {
        while ($listener.IsListening) {
            $ctx = $listener.GetContext()
            $req = $ctx.Request
            $res = $ctx.Response
            $path = $req.Url.AbsolutePath.ToLower()

            try {
                if ($path -eq "/" -or $path -eq "/index.html") {
                    $buf = [Text.Encoding]::UTF8.GetBytes($htmlContent)
                    $res.ContentType = "text/html; charset=utf-8"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                elseif ($path -eq "/api/status") {
                    $st = Get-Status
                    if (-not $st) { $st = @{ Engine = "Stopped"; Platform = "Windows" } }
                    $json = $st | ConvertTo-Json -Depth 6 -Compress
                    $buf = [Text.Encoding]::UTF8.GetBytes($json)
                    $res.ContentType = "application/json"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                elseif ($path -eq "/api/alerts") {
                    $pending = @(Get-PendingApprovals)
                    $json = ($pending | ConvertTo-Json -Depth 8 -Compress)
                    if (-not $json) { $json = "[]" }
                    if ($json[0] -ne '[') { $json = "[$json]" }
                    $buf = [Text.Encoding]::UTF8.GetBytes($json)
                    $res.ContentType = "application/json"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                elseif ($path -eq "/api/logs") {
                    $lines = @()
                    if (Test-Path $LogFile) {
                        $lines = Get-Content $LogFile -Tail 50 -ErrorAction SilentlyContinue
                    }
                    $obj = @{ lines = @($lines) }
                    $json = $obj | ConvertTo-Json -Compress
                    $buf = [Text.Encoding]::UTF8.GetBytes($json)
                    $res.ContentType = "application/json"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                elseif ($path -eq "/api/approve" -and $req.HttpMethod -eq "POST") {
                    $aid = $req.QueryString["id"]
                    if ($aid) {
                        $file = Join-Path $AlertDir "$aid.json"
                        if (Test-Path $file) {
                            $a = Get-Content $file -Raw | ConvertFrom-Json
                            Resolve-Approval -AlertId $aid -Decision "Approved" | Out-Null
                            Invoke-Action -Finding $a.Finding -Config (Get-Config) | Out-Null
                        }
                    }
                    $buf = [Text.Encoding]::UTF8.GetBytes('{"ok":true}')
                    $res.ContentType = "application/json"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                elseif ($path -eq "/api/deny" -and $req.HttpMethod -eq "POST") {
                    $aid = $req.QueryString["id"]
                    if ($aid) { Resolve-Approval -AlertId $aid -Decision "Denied" | Out-Null }
                    $buf = [Text.Encoding]::UTF8.GetBytes('{"ok":true}')
                    $res.ContentType = "application/json"
                    $res.ContentLength64 = $buf.Length
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
                else {
                    $res.StatusCode = 404
                    $buf = [Text.Encoding]::UTF8.GetBytes("Not found")
                    $res.OutputStream.Write($buf, 0, $buf.Length)
                }
            } catch {
                $res.StatusCode = 500
            } finally {
                $res.Close()
            }
        }
    } finally {
        $listener.Stop()
        $listener.Close()
    }
}

# -------------------- Real-time Network Traffic Simulation --------------------
function Start-NetworkSimulation {
    param(
        [string]$Mode = "mixed",
        [int]$Seconds = 120
    )

    Write-Host ""
    Write-Host "=== RansomKalki Real-Time Network Traffic Simulation ===" -ForegroundColor Cyan
    Write-Host "  Mode     : $Mode" -ForegroundColor White
    Write-Host "  Duration : ${Seconds}s" -ForegroundColor White
    Write-Host "  Dashboard: run '.\RansomKalki.ps1 dashboard' in another window to watch live" -ForegroundColor Gray
    Write-Host "  Press Ctrl+C to stop early." -ForegroundColor Gray
    Write-Host ""

    $end = (Get-Date).AddSeconds($Seconds)
    $tick = 0
    $rng = [System.Random]::new()

    # Simulated remote endpoints
    $c2Hosts = @("185.234.72.11","91.219.237.44","45.142.120.88","103.27.202.15")
    $cloudHosts = @("s3.amazonaws.com","storage.googleapis.com","blob.core.windows.net","transfer.sh","mega.nz")
    $legitHosts = @("192.168.1.10","10.0.0.5","172.16.0.20","8.8.8.8","1.1.1.1")

    while ((Get-Date) -lt $end) {
        $tick++
        $now = Get-Date

        # Generate traffic profile based on mode
        switch ($Mode) {
            "baseline" {
                $mbPerMin = [math]::Round(5 + $rng.NextDouble() * 25, 2)
                $extConns = $rng.Next(2, 12)
                $uniqueIPs = $rng.Next(2, 8)
                $suspicious = $false
                $pattern = "Normal office traffic"
                $remotes = $legitHosts | Get-Random -Count ([Math]::Min(3, $legitHosts.Count))
            }
            "exfil" {
                # Burst exfiltration pattern
                $mbPerMin = [math]::Round(400 + $rng.NextDouble() * 900, 2)
                $extConns = $rng.Next(15, 60)
                $uniqueIPs = $rng.Next(3, 10)
                $suspicious = $true
                $pattern = "High-volume outbound (possible exfil)"
                $remotes = $cloudHosts | Get-Random -Count ([Math]::Min(3, $cloudHosts.Count))
            }
            "c2" {
                $mbPerMin = [math]::Round(0.5 + $rng.NextDouble() * 8, 2)
                $extConns = $rng.Next(1, 6)
                $uniqueIPs = 1
                $suspicious = $true
                $pattern = "Periodic low-volume beaconing (possible C2)"
                $remotes = @($c2Hosts | Get-Random)
            }
            "ransomware" {
                $mbPerMin = [math]::Round(50 + $rng.NextDouble() * 200, 2)
                $extConns = $rng.Next(8, 30)
                $uniqueIPs = $rng.Next(4, 12)
                $suspicious = $true
                $pattern = "Ransomware prep: staging + C2 + backup probe"
                $remotes = ($c2Hosts + $cloudHosts) | Get-Random -Count 4
            }
            default { # mixed
                $roll = $rng.Next(100)
                if ($roll -lt 50) {
                    $mbPerMin = [math]::Round(8 + $rng.NextDouble() * 40, 2)
                    $extConns = $rng.Next(3, 15)
                    $uniqueIPs = $rng.Next(3, 10)
                    $suspicious = $false
                    $pattern = "Mixed: baseline"
                    $remotes = $legitHosts | Get-Random -Count 3
                } elseif ($roll -lt 75) {
                    $mbPerMin = [math]::Round(350 + $rng.NextDouble() * 600, 2)
                    $extConns = $rng.Next(20, 50)
                    $uniqueIPs = $rng.Next(4, 9)
                    $suspicious = $true
                    $pattern = "Mixed: exfil burst"
                    $remotes = $cloudHosts | Get-Random -Count 2
                } else {
                    $mbPerMin = [math]::Round(1 + $rng.NextDouble() * 5, 2)
                    $extConns = $rng.Next(1, 4)
                    $uniqueIPs = 1
                    $suspicious = $true
                    $pattern = "Mixed: C2 beacon"
                    $remotes = @($c2Hosts | Get-Random)
                }
            }
        }

        # Build status for dashboard
        $netStatus = [ordered]@{
            Engine            = "Running"
            Pid               = $PID
            LastCycle         = $now.ToString("o")
            MemoryUsedPct     = [math]::Round(35 + $rng.NextDouble() * 25, 1)
            DiskTimePct       = [math]::Round($rng.NextDouble() * 40, 1)
            FindingsCount     = if ($suspicious) { $rng.Next(1, 5) } else { 0 }
            PendingAlerts     = if ($suspicious) { $rng.Next(0, 3) } else { 0 }
            Mode              = if ($suspicious) { "Alert" } else { "Idle" }
            AutoApprove       = $true
            Version           = "1.2.0-sim"
            Platform          = "Windows"
            # Network simulation fields
            SimActive         = $true
            SimMode           = $Mode
            SimPattern        = $pattern
            NetMBPerMin       = $mbPerMin
            NetExternalConns  = $extConns
            NetUniqueIPs      = $uniqueIPs
            NetRemotes        = @($remotes)
            NetSuspicious     = $suspicious
            SimTick           = $tick
            SimRemainingSec   = [math]::Max(0, [int]($end - $now).TotalSeconds)
        }
        Save-Status $netStatus

        # Optionally create a synthetic finding/alert for high-suspicion ticks
        if ($suspicious -and $mbPerMin -ge 300) {
            $fid = [guid]::NewGuid().ToString("N").Substring(0, 8)
            $finding = [PSCustomObject]@{
                ID = 1; Type = "Network"; Name = "SimulatedExfil"
                Path = ""; PID = 0; MemoryMB = 0
                Score = 85; Severity = "High"
                Reasons = "Simulated high outbound volume $mbPerMin MB/min to $($remotes -join ', ')"
                Timestamp = $now.ToString("o")
            }
            $alertId = "sim$fid"
            $alertFile = Join-Path $AlertDir "$alertId.json"
            if (-not (Test-Path $alertFile)) {
                @{
                    AlertId = $alertId
                    Finding = $finding
                    SubmittedAt = $now.ToString("o")
                    TimeoutSec = 600
                    Status = "Pending"
                    ExpiresAt = $now.AddMinutes(10).ToString("o")
                    Simulated = $true
                } | ConvertTo-Json -Depth 6 | Set-Content $alertFile -Encoding UTF8
                Write-Log "SIM ALERT $alertId : $pattern ($mbPerMin MB/min)" "HIGH"
            }
        }

        $color = if ($suspicious) { "Magenta" } else { "Green" }
        Write-Host ("  [{0}] {1,-35} {2,8} MB/min  conns={3}  ips={4}" -f $now.ToString("HH:mm:ss"), $pattern, $mbPerMin, $extConns, $uniqueIPs) -ForegroundColor $color

        Start-Sleep -Seconds 3
    }

    # Clear simulation flags
    $final = Get-Status
    if ($final) {
        $final.SimActive = $false
        $final.Mode = "Idle"
        $final.SimPattern = "Simulation ended"
        Save-Status $final
    }
    Write-Host ""
    Write-Host "Simulation complete." -ForegroundColor Cyan
}

# -------------------- Command Dispatcher --------------------
$Config = Get-Config

switch ($Command) {
    "start" {
        if ($Daemon) {
            # Background style - for scheduled task
            Start-Engine -Config $Config
        } else {
            Write-Host "Starting RansomKalki engine in foreground (Ctrl+C to stop)..." -ForegroundColor Cyan
            Write-Host "For background: install as Scheduled Task with  .\RansomKalki.ps1 install" -ForegroundColor Gray
            Start-Engine -Config $Config
        }
    }
    "stop" {
        if (Test-EngineRunning) {
            $p = Get-Content $PidFile
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
            Write-Host "RansomKalki stopped." -ForegroundColor Green
            Write-Log "Engine stopped by user" "INFO"
        } else {
            Write-Host "RansomKalki is not running." -ForegroundColor Yellow
        }
    }
    "status"  { Show-Status }
    "monit"   { Show-Monit }
    "logs"    { Show-Logs }
    "scan"    {
        Write-Host "Running one-shot scan..." -ForegroundColor Cyan
        $intel = Load-ThreatIntel
        $snap  = Invoke-Collect
        $findings = Invoke-Detect -Snapshot $snap -Intel $intel -Config $Config
        if ($findings.Count -eq 0) {
            Write-Host "No suspicious items found." -ForegroundColor Green
        } else {
            $findings | Format-Table ID, Severity, Type, Name, Score, Reasons -AutoSize
        }
    }
    "approve" {
        if (-not $Id) { Write-Host "Usage: .\RansomKalki.ps1 approve -Id <AlertId>" -ForegroundColor Yellow; break }
        if (Resolve-Approval -AlertId $Id -Decision "Approved") {
            $file = Join-Path $AlertDir "$Id.json"
            $a = Get-Content $file -Raw | ConvertFrom-Json
            Invoke-Action -Finding $a.Finding -Config $Config | Out-Null
            Write-Host "Approved and action executed for $Id" -ForegroundColor Green
        } else { Write-Host "Alert not found." -ForegroundColor Red }
    }
    "deny" {
        if (-not $Id) { Write-Host "Usage: .\RansomKalki.ps1 deny -Id <AlertId>" -ForegroundColor Yellow; break }
        if (Resolve-Approval -AlertId $Id -Decision "Denied") {
            Write-Host "Denied $Id" -ForegroundColor Green
        } else { Write-Host "Alert not found." -ForegroundColor Red }
    }
    "install"    { Install-Service }
    "dashboard"  { Start-Dashboard -ListenPort $Port }
    "simulate"   { Start-NetworkSimulation -Mode $SimMode -Seconds $DurationSec }
    "capture"    {
        if ($Full) { Start-FullPacketCapture -Seconds $DurationSec -PacketFilter $Filter }
        else { Start-NetworkCapture -Seconds $DurationSec -SampleSeconds $SampleSec }
    }
    "pcap"       { Start-FullPacketCapture -Seconds $DurationSec -PacketFilter $Filter }
    "uninstall"  {
        Unregister-ScheduledTask -TaskName "RansomKalkiEngine" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Scheduled Task removed." -ForegroundColor Green
    }
    default {
        Write-Host @"

RansomKalki - Anti-Ransomware + System Cleaner (Windows)
Copyright © RansomKalki

Usage:  .\RansomKalki.ps1 <command> [options]

Commands:
  start             Start the engine (foreground)
  stop              Stop the engine
  status            Show current status (pm2-style)
  monit             Live status monitor (refresh every 5s)
  logs              Show recent engine logs
  scan              Run one-shot scan and print findings
  approve -Id <id>  Approve a pending alert and execute action
  deny    -Id <id>  Deny a pending alert
  install           Auto-install: folders + config + Scheduled Task + start
  uninstall         Remove Scheduled Task
  dashboard [-Port N]  Open real-time GUI dashboard (default port 8787)
  simulate [-SimMode mode] [-DurationSec N]
                    Synthetic network traffic simulation for demo/testing
                    Modes: baseline | exfil | c2 | ransomware | mixed
  capture [-DurationSec N] [-SampleSec N]
                    REAL network flow capture (adapter counters + TCP table)
  capture -Full [-DurationSec N] [-Filter "TCP Port 443"]
                    FULL packet capture via built-in pktmon → ETL/PCAP
  pcap [-DurationSec N] [-Filter "..."]
                    Alias for capture -Full
  help              Show this help

Auto-Approval (edit Config\engine.json):
  AutoApproveEnabled         = true/false
  AutoApproveScoreThreshold  = 80    (score >= this → act immediately)
  AutoApproveOnTimeout       = true  (timeout → act)
  RequireApprovalForImpact   = true  (force human approval for encryption-class)

Examples:
  .\RansomKalki.ps1 install
  .\RansomKalki.ps1 dashboard
  .\RansomKalki.ps1 simulate -SimMode exfil -DurationSec 60
  .\RansomKalki.ps1 simulate -SimMode mixed
  .\RansomKalki.ps1 status
  .\RansomKalki.ps1 monit
  .\RansomKalki.ps1 approve -Id a1b2c3d4e5f6

"@ -ForegroundColor Cyan
    }
}
