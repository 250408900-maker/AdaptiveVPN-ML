
param(
    [ValidateSet(
        "NORMAL",
        "HIGH_LATENCY",
        "HIGH_JITTER",
        "PACKET_LOSS"
    )]
    [string]$Condition = "NORMAL",

    [string]$CaptureId = "normal_v3_001",

    [ValidateRange(10, 3600)]
    [int]$DurationSeconds = 60,

    [int]$Interface = 5,

    [switch]$RecoverExisting
)

$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent $PSScriptRoot
$TShark = "C:\Program Files\Wireshark\tshark.exe"
$Workload = Join-Path $PSScriptRoot "workload_v3.ps1"

$ConditionFolder = $Condition.ToLower()
$Folder = Join-Path $Repo "data\captures\v3\$ConditionFolder"
$ProbeFolder = Join-Path $Repo "data\processed\probes"

New-Item -ItemType Directory -Force $Folder | Out-Null
New-Item -ItemType Directory -Force $ProbeFolder | Out-Null

$Pcap = Join-Path $Folder "$CaptureId.pcapng"
$Manifest = Join-Path $Folder "${CaptureId}_manifest.json"
$Raw = Join-Path $ProbeFolder "${CaptureId}_raw.csv"
$Summary = Join-Path $ProbeFolder "${CaptureId}_summary.csv"

if (!(Test-Path $TShark)) {
    throw "TShark not found: $TShark"
}

$CaptureLaunchUtc = $null
$WorkloadStartUtc = $null
$WorkloadEndUtc = $null

Write-Host ""
Write-Host "========================================"
Write-Host " AdaptiveVPN-ML V3 Capture Runner"
Write-Host "========================================"
Write-Host "Condition: $Condition"
Write-Host "Capture ID: $CaptureId"
Write-Host "Recovery mode: $RecoverExisting"
Write-Host ""

if (!$RecoverExisting) {

    if (!(Test-Path $Workload)) {
        throw "V3 workload script not found."
    }

    foreach ($file in @($Pcap, $Manifest, $Raw, $Summary)) {
        if (Test-Path $file) {
            throw "File already exists: $file"
        }
    }

    # Extra time for startup, warm-up, and shutdown.
    $CaptureDuration = $DurationSeconds + 30

    $Arguments = @(
        "-i", "$Interface",
        "-a", "duration:$CaptureDuration",
        "-w", "`"$Pcap`"",
        "-q"
    )

    Write-Host "Starting TShark..."

    $CaptureLaunchUtc = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    $Process = Start-Process `
        -FilePath $TShark `
        -ArgumentList $Arguments `
        -PassThru `
        -NoNewWindow

    # Give the capture process time to initialize.
    Start-Sleep -Seconds 3

    $Process.Refresh()

    if ($Process.HasExited) {
        throw "TShark exited during startup."
    }

    # Generate traffic before starting timed probes.
    # This is a warm-up, not proof of capture readiness.
    Write-Host "Warming up network capture..."

    curl.exe -L --silent --max-time 5 `
        --output NUL "https://example.com"

    ping.exe -n 1 -w 1000 1.1.1.1 | Out-Null

    Start-Sleep -Seconds 3

    $Process.Refresh()

    if ($Process.HasExited) {
        throw "TShark exited during warm-up."
    }

    Write-Host "Warm-up complete."
    Write-Host "Starting V3 workload..."

    $WorkloadStartUtc = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    Push-Location $Repo

    try {
        & $Workload `
            -DurationSeconds $DurationSeconds `
            -Condition $Condition `
            -CaptureId $CaptureId
    }
    finally {
        Pop-Location
    }

    $WorkloadEndUtc = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    Write-Host "Waiting for TShark to finish..."

    $Process.WaitForExit()
    $Process.Refresh()

    if (
        $null -ne $Process.ExitCode -and
        $Process.ExitCode -ne 0
    ) {
        throw "TShark failed: $($Process.ExitCode)"
    }

}
else {
    Write-Host "Recovering existing capture..."

    if (Test-Path $Manifest) {
        throw "Manifest already exists: $Manifest"
    }
}

# ========================================
# VALIDATE FILES
# ========================================

foreach ($file in @($Pcap, $Raw, $Summary)) {
    if (!(Test-Path $file)) {
        throw "Required file missing: $file"
    }
}

$Probes = @(Import-Csv $Raw)
$Summaries = @(Import-Csv $Summary)

if ($Probes.Count -eq 0) {
    throw "Raw probe CSV is empty."
}

if ($Summaries.Count -eq 0) {
    throw "Probe summary CSV is empty."
}

$FirstProbe = $Probes[0]

$ProbeOriginDate = (
    [DateTimeOffset]::Parse(
        $FirstProbe.timestamp_utc
    )
).AddSeconds(
    -[double]$FirstProbe.elapsed_s
)

$ProbeOrigin = $ProbeOriginDate.ToString("o")

Write-Host "Checking PCAP timestamps..."

$FirstPacketEpoch = & $TShark `
    -r $Pcap -c 1 `
    -T fields -e frame.time_epoch

if ($LASTEXITCODE -ne 0 -or !$FirstPacketEpoch) {
    throw "Unable to read first PCAP packet."
}

$LastPacketEpoch = & $TShark `
    -r $Pcap `
    -T fields -e frame.time_epoch |
    Select-Object -Last 1

if ($LASTEXITCODE -ne 0 -or !$LastPacketEpoch) {
    throw "Unable to read last PCAP packet."
}

$PacketCount = (
    & $TShark -r $Pcap `
        -T fields -e frame.number |
    Measure-Object -Line
).Lines

if ($LASTEXITCODE -ne 0 -or $PacketCount -le 0) {
    throw "PCAP packet validation failed."
}

$FirstPacketDate = (
    [DateTimeOffset]::FromUnixTimeMilliseconds(
        [long]([double]::Parse(
            "$FirstPacketEpoch",
            [System.Globalization.CultureInfo]::InvariantCulture
        ) * 1000)
    )
)

$LastPacketDate = (
    [DateTimeOffset]::FromUnixTimeMilliseconds(
        [long]([double]::Parse(
            "$LastPacketEpoch",
            [System.Globalization.CultureInfo]::InvariantCulture
        ) * 1000)
    )
)

$FirstOffset = [math]::Round(
    ($FirstPacketDate - $ProbeOriginDate).TotalSeconds,
    2
)

$LastOffset = [math]::Round(
    ($LastPacketDate - $ProbeOriginDate).TotalSeconds,
    2
)

# Check whether recorded packets span the entire
# requested measurement interval.
$FullCoverage = (
    $FirstOffset -le 0 -and
    $LastOffset -ge $DurationSeconds
)

if ($FullCoverage) {
    $QualityStatus = "FULL_COVERAGE"
}
else {
    $QualityStatus = "PARTIAL_COVERAGE"
}

# ========================================
# SAVE MANIFEST
# ========================================

$Metadata = [ordered]@{
    capture_id = $CaptureId
    condition = $Condition
    interface = $Interface
    requested_duration_seconds = $DurationSeconds

    recovered = [bool]$RecoverExisting

    capture_launch_utc = $CaptureLaunchUtc
    capture_first_packet_epoch = "$FirstPacketEpoch"
    capture_last_packet_epoch = "$LastPacketEpoch"

    workload_start_utc = $WorkloadStartUtc
    workload_end_utc = $WorkloadEndUtc

    probe_window_origin_utc = $ProbeOrigin

    first_packet_offset_s = $FirstOffset
    last_packet_offset_s = $LastOffset
    capture_quality = $QualityStatus

    packet_count = $PacketCount
    probe_count = $Probes.Count
    probe_window_count = $Summaries.Count

    pcap_file = $Pcap
    probe_raw_file = $Raw
    probe_summary_file = $Summary
}

$Metadata |
    ConvertTo-Json -Depth 4 |
    Set-Content $Manifest

Write-Host ""
Write-Host "========================================"
Write-Host " V3 CAPTURE COMPLETE"
Write-Host "========================================"
Write-Host "Packets: $PacketCount"
Write-Host "Probes: $($Probes.Count)"
Write-Host "Windows: $($Summaries.Count)"
Write-Host "First packet offset: $FirstOffset s"
Write-Host "Last packet offset: $LastOffset s"
Write-Host "Capture quality: $QualityStatus"
Write-Host "Manifest: $Manifest"

if (!$FullCoverage) {
    Write-Warning (
        "Partial packet coverage detected. " +
        "The V3 extractor will exclude incomplete windows."
    )
}
