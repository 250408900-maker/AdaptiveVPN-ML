
param(
    [int]$DurationSeconds = 60,
    [string]$Condition = "NORMAL",
    [string]$CaptureId = "test_v3_001",
    [string]$ProbeTarget = "1.1.1.1",
    [int]$TcpPort = 443
)

$ErrorActionPreference = "Stop"

$WindowSeconds = 10
$OutputDir = ".\data\processed\probes"

New-Item -ItemType Directory -Force $OutputDir | Out-Null

$RawFile = Join-Path $OutputDir "${CaptureId}_raw.csv"
$SummaryFile = Join-Path $OutputDir "${CaptureId}_summary.csv"

$Condition = $Condition.ToUpper()

Write-Host ""
Write-Host "========================================"
Write-Host " AdaptiveVPN-ML Workload V3"
Write-Host " ICMP + TCP Measurements"
Write-Host "========================================"
Write-Host "Condition: $Condition"
Write-Host "Capture: $CaptureId"
Write-Host "Duration: $DurationSeconds seconds"
Write-Host "Target: ${ProbeTarget}:${TcpPort}"
Write-Host ""

$records = New-Object System.Collections.Generic.List[object]
$clock = [System.Diagnostics.Stopwatch]::StartNew()

$iteration = 1

while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {

    $iterationStart = $clock.Elapsed.TotalSeconds

    $window = [int][Math]::Floor(
        $iterationStart / $WindowSeconds
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString("o")

    # ======================================
    # ICMP PROBE
    # ======================================

    $pingOutput = @(
        & ping.exe -n 1 -w 700 $ProbeTarget 2>&1
    )

    $pingExitCode = $LASTEXITCODE

    $icmpSuccess = 0
    $icmpRtt = $null

    if ($pingExitCode -eq 0) {

        $reply = $pingOutput | Where-Object {
            $_ -match "time\s*[=<]\s*\d+\s*ms"
        } | Select-Object -First 1

        if ($null -ne $reply) {

            $icmpSuccess = 1

            if ($reply -match "time\s*([=<])\s*(\d+)\s*ms") {

                $icmpRtt = [double]$Matches[2]

                if ($Matches[1] -eq "<") {
                    $icmpRtt = 0.5
                }
            }
        }
    }

    # ======================================
    # TCP CONNECT PROBE
    # ======================================

    $tcpSuccess = 0
    $tcpConnectMs = $null

    $client = [System.Net.Sockets.TcpClient]::new()
    $tcpWatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {

        $async = $client.BeginConnect(
            $ProbeTarget,
            $TcpPort,
            $null,
            $null
        )

        if ($async.AsyncWaitHandle.WaitOne(1500)) {

            $client.EndConnect($async)

            $tcpWatch.Stop()

            $tcpSuccess = 1

            $tcpConnectMs = [Math]::Round(
                $tcpWatch.Elapsed.TotalMilliseconds,
                3
            )
        }
    }
    catch {
        $tcpSuccess = 0
    }
    finally {

        $tcpWatch.Stop()
        $client.Close()

        if ($null -ne $async) {
            $async.AsyncWaitHandle.Close()
        }
    }

    # ======================================
    # CONTROLLED HTTPS WORKLOAD
    # ======================================

    & curl.exe -L --silent --max-time 2 `
        --output NUL "https://example.com"

    $curlCode = $LASTEXITCODE

    # ======================================
    # SAVE MEASUREMENT
    # ======================================

    $records.Add([pscustomobject]@{
        capture_id = $CaptureId
        condition = $Condition
        timestamp_utc = $timestamp
        elapsed_s = [Math]::Round($iterationStart, 3)
        window_start_s = $window * $WindowSeconds

        icmp_success = $icmpSuccess
        icmp_rtt_ms = $icmpRtt

        tcp_success = $tcpSuccess
        tcp_connect_ms = $tcpConnectMs

        curl_exit_code = $curlCode
    })

    Write-Host (
        "Iteration $iteration | ICMP: $icmpSuccess | " +
        "TCP: $tcpSuccess | TCP time: $tcpConnectMs ms"
    )

    $iteration++

    # One cycle per second when possible.
    $elapsedMs = (
        $clock.Elapsed.TotalSeconds - $iterationStart
    ) * 1000

    $remaining = 1000 - $elapsedMs

    if ($remaining -gt 0) {
        Start-Sleep -Milliseconds ([int]$remaining)
    }
}

$clock.Stop()

# ======================================
# EXPORT RAW MEASUREMENTS
# ======================================

$records | Export-Csv $RawFile -NoTypeInformation

# ======================================
# AGGREGATE 10-SECOND WINDOWS
# ======================================

$summary = @()

$totalWindows = [int][Math]::Ceiling(
    $DurationSeconds / $WindowSeconds
)

for ($w = 0; $w -lt $totalWindows; $w++) {

    $windowStart = $w * $WindowSeconds

    $samples = @(
        $records | Where-Object {
            $_.window_start_s -eq $windowStart
        }
    )

    $sent = $samples.Count

    $icmpReceived = @(
        $samples | Where-Object {
            $_.icmp_success -eq 1
        }
    ).Count

    $tcpReceived = @(
        $samples | Where-Object {
            $_.tcp_success -eq 1
        }
    ).Count

    $icmpValues = @(
        $samples | Where-Object {
            $null -ne $_.icmp_rtt_ms
        } | ForEach-Object {
            [double]$_.icmp_rtt_ms
        }
    )

    $tcpValues = @(
        $samples | Where-Object {
            $null -ne $_.tcp_connect_ms
        } | ForEach-Object {
            [double]$_.tcp_connect_ms
        }
    )

    $icmpLoss = $null
    $tcpFailure = $null
    $icmpMean = $null
    $tcpMean = $null
    $tcpStd = $null

    if ($sent -gt 0) {

        $tcpFailure = 100 * (
            $sent - $tcpReceived
        ) / $sent

        # No ICMP replies does not prove
        # network-wide packet loss.
        if ($icmpReceived -gt 0) {
            $icmpLoss = 100 * (
                $sent - $icmpReceived
            ) / $sent
        }
    }

    if ($icmpValues.Count -gt 0) {
        $icmpMean = (
            $icmpValues | Measure-Object -Average
        ).Average
    }

    if ($tcpValues.Count -gt 0) {

        $tcpMean = (
            $tcpValues | Measure-Object -Average
        ).Average

        $sumSquares = 0

        foreach ($value in $tcpValues) {
            $sumSquares += [Math]::Pow(
                $value - $tcpMean, 2
            )
        }

        $tcpStd = [Math]::Sqrt(
            $sumSquares / $tcpValues.Count
        )
    }

    $icmpStatus = "NO_PROBES"

    if ($sent -gt 0) {

        if ($icmpReceived -eq 0) {
            $icmpStatus = "NO_REPLIES"
        }
        else {
            $icmpStatus = "RESPONDING"
        }
    }

    $summary += [pscustomobject]@{
        capture_id = $CaptureId
        condition = $Condition
        window_start_s = $windowStart

        probe_sent = $sent

        icmp_received = $icmpReceived
        icmp_status = $icmpStatus
        icmp_nonresponse_pct = $icmpLoss
        icmp_rtt_mean_ms = $icmpMean

        tcp_success_count = $tcpReceived
        tcp_failure_pct = $tcpFailure
        tcp_connect_mean_ms = $tcpMean
        tcp_connect_std_ms = $tcpStd
    }
}

$summary | Export-Csv $SummaryFile -NoTypeInformation

Write-Host ""
Write-Host "========================================"
Write-Host " WORKLOAD V3 COMPLETE"
Write-Host "========================================"
Write-Host "Raw: $RawFile"
Write-Host "Summary: $SummaryFile"
Write-Host ""

$summary | Format-Table `
    window_start_s,probe_sent,icmp_status,`
    tcp_success_count,tcp_failure_pct,`
    tcp_connect_mean_ms,tcp_connect_std_ms `
    -AutoSize
