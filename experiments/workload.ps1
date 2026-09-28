param(
    [int]$DurationSeconds = 60
)

Write-Host ""
Write-Host "========================================"
Write-Host " AdaptiveVPN-ML Controlled Workload V2"
Write-Host "========================================"
Write-Host "Duration: $DurationSeconds seconds"
Write-Host ""

$end = (Get-Date).AddSeconds($DurationSeconds)
$iteration = 1

while ((Get-Date) -lt $end) {

    $iterationStart = Get-Date

    Write-Host "Workload iteration $iteration"

    # HTTPS traffic
    curl.exe -L `
        --silent `
        --output NUL `
        "https://example.com"

    # ICMP traffic
    ping.exe 1.1.1.1 -n 1 | Out-Null

    # Keep approximately one workload cycle per second
    $elapsed = ((Get-Date) - $iterationStart).TotalMilliseconds
    $remaining = 1000 - $elapsed

    if ($remaining -gt 0) {
        Start-Sleep -Milliseconds ([int]$remaining)
    }

    $iteration++
}

Write-Host ""
Write-Host "========================================"
Write-Host " WORKLOAD COMPLETE"
Write-Host "========================================"