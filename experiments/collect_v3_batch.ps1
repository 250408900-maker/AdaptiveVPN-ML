
param(
    [ValidateSet(
        "NORMAL",
        "HIGH_LATENCY",
        "HIGH_JITTER",
        "PACKET_LOSS"
    )]
    [string]$Condition = "NORMAL",

    [ValidateRange(1, 100)]
    [int]$Count = 3,

    [ValidateRange(1, 999)]
    [int]$StartIndex = 1,

    [ValidateRange(10, 3600)]
    [int]$DurationSeconds = 60,

    [int]$Interface = 5,

    [ValidateRange(1, 10)]
    [int]$MaxAttemptsPerCapture = 2,

    # 0 means require all expected 10-second windows.
    [ValidateRange(0, 360)]
    [int]$MinAlignedWindows = 0
)

$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent $PSScriptRoot
$CaptureScript = Join-Path $PSScriptRoot "capture_v3.ps1"
$Extractor = Join-Path $Repo "src\features\extract_v3.py"

$ConditionName = $Condition.ToLowerInvariant()

$CaptureFolder = Join-Path $Repo "data\captures\v3\$ConditionName"
$ProbeFolder = Join-Path $Repo "data\processed\probes"
$FeatureFolder = Join-Path $Repo "data\processed\v3"
$ReportFolder = Join-Path $FeatureFolder "reports"

foreach ($folder in @(
    $CaptureFolder,
    $ProbeFolder,
    $FeatureFolder,
    $ReportFolder
)) {
    New-Item -ItemType Directory -Force -Path $folder |
        Out-Null
}

if (!(Test-Path $CaptureScript)) {
    throw "Capture script not found: $CaptureScript"
}

if (!(Test-Path $Extractor)) {
    throw "Extractor not found: $Extractor"
}

if ($DurationSeconds % 10 -ne 0) {
    throw "DurationSeconds must be a multiple of 10."
}

$ExpectedWindows = [int]($DurationSeconds / 10)

if ($MinAlignedWindows -eq 0) {
    $RequiredWindows = $ExpectedWindows
}
else {
    $RequiredWindows = $MinAlignedWindows
}

if ($RequiredWindows -gt $ExpectedWindows) {
    throw "MinAlignedWindows cannot exceed $ExpectedWindows."
}

$MaximumAttempts = $Count * $MaxAttemptsPerCapture
$LastIndex = $StartIndex + $MaximumAttempts - 1

if ($LastIndex -gt 999) {
    throw "Not enough capture IDs remain before index 999."
}

# Reserve all possible filenames before starting.
# Never overwrite previous experiments.
for ($index = $StartIndex; $index -le $LastIndex; $index++) {

    $Id = "{0}_v3_{1:000}" -f $ConditionName, $index

    $Files = @(
        (Join-Path $CaptureFolder "$Id.pcapng"),
        (Join-Path $CaptureFolder "${Id}_manifest.json"),
        (Join-Path $ProbeFolder "${Id}_raw.csv"),
        (Join-Path $ProbeFolder "${Id}_summary.csv"),
        (Join-Path $FeatureFolder "${Id}_features.csv")
    )

    foreach ($file in $Files) {
        if (Test-Path $file) {
            throw "Existing file: $file. Choose a higher StartIndex."
        }
    }
}

$ReportTime = Get-Date -Format "yyyyMMdd_HHmmss_fff"

$ReportPath = Join-Path $ReportFolder (
    "${ConditionName}_batch_${ReportTime}.csv"
)

$Results = [System.Collections.Generic.List[object]]::new()

$NextIndex = $StartIndex
$AcceptedCount = 0
$RejectedCount = 0
$TotalWindows = 0

Write-Host ""
Write-Host "=========================================="
Write-Host " AdaptiveVPN-ML V3 Batch Collector"
Write-Host "=========================================="
Write-Host "Condition: $Condition"
Write-Host "Target accepted captures: $Count"
Write-Host "Duration: $DurationSeconds seconds"
Write-Host "Expected windows: $ExpectedWindows"
Write-Host "Minimum accepted windows: $RequiredWindows"
Write-Host "Max attempts per capture: $MaxAttemptsPerCapture"
Write-Host "=========================================="

Push-Location $Repo

try {

    for ($target = 1; $target -le $Count; $target++) {

        $Accepted = $false

        for (
            $attempt = 1;
            $attempt -le $MaxAttemptsPerCapture;
            $attempt++
        ) {

            $CaptureId = "{0}_v3_{1:000}" -f `
                $ConditionName, $NextIndex

            $NextIndex++

            $Manifest = Join-Path $CaptureFolder (
                "${CaptureId}_manifest.json"
            )

            $Features = Join-Path $FeatureFolder (
                "${CaptureId}_features.csv"
            )

            Write-Host ""
            Write-Host "=========================================="
            Write-Host " Target $target / $Count"
            Write-Host " Attempt $attempt / $MaxAttemptsPerCapture"
            Write-Host " Capture: $CaptureId"
            Write-Host "=========================================="

            # If the capture runner itself fails, stop.
            # Retrying while a failed TShark process might
            # still be active could create overlapping captures.
            & $CaptureScript `
                -Condition $Condition `
                -CaptureId $CaptureId `
                -DurationSeconds $DurationSeconds `
                -Interface $Interface

            if (!(Test-Path $Manifest)) {
                throw "Capture runner did not create $Manifest"
            }

            $Metadata = Get-Content $Manifest -Raw |
                ConvertFrom-Json

            Write-Host ""
            Write-Host "Extracting synchronized ML features..."

            python $Extractor $Manifest

            if ($LASTEXITCODE -ne 0) {
                throw "Feature extraction failed: $CaptureId"
            }

            if (!(Test-Path $Features)) {
                throw "Feature CSV missing: $Features"
            }

            $Rows = @(Import-Csv -LiteralPath $Features)
            $AlignedWindows = $Rows.Count

            $UniqueWindows = @(
                $Rows |
                ForEach-Object { $_.window_start_s } |
                Sort-Object -Unique
            ).Count

            $Quality = [string]$Metadata.capture_quality

            $FullCoverage = (
                $Quality -eq "FULL_COVERAGE"
            )

            $EnoughWindows = (
                $AlignedWindows -ge $RequiredWindows -and
                $UniqueWindows -eq $AlignedWindows
            )

            $Accepted = (
                $FullCoverage -and $EnoughWindows
            )

            if ($Accepted) {
                $Status = "ACCEPTED"
                $AcceptedCount++
                $TotalWindows += $AlignedWindows
            }
            else {
                $Status = "REJECTED"
                $RejectedCount++
            }

            $Results.Add(
                [PSCustomObject]@{
                    capture_id = $CaptureId
                    condition = $Condition
                    target = $target
                    attempt = $attempt
                    status = $Status
                    capture_quality = $Quality
                    aligned_windows = $AlignedWindows
                    expected_windows = $ExpectedWindows
                    required_windows = $RequiredWindows
                    first_packet_offset_s = $Metadata.first_packet_offset_s
                    last_packet_offset_s = $Metadata.last_packet_offset_s
                    packet_count = $Metadata.packet_count
                    probe_count = $Metadata.probe_count
                    feature_file = $Features
                }
            )

            Write-Host ""
            Write-Host "------------------------------------------"
            Write-Host "Capture: $CaptureId"
            Write-Host "Coverage: $Quality"
            Write-Host "Aligned windows: $AlignedWindows / $ExpectedWindows"
            Write-Host "Decision: $Status"
            Write-Host "------------------------------------------"

            if ($Accepted) {
                Write-Host "Capture accepted."
                break
            }

            Write-Warning (
                "Capture did not meet quality requirements."
            )

            if ($attempt -lt $MaxAttemptsPerCapture) {
                Write-Host "Automatically retrying with a new ID..."
                Start-Sleep -Seconds 5
            }
        }

        if (!$Accepted) {
            Write-Warning (
                "Target $target failed after " +
                "$MaxAttemptsPerCapture attempts. " +
                "Continuing to the next target."
            )
        }

        if ($target -lt $Count) {
            Start-Sleep -Seconds 3
        }
    }

}
finally {

    Pop-Location

    if ($Results.Count -gt 0) {
        $Results |
            Export-Csv `
                -LiteralPath $ReportPath `
                -NoTypeInformation `
                -Encoding UTF8
    }

    Write-Host ""
    Write-Host "=========================================="
    Write-Host " V3 BATCH SUMMARY"
    Write-Host "=========================================="
    Write-Host "Condition: $Condition"
    Write-Host "Accepted captures: $AcceptedCount / $Count"
    Write-Host "Rejected attempts: $RejectedCount"
    Write-Host "Accepted aligned windows: $TotalWindows"
    Write-Host "Report: $ReportPath"
    Write-Host "=========================================="
}

if ($AcceptedCount -lt $Count) {
    throw (
        "Batch incomplete: only $AcceptedCount of " +
        "$Count target captures met quality requirements."
    )
}
