"""Validate the AdaptiveVPN-ML network dataset without modifying it.

This script reads network_data.csv and reports basic dataset quality checks:
- total measurement count
- protocol distribution
- missing values
- obviously invalid numeric values
- summary statistics by protocol
- sample-balance warnings

The script is deliberately read-only and uses only Python standard library tools.
"""

import argparse
import csv
import math
import os
import statistics
import sys
from collections import Counter, defaultdict


DEFAULT_CSV_PATH = os.path.join(os.path.dirname(__file__) or ".", "network_data.csv")
NUMERIC_FIELDS = [
    "latency_ms",
    "packet_loss_percent",
    "jitter_ms",
    "download_mbps",
    "upload_mbps",
]


def safe_float(value):
    """Convert a CSV value to a float, returning None for empty or invalid input."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    try:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return None
        return number
    except (TypeError, ValueError):
        return None


def load_rows(csv_path):
    """Open the CSV file and return a list of dict rows, or an empty list on error."""
    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            rows = list(reader)
            return rows
    except FileNotFoundError:
        print(f"Dataset not found: {csv_path}", file=sys.stderr)
        return []
    except OSError as exc:
        print(f"Could not read dataset: {exc}", file=sys.stderr)
        return []


def show_total_measurements(rows):
    """Print the total number of measurements in the CSV dataset."""
    print(f"Total measurements: {len(rows)}")


def show_protocol_counts(rows):
    """Summarize the number of rows by protocol."""
    counts = Counter((row.get("protocol") or "unknown").strip() or "unknown" for row in rows)
    print("Protocol counts:")
    if not counts:
        print("  none")
        return
    for protocol, count in sorted(counts.items()):
        print(f"  {protocol}: {count}")


def show_missing_values(rows):
    """Report the fields that are missing or empty in each row."""
    missing = defaultdict(int)
    for row in rows:
        for key in row:
            value = row.get(key, "")
            if value is None or str(value).strip() == "":
                missing[key] += 1

    print("Missing values:")
    if not missing:
        print("  none")
        return
    for field, count in sorted(missing.items()):
        print(f"  {field}: {count}")


def show_invalid_values(rows):
    """Flag obviously invalid measurement values.

    Invalid values include negative latency metrics, packet loss > 100%, or other
    impossible throughput readings.
    """
    invalid_rows = []
    for index, row in enumerate(rows, start=1):
        line_number = index
        issues = []

        for field in NUMERIC_FIELDS:
            value = safe_float(row.get(field, ""))
            if value is None:
                continue
            if field in {"latency_ms", "jitter_ms"} and value < 0:
                issues.append(f"{field} < 0")
            if field == "packet_loss_percent" and (value < 0 or value > 100):
                issues.append(f"{field} outside [0, 100]")
            if field in {"download_mbps", "upload_mbps"} and value < 0:
                issues.append(f"{field} < 0")

        if issues:
            invalid_rows.append((line_number, issues, row.get("protocol", "")))

    print("Invalid values:")
    if not invalid_rows:
        print("  none")
        return

    for line_number, issues, protocol in invalid_rows:
        print(f"  row {line_number} (protocol={protocol}): {', '.join(issues)}")


def summarize_by_protocol(rows):
    """Return basic statistics for each protocol group."""
    values_by_protocol = defaultdict(lambda: defaultdict(list))
    for row in rows:
        protocol = (row.get("protocol") or "unknown").strip() or "unknown"
        for field in NUMERIC_FIELDS:
            value = safe_float(row.get(field, ""))
            if value is not None:
                values_by_protocol[protocol][field].append(value)

    print("Basic statistics by protocol:")
    if not values_by_protocol:
        print("  no data")
        return

    for protocol in sorted(values_by_protocol):
        print(f"  Protocol: {protocol}")
        for field in NUMERIC_FIELDS:
            items = values_by_protocol[protocol][field]
            if not items:
                print(f"    {field}: no valid data")
                continue
            mean_value = statistics.mean(items)
            median_value = statistics.median(items)
            minimum = min(items)
            maximum = max(items)
            print(
                f"    {field}: avg={mean_value:.3f}, median={median_value:.3f}, "
                f"min={minimum:.3f}, max={maximum:.3f}, count={len(items)}"
            )


def warn_if_unbalanced(rows):
    """Warn when one protocol dominates the dataset.

    This is a simple sanity check to avoid building a dataset that is too skewed
    for comparison work. It does not mutate the CSV or stop collection.
    """
    counts = Counter((row.get("protocol") or "unknown").strip() or "unknown" for row in rows)
    if len(counts) <= 1 or not rows:
        return

    total = sum(counts.values())
    largest_count = max(counts.values())
    ratio = largest_count / total
    if ratio >= 0.8:
        print("WARNING: protocol sample counts are significantly unbalanced.", file=sys.stderr)
        print(
            f"  Largest protocol share: {ratio:.1%} ({largest_count}/{total}).",
            file=sys.stderr,
        )
        print("  Consider collecting more balanced samples across protocols.", file=sys.stderr)


def main():
    """CLI entry point for dataset validation."""
    parser = argparse.ArgumentParser(
        description="Validate network_data.csv without changing the dataset."
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV_PATH,
        help="Path to the CSV file to validate (default: network_data.csv in this project folder).",
    )
    args = parser.parse_args()

    csv_path = os.path.abspath(args.csv)
    rows = load_rows(csv_path)
    if not rows:
        print("No data rows were loaded.")
        return 1

    print(f"Dataset: {csv_path}")
    show_total_measurements(rows)
    show_protocol_counts(rows)
    show_missing_values(rows)
    show_invalid_values(rows)
    summarize_by_protocol(rows)
    warn_if_unbalanced(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
