import argparse
import csv
import math
from pathlib import Path


def summarize(path, label):
    with Path(path).open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        raise ValueError(f"Empty dataset: {path}")

    attempts = sum(int(r["tcp_attempts"]) for r in rows)
    failures = sum(
        round(int(r["tcp_attempts"]) * float(r["tcp_failure_pct"]) / 100)
        for r in rows
    )
    latencies = [
        float(r["tcp_connect_mean_ms"])
        for r in rows
        if math.isfinite(float(r["tcp_connect_mean_ms"]))
    ]

    return {
        "label": label,
        "windows": len(rows),
        "tcp_attempts": attempts,
        "tcp_failures": failures,
        "tcp_successes": attempts - failures,
        "mean_window_latency_ms": (
            round(sum(latencies) / len(latencies), 3)
            if latencies else None
        ),
        "interfaces": sorted({
            r["interface_before"] for r in rows
            if r.get("interface_before")
        }),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset", action="append", nargs=2,
        metavar=("LABEL", "CSV"), required=True
    )
    args = parser.parse_args()

    print("OBSERVATIONAL DATASET SUMMARY")
    print("Not a controlled route-performance comparison")
    print()

    for label, path in args.dataset:
        result = summarize(path, label)
        print(result)
        print()


if __name__ == "__main__":
    main()
