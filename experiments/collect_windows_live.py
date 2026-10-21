"""Live Windows network measurements for AdaptiveVPN-ML.

Read-only measurement collector. Does not connect or switch VPNs.
"""
import argparse
import csv
import math
import socket
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from src.monitor.route_evidence import inspect_current_route


FIELDS = [
    "timestamp_utc",
    "target",
    "window_seconds",
    "tcp_attempts",
    "tcp_connect_mean_ms",
    "tcp_connect_std_ms",
    "tcp_failure_pct",
    "icmp_nonresponse_pct",
    "interface_before",
    "interface_after",
    "route_stable",
    "evidence_level",
    "vpn_path_verified",
]


def tcp_probe(host, port, timeout=2.0):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return (time.perf_counter() - start) * 1000, True
    except OSError:
        return None, False


def icmp_probe(host):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", host],
            capture_output=True,
            timeout=4,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def measure_window(host, port, window_seconds=10, attempts=5):
    if attempts < 1:
        raise ValueError('attempts must be at least 1')
    if window_seconds <= 0:
        raise ValueError('window_seconds must be positive')
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    before = inspect_current_route(host)
    started = time.monotonic()

    latencies = []
    tcp_failures = 0
    icmp_failures = 0

    for index in range(attempts):
        latency, success = tcp_probe(host, port)

        if success:
            latencies.append(latency)
        else:
            tcp_failures += 1

        if not icmp_probe(host):
            icmp_failures += 1

        remaining = window_seconds - (time.monotonic() - started)
        remaining_probes = attempts - index - 1

        if remaining > 0 and remaining_probes > 0:
            time.sleep(remaining / (remaining_probes + 1))

    elapsed = time.monotonic() - started
    if elapsed < window_seconds:
        time.sleep(window_seconds - elapsed)

    after = inspect_current_route(host)

    before_interface = before.get("interface")
    after_interface = after.get("interface")

    before_index = before.get("interface_index")
    after_index = after.get("interface_index")

    stable = (
        before.get("status") == "ROUTE_OBSERVED"
        and after.get("status") == "ROUTE_OBSERVED"
        and bool(before_interface)
        and before_interface == after_interface
        and before_index is not None
        and before_index == after_index
    )

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": f"{host}:{port}",
        "window_seconds": window_seconds,
        "tcp_attempts": attempts,
        "tcp_connect_mean_ms": (
            round(statistics.mean(latencies), 3)
            if latencies else math.nan
        ),
        "tcp_connect_std_ms": (
            round(statistics.pstdev(latencies), 3)
            if latencies else math.nan
        ),
        "tcp_failure_pct": round(100 * tcp_failures / attempts, 3),
        "icmp_nonresponse_pct": round(100 * icmp_failures / attempts, 3),
        "interface_before": before_interface or "",
        "interface_after": after_interface or "",
        "route_stable": stable,
        "evidence_level": "route_selection_only",
        "vpn_path_verified": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="1.1.1.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--windows", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--attempts", type=int, default=5)
    args = parser.parse_args()

    if args.windows < 1 or args.seconds <= 0 or args.attempts < 1:
        parser.error("Windows, seconds and attempts must be positive")

    output_dir = Path("data/processed/live")
    output_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    output = output_dir / f"windows_live_{stamp}.csv"

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()

        for index in range(args.windows):
            result = measure_window(
                args.host,
                args.port,
                args.seconds,
                args.attempts,
            )
            writer.writerow(result)
            file.flush()

            print(
                f"Window {index + 1}/{args.windows} | "
                f"TCP mean: {result['tcp_connect_mean_ms']} ms | "
                f"TCP failure: {result['tcp_failure_pct']}% | "
                f"Interface: {result['interface_after'] or 'unknown'} | "
                f"Route stable: {result['route_stable']}"
            )

    print(f"\nSaved real measurements to: {output}")
    print("VPN path verified: NO")


if __name__ == "__main__":
    main()
