"""Collect multiple network measurements for the AdaptiveVPN-ML project.

This script reuses the existing logic in monitor.py to gather a series of
measurements over time. It is intentionally simple so it can later be expanded
into a larger data-collection workflow for VPN performance analysis.
"""

import argparse
import os
import sys
import time

import monitor


def run_single_measurement(host, count, speed_test=False):
    """Run one measurement and append it to the dataset."""
    try:
        protocol, vpn_status = monitor.detect_wireguard_vpn()
        return_code, output = monitor.run_ping(host, count)
        metrics = monitor.parse_ping_output(output)

        if return_code not in (0, 1):
            print(f"  Warning: ping failed with exit code {return_code}.", file=sys.stderr)
            return False

        download_mbps = ""
        upload_mbps = ""
        if speed_test:
            try:
                download_val, upload_val = monitor.measure_throughput()
                if download_val is not None and upload_val is not None:
                    download_mbps = f"{download_val:.2f}"
                    upload_mbps = f"{upload_val:.2f}"
                    print(f"  Download throughput: {download_mbps} Mbps")
                    print(f"  Upload throughput: {upload_mbps} Mbps")
                else:
                    print("  Warning: speed test could not complete; saving empty values.")
            except Exception as exc:
                print(f"  Warning: speed test error: {exc}", file=sys.stderr)

        monitor.print_results(host, metrics, protocol, vpn_status)
        if output.strip():
            print("  Ping output:\n" + output.strip())

        csv_path = os.path.join(os.path.dirname(monitor.__file__) or ".", "network_data.csv")
        monitor.append_measurement(
            csv_path,
            host,
            metrics,
            protocol,
            vpn_status,
            download_mbps,
            upload_mbps,
        )
        return True

    except Exception as exc:
        print(f"  Error during measurement: {exc}", file=sys.stderr)
        return False


def main():
    """Collect repeated measurements according to user-specified settings."""
    parser = argparse.ArgumentParser(
        description="Collect repeated network measurements and append them to network_data.csv."
    )
    parser.add_argument(
        "--host",
        default="8.8.8.8",
        help="Target host or IP address to ping (default: 8.8.8.8).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=4,
        help="Number of ping requests per measurement (default: 4).",
    )
    parser.add_argument(
        "--measurements",
        type=int,
        default=5,
        help="Total number of measurements to collect (default: 5).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Seconds to wait between measurements (default: 5).",
    )
    parser.add_argument(
        "--speed-test",
        action="store_true",
        help="Run a speed test during each measurement when available.",
    )
    args = parser.parse_args()

    if args.count <= 0:
        print("Error: --count must be greater than zero.", file=sys.stderr)
        return 1
    if args.measurements <= 0:
        print("Error: --measurements must be greater than zero.", file=sys.stderr)
        return 1
    if args.delay < 0:
        print("Error: --delay cannot be negative.", file=sys.stderr)
        return 1

    print(f"Starting collection: {args.measurements} measurement(s), delay={args.delay}s")

    for index in range(1, args.measurements + 1):
        print(f"\nMeasurement {index}/{args.measurements}")
        success = run_single_measurement(args.host, args.count, speed_test=args.speed_test)
        if not success:
            print("  Measurement failed or was skipped; continuing to the next one.")

        if index < args.measurements and args.delay > 0:
            print(f"Waiting {args.delay} seconds before the next measurement...")
            time.sleep(args.delay)

    print("\nCollection complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
