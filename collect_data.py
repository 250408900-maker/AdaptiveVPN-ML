"""Collect multiple network measurements for the AdaptiveVPN-ML project.

This script reuses the existing logic in monitor.py to gather a series of
measurements over time. It is intentionally simple so it can later be expanded
into a larger data-collection workflow for VPN performance analysis.
"""

import argparse
import os
import sys
import time

import adaptive_selector
import monitor


def resolve_protocol(protocol, detected_protocol, detected_status):
    """Apply an optional protocol override while preserving auto-detection defaults."""
    if protocol is None or str(protocol).lower() == "auto":
        return detected_protocol, detected_status

    normalized = str(protocol).strip().lower()
    if normalized in {"wireguard", "openvpn", "vless", "direct"}:
        if normalized == "direct":
            return "direct", "Disconnected"
        return normalized, "Connected"

    if normalized in {"wireguard", "wg"}:
        return "wireguard", "Connected"
    if normalized in {"openvpn", "ovpn"}:
        return "openvpn", "Connected"
    if normalized in {"vless", "xray"}:
        return "vless", "Connected"

    return detected_protocol, detected_status


def run_single_measurement(host, count, speed_test=False, protocol="auto", port=443):
    """Run one measurement and append it to the dataset."""
    try:
        detected_protocol, detected_status = monitor.detect_protocol_state()
        protocol, vpn_status = resolve_protocol(protocol, detected_protocol, detected_status)
        protocol = monitor.normalize_protocol_name(protocol)

        if protocol == "vless" and vpn_status == "Connected":
            metrics = monitor.measure_connection_metrics(host, count=count, protocol="vless", port=port)
            output = "Proxy-aware VLESS measurement via SOCKS5 127.0.0.1:10808"
            return_code = 0 if metrics["packet_loss_pct"] < 100.0 else 1
        else:
            return_code, output = monitor.run_ping(host, count)
            metrics = monitor.parse_ping_output(output)

        if return_code not in (0, 1):
            print(f"  Warning: measurement failed with exit code {return_code}.", file=sys.stderr)
            return False

        download_mbps = None
        upload_mbps = None
        if speed_test:
            try:
                download_val, upload_val = monitor.measure_throughput(protocol)
                if download_val is not None and upload_val is not None:
                    download_mbps = float(download_val)
                    upload_mbps = float(upload_val)
                    print(f"  Download throughput: {download_mbps:.2f} Mbps")
                    print(f"  Upload throughput: {upload_mbps:.2f} Mbps")
                else:
                    print("  Warning: speed test could not complete; leaving throughput values empty.")
            except Exception as exc:
                print(f"  Warning: speed test error: {exc}", file=sys.stderr)

        monitor.print_results(host, metrics, protocol, vpn_status)
        if output.strip():
            print("  Measurement output:\n" + output.strip())

        csv_path = os.path.join(os.path.dirname(monitor.__file__) or ".", "network_data.csv")
        row = monitor.append_measurement(
            csv_path,
            host,
            metrics,
            protocol,
            vpn_status,
            download_mbps,
            upload_mbps,
        )
        if row is None:
            print("  Measurement was incomplete or invalid and was not saved.", file=sys.stderr)
            return False

        if protocol in {"wireguard", "openvpn", "vless"}:
            try:
                if not os.path.exists(adaptive_selector.STATE_PATH):
                    adaptive_selector.train_from_dataset(csv_path, adaptive_selector.STATE_PATH)
                updated, reward = adaptive_selector.record_measurement_from_row(
                    protocol=protocol,
                    timestamp=row.get("timestamp"),
                    host=row.get("target_host"),
                    latency=row.get("latency_ms"),
                    loss=row.get("packet_loss_percent"),
                    jitter=row.get("jitter_ms"),
                    download=row.get("download_mbps"),
                    upload=row.get("upload_mbps"),
                    state_path=adaptive_selector.STATE_PATH,
                )
                if updated:
                    recommended_protocol, _, recommendation_text = adaptive_selector.recommend_protocol(csv_path, adaptive_selector.STATE_PATH)
                    print(f"  Selector updated with {protocol} observation.")
                    print(f"  Recommended protocol: {recommended_protocol}")
                    print(f"  {recommendation_text}")
                else:
                    print("  Selector already contains this measurement; no duplicate update was recorded.")
            except Exception as exc:
                print(f"  Warning: selector update failed but measurement was saved: {exc}", file=sys.stderr)

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
    parser.add_argument(
        "--protocol",
        default="auto",
        choices=["auto", "wireguard", "openvpn", "vless", "direct"],
        help="Override detection and record a specific protocol label. Default: auto.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="TCP port used for proxy-aware VLESS and optional protocol-specific checks (default: 443).",
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
        success = run_single_measurement(
            args.host,
            args.count,
            speed_test=args.speed_test,
            protocol=args.protocol,
            port=args.port,
        )
        if not success:
            print("  Measurement failed or was skipped; continuing to the next one.")

        if index < args.measurements and args.delay > 0:
            print(f"Waiting {args.delay} seconds before the next measurement...")
            time.sleep(args.delay)

    print("\nCollection complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
