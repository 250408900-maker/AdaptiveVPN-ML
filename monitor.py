

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from datetime import datetime

CSV_COLUMNS = [
    "timestamp",
    "target_host",
    "protocol",
    "vpn_status",
    "connection_label",
    "latency_ms",
    "packet_loss_percent",
    "jitter_ms",
    "download_mbps",
    "upload_mbps",
]


def run_ping(host, count=4):
    """Run a Windows ping command and return its exit code and raw output."""
    command = ["ping", "-n", str(count), host]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode, output


def parse_ping_output(output):
    """Extract response times and packet loss from the ping output."""
    latencies = []
    average_latency = None
    packet_loss = 0.0

    # Example Windows ping response:
    # Reply from 8.8.8.8: bytes=32 time=18ms TTL=118
    for line in output.splitlines():
        match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", line, re.IGNORECASE)
        if match:
            latencies.append(float(match.group(1)))

    # Example summary line:
    # Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
    packet_match = re.search(
        r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\((\d+(?:\.\d+)?)%\s*loss\)",
        output,
        re.IGNORECASE,
    )
    if packet_match:
        packet_loss = float(packet_match.group(4))

    # Fallback: if the summary line is not present, estimate from sent/received.
    if packet_loss == 0.0:
        sent_match = re.search(r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+)", output, re.IGNORECASE)
        if sent_match:
            sent = float(sent_match.group(1))
            received = float(sent_match.group(2))
            if sent > 0:
                packet_loss = ((sent - received) / sent) * 100.0

    # For some ping outputs, the average latency is printed directly.
    average_match = re.search(r"Average\s*=\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    if average_match:
        average_latency = float(average_match.group(1))

    if latencies:
        if average_latency is None:
            average_latency = sum(latencies) / len(latencies)
        jitter = 0.0
        if len(latencies) > 1:
            deltas = [abs(latencies[index] - latencies[index - 1]) for index in range(1, len(latencies))]
            jitter = sum(deltas) / len(deltas)
    else:
        jitter = 0.0

    return {
        "latency_ms": average_latency if average_latency is not None else 0.0,
        "packet_loss_pct": packet_loss,
        "jitter_ms": jitter,
        "samples": latencies,
    }


def run_powershell_json(command):
    """Run a PowerShell command and return parsed JSON output if available."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def is_valid_ip_address(value):
    """Reject link-local or placeholder addresses as evidence of an inactive tunnel."""
    if not value:
        return False
    value = value.strip()
    if value.lower() in {"not available", "unknown", "", "manual"}:
        return False
    if value.startswith("169.254.") or value.startswith("fe80::"):
        return False
    return True


def normalize_media_state(value):
    """Convert PowerShell numeric media state values into a human-readable label."""
    if value is None:
        return "unknown"
    if isinstance(value, int):
        mapping = {
            0: "unknown",
            1: "connected",
            2: "disconnected",
            3: "connecting",
            4: "disconnecting",
        }
        return mapping.get(value, str(value).lower())
    return str(value).strip().lower()


def get_connection_label(protocol, vpn_status):
    """Map the detected VPN state to a simple dataset label."""
    if protocol == "WireGuard" and vpn_status == "Connected":
        return "vpn"
    return "no_vpn"


def check_wireguard_vpn(adapters, ip_addresses):
    """Return WireGuard state if an active WireGuard adapter is present."""
    for adapter in adapters:
        name = str(adapter.get("Name", "")).strip()
        description = str(adapter.get("InterfaceDescription", "")).strip()
        status = str(adapter.get("Status", "")).strip().lower()
        media_state = normalize_media_state(adapter.get("MediaConnectionState"))

        if "wireguard" not in (name + " " + description).lower():
            continue

        if status != "up" or media_state not in {"connected", "up"}:
            continue

        assigned_ips = [
            entry.get("IPAddress", "")
            for entry in ip_addresses
            if str(entry.get("InterfaceAlias", "")).lower() == name.lower()
        ]
        if not assigned_ips:
            continue

        has_valid_ip = any(is_valid_ip_address(item) for item in assigned_ips)
        if not has_valid_ip:
            continue

        return "WireGuard", "Connected"

    return "None", "Disconnected"


def detect_vpn_connection():
    """Detect the current active VPN protocol or report no VPN connection.

    This is the generic entry point for future multi-protocol detection. For now,
    only WireGuard is supported, and the logic intentionally mirrors the original
    behavior so the project remains stable while future protocols can be added.
    """
    adapters = run_powershell_json(
        "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MediaConnectionState | ConvertTo-Json -Depth 10"
    )
    ip_addresses = run_powershell_json(
        "Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, Type | ConvertTo-Json -Depth 10"
    )

    if not isinstance(adapters, list):
        adapters = []
    if not isinstance(ip_addresses, list):
        ip_addresses = []

    # Future protocol checks can be added here in order of preference.
    wireguard_result = check_wireguard_vpn(adapters, ip_addresses)
    if wireguard_result[0] != "None":
        return wireguard_result

    return "None", "Disconnected"


def detect_wireguard_vpn():
    """Backward-compatible wrapper for the original WireGuard-only detection."""
    return detect_vpn_connection()


def print_results(host, metrics, protocol="None", vpn_status="Disconnected"):
    """Display the measured network quality in a readable format."""
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    print("\n" + "=" * 60)
    print("AdaptiveVPN-ML Network Quality Monitor")
    print("=" * 60)
    print(f"Timestamp: {timestamp}")
    print(f"Target host: {host}")
    print(f"VPN protocol: {protocol}")
    print(f"VPN status: {vpn_status}")
    print(f"Ping latency (average): {metrics['latency_ms']:.2f} ms")
    print(f"Packet loss: {metrics['packet_loss_pct']:.2f}%")
    print(f"Jitter: {metrics['jitter_ms']:.2f} ms")
    print("=" * 60)


def ensure_csv_header(csv_path):
    """Create the CSV file and header if needed while preserving existing rows."""
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(CSV_COLUMNS)
        return

    with open(csv_path, "r", newline="", encoding="utf-8") as csv_file:
        rows = list(csv.reader(csv_file))

    if not rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(CSV_COLUMNS)
        return

    header = rows[0]
    if header == CSV_COLUMNS:
        return

    header_map = {name: index for index, name in enumerate(header)}
    new_header = list(CSV_COLUMNS)
    updated_rows = [header]

    for row in rows[1:]:
        padded = row[:]
        while len(padded) < len(new_header):
            padded.append("")
        for column in CSV_COLUMNS:
            if column not in header_map:
                padded.append("")
        updated_rows.append(padded[: len(new_header)])

    for column in CSV_COLUMNS:
        if column not in header_map:
            header.append(column)

    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_COLUMNS)
        for row in rows[1:]:
            padded = row[:]
            while len(padded) < len(CSV_COLUMNS):
                padded.append("")
            writer.writerow(padded[: len(CSV_COLUMNS)])


def append_measurement(csv_path, host, metrics, protocol="None", vpn_status="Disconnected", download_mbps="", upload_mbps=""):
    """Append one completed measurement to the CSV dataset."""
    ensure_csv_header(csv_path)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    connection_label = get_connection_label(protocol, vpn_status)

    with open(csv_path, "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                timestamp,
                host,
                protocol,
                vpn_status,
                connection_label,
                f"{metrics['latency_ms']:.2f}",
                f"{metrics['packet_loss_pct']:.2f}",
                f"{metrics['jitter_ms']:.2f}",
                download_mbps,
                upload_mbps,
            ]
        )


def measure_throughput():
    """Run a speed test if the speedtest-cli dependency is available."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "speedtest", "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )
    except FileNotFoundError:
        print(
            "Warning: speedtest-cli is not installed. Install it with: pip install speedtest-cli",
            file=sys.stderr,
        )
        return None, None
    except subprocess.TimeoutExpired:
        print("Warning: speed test timed out after 90 seconds.", file=sys.stderr)
        return None, None

    if result.returncode != 0:
        print(
            "Warning: speed test failed. Install speedtest-cli with: pip install speedtest-cli",
            file=sys.stderr,
        )
        return None, None

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Warning: speed test returned invalid output and was skipped.", file=sys.stderr)
        return None, None

    download_mbps = payload.get("download")
    upload_mbps = payload.get("upload")
    if download_mbps is None or upload_mbps is None:
        print("Warning: speed test output did not contain download/upload values.", file=sys.stderr)
        return None, None

    try:
        download_mbps = float(download_mbps) / 1_000_000.0
        upload_mbps = float(upload_mbps) / 1_000_000.0
    except (TypeError, ValueError):
        print("Warning: speed test values could not be parsed.", file=sys.stderr)
        return None, None

    return download_mbps, upload_mbps


def main():
    """Parse command-line input and run the monitor."""
    parser = argparse.ArgumentParser(
        description="Measure basic network quality using the Windows ping command."
    )
    parser.add_argument(
        "--host",
        default="8.8.8.8",
        help="Target IP address or hostname to ping (default: 8.8.8.8).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=4,
        help="Number of ping requests to send (default: 4).",
    )
    parser.add_argument(
        "--speed-test",
        action="store_true",
        help="Run a speed test using speedtest-cli and record download/upload Mbps.",
    )
    args = parser.parse_args()

    if args.count <= 0:
        print("Error: --count must be greater than zero.", file=sys.stderr)
        return 1

    try:
        protocol, vpn_status = detect_wireguard_vpn()
        return_code, output = run_ping(args.host, args.count)
        metrics = parse_ping_output(output)

        if return_code not in (0, 1):
            print(f"Ping command failed with exit code {return_code}.", file=sys.stderr)
            print(output, file=sys.stderr)
            return return_code

        print_results(args.host, metrics, protocol, vpn_status)
        if output.strip():
            print("Ping output:\n" + output.strip())

        download_mbps = ""
        upload_mbps = ""
        if args.speed_test:
            download_mbps, upload_mbps = measure_throughput()
            if download_mbps is not None and upload_mbps is not None:
                print(f"Download throughput: {download_mbps:.2f} Mbps")
                print(f"Upload throughput: {upload_mbps:.2f} Mbps")

        csv_path = os.path.join(os.path.dirname(__file__) or ".", "network_data.csv")
        append_measurement(
            csv_path,
            args.host,
            metrics,
            protocol,
            vpn_status,
            "" if download_mbps is None else f"{download_mbps:.2f}",
            "" if upload_mbps is None else f"{upload_mbps:.2f}",
        )
        return 0

    except Exception as exc:  # pragma: no cover - defensive error handling.
        print(f"Error measuring network quality: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
