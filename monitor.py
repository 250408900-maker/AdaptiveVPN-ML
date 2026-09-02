

import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

import adaptive_selector

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


def parse_float_or_none(value):
    """Normalize numeric values to float while treating missing or invalid inputs as None."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return None
        try:
            parsed = float(stripped)
        except ValueError:
            return None
        return parsed
    return None


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
        "latency_ms": float(average_latency if average_latency is not None else 0.0),
        "packet_loss_pct": float(packet_loss),
        "jitter_ms": float(jitter),
        "samples": latencies,
    }


def socks5_connect_via_proxy(host, port, proxy_host="127.0.0.1", proxy_port=10808, timeout=2.0):
    """Open a SOCKS5 TCP connection through the local VLESS/v2rayN proxy.

    This is intentionally lightweight and standard-library only. It is used for
    VLESS measurement quality checks because ordinary ICMP ping does not reliably
    traverse the proxy path in v2rayN system-proxy mode.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))

    handshake = b"\x05\x01\x00"
    sock.sendall(handshake)
    response = sock.recv(2)
    if len(response) != 2 or response[0] != 0x05 or response[1] != 0x00:
        sock.close()
        raise OSError("Proxy handshake failed")

    # CONNECT to the target host. IPv4 or domain names are both supported.
    try:
        target_ip = socket.inet_aton(host)
        addr_type = 0x01
        addr_bytes = target_ip
    except OSError:
        addr_type = 0x03
        host_bytes = host.encode("idna")
        addr_bytes = bytes([len(host_bytes)]) + host_bytes

    if addr_type == 0x01:
        request = b"\x05\x01\x00\x01" + addr_bytes + socket.htons(port).to_bytes(2, byteorder="big")
    else:
        request = b"\x05\x01\x00\x03" + addr_bytes + socket.htons(port).to_bytes(2, byteorder="big")

    sock.sendall(request)
    response = sock.recv(10)
    if len(response) < 2:
        sock.close()
        raise OSError("Proxy CONNECT response was incomplete")
    if response[0] != 0x05 or response[1] != 0x00:
        sock.close()
        raise OSError(f"Proxy CONNECT failed with SOCKS5 status {response[1]}")

    # A successful CONNECT means we reached the target through the proxy path.
    return sock


def measure_vless_proxy_metrics(host, count=4, port=443, timeout=2.5):
    """Measure latency, loss, and jitter through the VLESS proxy path.

    Because the VLESS route is not visible to ICMP, the probe uses repeated
    lightweight SOCKS5 CONNECT requests to the target via 127.0.0.1:10808 and
    derives metrics from success/failure and elapsed connection time.
    """
    latencies = []
    failed_attempts = 0

    for _ in range(max(1, int(count))):
        start = time.perf_counter()
        try:
            proxy_sock = socks5_connect_via_proxy(host, port, timeout=timeout)
            proxy_sock.close()
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            latencies.append(elapsed_ms)
        except OSError:
            failed_attempts += 1

    if not latencies:
        return {
            "latency_ms": 0.0,
            "packet_loss_pct": 100.0,
            "jitter_ms": 0.0,
            "samples": [],
        }

    latency_avg = sum(latencies) / len(latencies)
    jitter = 0.0
    if len(latencies) > 1:
        deltas = [abs(latencies[index] - latencies[index - 1]) for index in range(1, len(latencies))]
        jitter = sum(deltas) / len(deltas)

    loss_pct = (failed_attempts / max(1, count)) * 100.0
    return {
        "latency_ms": latency_avg,
        "packet_loss_pct": loss_pct,
        "jitter_ms": jitter,
        "samples": latencies,
    }


def measure_connection_metrics(host, count=4, protocol="direct", port=443, timeout=2.5):
    """Return latency, loss, and jitter for the active protocol.

    Direct, WireGuard, and OpenVPN continue to use ICMP ping. For VLESS we use a
    SOCKS5 proxy-aware TCP probe because ICMP does not traverse the proxy path.
    """
    normalized = str(protocol or "direct").strip().lower()
    if normalized == "vless":
        return measure_vless_proxy_metrics(host, count=count, port=port, timeout=timeout)

    return_code, output = run_ping(host, count)
    metrics = parse_ping_output(output)
    metrics["return_code"] = return_code
    metrics["output"] = output
    return metrics


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


def normalize_protocol_name(protocol):
    """Normalize protocol labels to the canonical lowercase dataset values."""
    normalized = str(protocol or "direct").strip().lower()
    if normalized in {"", "none", "null", "direct"}:
        return "direct"
    if normalized in {"wireguard", "wg"}:
        return "wireguard"
    if normalized in {"openvpn", "ovpn"}:
        return "openvpn"
    if normalized in {"vless", "vless/xray", "xray"}:
        return "vless"
    return normalized


def get_connection_label(protocol, vpn_status):
    """Map protocol/state to a simple dataset label.

    This keeps the CSV readable for downstream analysis while distinguishing
    direct internet access from VPN/proxy traffic.
    """
    normalized = normalize_protocol_name(protocol)
    if normalized in {"direct", "none"}:
        return "direct"
    if normalized in {"wireguard", "openvpn"}:
        return "vpn" if vpn_status == "Connected" else "direct"
    if normalized == "vless":
        return "proxy" if vpn_status == "Connected" else "direct"
    return "direct"


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

        return "wireguard", "Connected"

    return None


def check_openvpn_vpn(adapters, ip_addresses):
    """Return OpenVPN state if an active OpenVPN adapter is present.

    This uses the same adapter/IP checks as WireGuard, but is intentionally
    separated so the detector can be expanded for future protocols without
    changing the public API.
    """
    for adapter in adapters:
        name = str(adapter.get("Name", "")).strip()
        description = str(adapter.get("InterfaceDescription", "")).strip()
        status = str(adapter.get("Status", "")).strip().lower()
        media_state = normalize_media_state(adapter.get("MediaConnectionState"))
        combined = (name + " " + description).lower()

        if "openvpn" not in combined and not re.search(r"(tun|tap)[0-9]+", combined):
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

        return "openvpn", "Connected"

    return None


def check_vless_proxy():
    """Check whether the local v2rayN SOCKS/HTTP proxy is available on 127.0.0.1:10808."""
    try:
        with socket.create_connection(("127.0.0.1", 10808), timeout=1.0):
            return "vless", "Connected"
    except OSError:
        return None


def detect_protocol_state():
    """Detect the current active protocol or fall back to direct internet access."""
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

    checks = [
        lambda: check_wireguard_vpn(adapters, ip_addresses),
        lambda: check_openvpn_vpn(adapters, ip_addresses),
        lambda: check_vless_proxy(),
    ]

    for check in checks:
        result = check()
        if result is not None:
            return result

    return "direct", "Disconnected"


def detect_vpn_connection():
    """Backward-compatible generic wrapper returning (protocol, status)."""
    return detect_protocol_state()


def detect_wireguard_vpn():
    """Backward-compatible wrapper for the original WireGuard-only detection."""
    result = check_wireguard_vpn(
        run_powershell_json(
            "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MediaConnectionState | ConvertTo-Json -Depth 10"
        ),
        run_powershell_json(
            "Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, Type | ConvertTo-Json -Depth 10"
        ),
    )
    if result is None:
        return "direct", "Disconnected"
    return result


def print_results(host, metrics, protocol="None", vpn_status="Disconnected"):
    """Display the measured network quality in a readable format."""
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    latency_ms = parse_float_or_none(metrics.get("latency_ms"))
    packet_loss_pct = parse_float_or_none(metrics.get("packet_loss_pct"))
    jitter_ms = parse_float_or_none(metrics.get("jitter_ms"))

    print("\n" + "=" * 60)
    print("AdaptiveVPN-ML Network Quality Monitor")
    print("=" * 60)
    print(f"Timestamp: {timestamp}")
    print(f"Target host: {host}")
    print(f"VPN protocol: {protocol}")
    print(f"VPN status: {vpn_status}")
    print(f"Ping latency (average): {latency_ms:.2f} ms" if latency_ms is not None else "Ping latency (average): N/A")
    print(f"Packet loss: {packet_loss_pct:.2f}%" if packet_loss_pct is not None else "Packet loss: N/A")
    print(f"Jitter: {jitter_ms:.2f} ms" if jitter_ms is not None else "Jitter: N/A")
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
    latency_ms = parse_float_or_none(metrics.get("latency_ms"))
    packet_loss_pct = parse_float_or_none(metrics.get("packet_loss_pct"))
    jitter_ms = parse_float_or_none(metrics.get("jitter_ms"))

    if latency_ms is None or packet_loss_pct is None or jitter_ms is None:
        return None

    ensure_csv_header(csv_path)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    normalized_protocol = normalize_protocol_name(protocol)
    connection_label = get_connection_label(normalized_protocol, vpn_status)

    download_value = None if download_mbps in (None, "") else parse_float_or_none(download_mbps)
    upload_value = None if upload_mbps in (None, "") else parse_float_or_none(upload_mbps)

    row = [
        timestamp,
        host,
        normalized_protocol,
        vpn_status,
        connection_label,
        f"{latency_ms:.2f}",
        f"{packet_loss_pct:.2f}",
        f"{jitter_ms:.2f}",
        "" if download_value is None else f"{download_value:.2f}",
        "" if upload_value is None else f"{upload_value:.2f}",
    ]

    with open(csv_path, "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(row)

    return {
        "timestamp": timestamp,
        "target_host": host,
        "protocol": normalized_protocol,
        "vpn_status": vpn_status,
        "connection_label": connection_label,
        "latency_ms": latency_ms,
        "packet_loss_percent": packet_loss_pct,
        "jitter_ms": jitter_ms,
        "download_mbps": download_value,
        "upload_mbps": upload_value,
    }


def update_selector_from_row(row, csv_path=None, state_path=None):
    """Persist a completed observation into the UCB1 selector after CSV save."""
    if row is None:
        return False, None

    protocol = normalize_protocol_name(row.get("protocol"))
    if protocol not in adaptive_selector.ARMS:
        return False, None

    if csv_path is None:
        csv_path = os.path.join(os.path.dirname(__file__) or ".", "network_data.csv")
    if state_path is None:
        state_path = adaptive_selector.STATE_PATH

    current_signature = adaptive_selector.observation_signature(
        protocol,
        timestamp=row.get("timestamp"),
        host=row.get("target_host"),
        latency=row.get("latency_ms"),
        loss=row.get("packet_loss_percent"),
        jitter=row.get("jitter_ms"),
        download=row.get("download_mbps"),
        upload=row.get("upload_mbps"),
    )

    if not os.path.exists(state_path):
        adaptive_selector.train_from_dataset(csv_path, state_path, exclude_signature=current_signature)

    updated, reward = adaptive_selector.record_measurement_from_row(
        protocol=protocol,
        timestamp=row.get("timestamp"),
        host=row.get("target_host"),
        latency=row.get("latency_ms"),
        loss=row.get("packet_loss_percent"),
        jitter=row.get("jitter_ms"),
        download=row.get("download_mbps"),
        upload=row.get("upload_mbps"),
        state_path=state_path,
    )

    if updated:
        recommended_protocol, _, recommendation_text = adaptive_selector.recommend_protocol(csv_path, state_path)
        print("Measurement saved")
        print("Selector updated")
        print(f"Recommended protocol: {recommended_protocol}")
        print(recommendation_text)
        return True, (recommended_protocol, recommendation_text)

    print("Measurement saved")
    print("Selector already contains this observation; duplicate protected.")
    return False, None


def measure_throughput(protocol="auto"):
    """Measure throughput using speedtest-cli while honoring the active proxy path.

    When the active protocol is VLESS, the local v2rayN SOCKS proxy on
    127.0.0.1:10808 is used so the measurement traverses the configured proxy.
    For direct/VPN traffic, the system default route is used and no proxy env
    variables are injected.
    """
    normalized = str(protocol or "auto").strip().lower()
    if normalized == "auto":
        detected_protocol, _ = detect_protocol_state()
        normalized = str(detected_protocol or "direct").strip().lower()

    proxy_env = {}
    if normalized == "vless":
        try:
            with socket.create_connection(("127.0.0.1", 10808), timeout=1.5):
                proxy_env = {
                    "HTTP_PROXY": "socks5h://127.0.0.1:10808",
                    "HTTPS_PROXY": "socks5h://127.0.0.1:10808",
                    "ALL_PROXY": "socks5h://127.0.0.1:10808",
                    "NO_PROXY": "localhost,127.0.0.1",
                }
        except OSError:
            print(
                "Warning: VLESS proxy at 127.0.0.1:10808 is not available; throughput test skipped.",
                file=sys.stderr,
            )
            return None, None

    try:
        env = os.environ.copy()
        env.update(proxy_env)
        result = subprocess.run(
            [sys.executable, "-m", "speedtest", "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            env=env,
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
    parser.add_argument(
        "--protocol",
        default="auto",
        choices=["auto", "direct", "wireguard", "openvpn", "vless"],
        help="Override protocol detection and record a specific protocol label. Default: auto.",
    )
    args = parser.parse_args()

    if args.count <= 0:
        print("Error: --count must be greater than zero.", file=sys.stderr)
        return 1

    try:
        detected_protocol, detected_status = detect_protocol_state()
        if args.protocol == "auto":
            protocol, vpn_status = detected_protocol, detected_status
        else:
            normalized = str(args.protocol).strip().lower()
            if normalized == "direct":
                protocol, vpn_status = "direct", "Disconnected"
            else:
                protocol, vpn_status = normalized, "Connected"

        return_code, output = run_ping(args.host, args.count)
        metrics = parse_ping_output(output)

        if return_code not in (0, 1):
            print(f"Ping command failed with exit code {return_code}.", file=sys.stderr)
            print(output, file=sys.stderr)
            return return_code

        print_results(args.host, metrics, protocol, vpn_status)
        if output.strip():
            print("Ping output:\n" + output.strip())

        download_mbps = None
        upload_mbps = None
        if args.speed_test:
            download_mbps, upload_mbps = measure_throughput(protocol)
            if download_mbps is not None and upload_mbps is not None:
                print(f"Download throughput: {download_mbps:.2f} Mbps")
                print(f"Upload throughput: {upload_mbps:.2f} Mbps")

        csv_path = os.path.join(os.path.dirname(__file__) or ".", "network_data.csv")
        row = append_measurement(
            csv_path,
            args.host,
            metrics,
            protocol,
            vpn_status,
            download_mbps,
            upload_mbps,
        )

        if row is None:
            print("Measurement was incomplete or invalid and was not saved.", file=sys.stderr)
            return 1

        try:
            update_selector_from_row(row, csv_path=csv_path, state_path=adaptive_selector.STATE_PATH)
        except Exception as exc:  # pragma: no cover - defensive error handling.
            print(f"Warning: selector update failed after save: {exc}", file=sys.stderr)

        return 0

    except Exception as exc:  # pragma: no cover - defensive error handling.
        print(f"Error measuring network quality: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
