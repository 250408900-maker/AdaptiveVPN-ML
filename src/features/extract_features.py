import argparse
import csv
import subprocess
from collections import defaultdict
from pathlib import Path


WINDOW_SIZE = 10.0
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def main():
    # ---------------------------------------------------------
    # Command-line arguments
    # ---------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Extract window-based network features from a PCAPNG capture."
    )

    parser.add_argument(
        "pcap",
        type=Path,
        help="Path to the input PCAP/PCAPNG file",
    )

    parser.add_argument(
        "label",
        help="Network condition label, e.g. NORMAL or HIGH_LATENCY",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output CSV path",
    )

    args = parser.parse_args()

    PCAP = args.pcap
    LABEL = args.label.upper()

    OUTPUT = (
        args.output
        if args.output
        else Path("data/processed") / f"{PCAP.stem}_features.csv"
    )

    # ---------------------------------------------------------
    # Validate input
    # ---------------------------------------------------------
    if not PCAP.exists():
        raise FileNotFoundError(f"PCAP not found: {PCAP}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # Fields extracted from TShark
    # ---------------------------------------------------------
    fields = [
        "frame.time_relative",
        "frame.len",
        "ip.proto",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.analysis.retransmission",
        "tcp.flags.reset",
        "tcp.analysis.ack_rtt",
    ]

    command = [
        TSHARK,
        "-r",
        str(PCAP),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]

    for field in fields:
        command += ["-e", field]

    print(f"Reading {PCAP} ...")
    print(f"Label: {LABEL}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        check=True,
    )

    # ---------------------------------------------------------
    # Storage for 10-second windows
    # ---------------------------------------------------------
    windows = defaultdict(
        lambda: {
            "packet_count": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "retransmissions": 0,
            "tcp_resets": 0,
            "rtt_values": [],
            "flows": set(),
        }
    )

    # ---------------------------------------------------------
    # Process packets
    # ---------------------------------------------------------
    for line in result.stdout.splitlines():
        parts = line.split("\t")

        while len(parts) < len(fields):
            parts.append("")

        (
            time_relative,
            frame_len,
            ip_proto,
            ip_src,
            ip_dst,
            tcp_src,
            tcp_dst,
            udp_src,
            udp_dst,
            retransmission,
            reset,
            ack_rtt,
        ) = parts[: len(fields)]

        timestamp = safe_float(time_relative)
        length = safe_float(frame_len)

        if timestamp is None:
            continue

        window_id = int(timestamp // WINDOW_SIZE)
        w = windows[window_id]

        # Total packets
        w["packet_count"] += 1

        # Total bytes
        if length is not None:
            w["total_bytes"] += int(length)

        # -----------------------------------------------------
        # IP protocol numbers:
        # ICMP = 1
        # TCP  = 6
        # UDP  = 17
        # -----------------------------------------------------
        if ip_proto == "6":
            w["tcp_packets"] += 1

            if ip_src and ip_dst:
                flow = (
                    "TCP",
                    ip_src,
                    tcp_src,
                    ip_dst,
                    tcp_dst,
                )
                w["flows"].add(flow)

        elif ip_proto == "17":
            w["udp_packets"] += 1

            if ip_src and ip_dst:
                flow = (
                    "UDP",
                    ip_src,
                    udp_src,
                    ip_dst,
                    udp_dst,
                )
                w["flows"].add(flow)

        elif ip_proto == "1":
            w["icmp_packets"] += 1

        # TCP retransmissions
        if retransmission:
            w["retransmissions"] += 1

        # TCP resets
        if reset == "1":
            w["tcp_resets"] += 1

        # TCP ACK RTT
        rtt = safe_float(ack_rtt)

        if rtt is not None:
            # TShark reports seconds.
            # Convert to milliseconds.
            w["rtt_values"].append(rtt * 1000)

    # ---------------------------------------------------------
    # Convert windows into feature rows
    # ---------------------------------------------------------
    rows = []

    for window_id in sorted(windows):
        w = windows[window_id]

        avg_rtt = (
            sum(w["rtt_values"]) / len(w["rtt_values"])
            if w["rtt_values"]
            else 0
        )

        rows.append(
            {
                "window_start_s": window_id * WINDOW_SIZE,
                "window_end_s": (window_id + 1) * WINDOW_SIZE,
                "packet_count": w["packet_count"],
                "total_bytes": w["total_bytes"],
                "throughput_kbps": round(
                    (w["total_bytes"] * 8)
                    / WINDOW_SIZE
                    / 1000,
                    2,
                ),
                "flow_count": len(w["flows"]),
                "tcp_packets": w["tcp_packets"],
                "udp_packets": w["udp_packets"],
                "icmp_packets": w["icmp_packets"],
                "retransmissions": w["retransmissions"],
                "retransmission_rate": round(
                    w["retransmissions"]
                    / max(w["tcp_packets"], 1),
                    5,
                ),
                "tcp_resets": w["tcp_resets"],
                "reset_rate": round(
                    w["tcp_resets"]
                    / max(w["tcp_packets"], 1),
                    5,
                ),
                "avg_tcp_ack_rtt_ms": round(avg_rtt, 3),
                "label": LABEL,
            }
        )

    # ---------------------------------------------------------
    # Safety check
    # ---------------------------------------------------------
    if not rows:
        raise RuntimeError(
            f"No usable packets were extracted from {PCAP}"
        )

    # ---------------------------------------------------------
    # Save CSV
    # ---------------------------------------------------------
    fieldnames = list(rows[0].keys())

    with OUTPUT.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Created {len(rows)} windows")
    print(f"Saved -> {OUTPUT}")


if __name__ == "__main__":
    main()