
import argparse
import csv
import statistics
import subprocess
from datetime import datetime
from pathlib import Path
import json

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
WINDOW_SECONDS = 10
MIN_PACKETS = 20

FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.proto",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "tcp.analysis.retransmission",
    "tcp.flags.reset",
    "tcp.analysis.ack_rtt",
]


def number(value, default=None):
    try:
        return float(value) if value != "" else default
    except (ValueError, TypeError):
        return default


def integer(value, default=0):
    try:
        return int(value, 0)
    except (ValueError, TypeError):
        return default


def new_window():
    return {
        "packet_count": 0,
        "total_bytes": 0,
        "flows": set(),
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "retransmissions": 0,
        "tcp_resets": 0,
        "rtt_values": [],
    }


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8-sig")
    )

    capture_id = manifest["capture_id"]
    label = manifest["condition"].upper()

    pcap = Path(manifest["pcap_file"])
    raw_path = Path(manifest["probe_raw_file"])
    summary_path = Path(manifest["probe_summary_file"])

    for path in (pcap, raw_path, summary_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    origin = datetime.fromisoformat(
        manifest["probe_window_origin_utc"].replace(
            "Z", "+00:00"
        )
    ).timestamp()

    duration = int(
        manifest["requested_duration_seconds"]
    )

    if duration % WINDOW_SECONDS != 0:
        raise ValueError(
            "Duration must be divisible by 10 seconds."
        )

    total_windows = duration // WINDOW_SECONDS

    print(f"Capture: {capture_id}")
    print(f"Condition: {label}")
    print(f"Probe origin: {origin}")
    print("Reading PCAP using absolute timestamps...")

    command = [
        TSHARK,
        "-r", str(pcap),
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=f",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    windows = {
        i: new_window()
        for i in range(total_windows)
    }

    first_packet = None
    last_packet = None

    for line in result.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        parts = parts[:len(FIELDS)]

        (
            epoch, frame_len, proto, src, dst,
            tcp_src, tcp_dst, tcp_len,
            udp_src, udp_dst, retrans, reset, ack_rtt
        ) = parts

        timestamp = number(epoch)

        if timestamp is None:
            continue

        if first_packet is None:
            first_packet = timestamp

        last_packet = timestamp

        elapsed = timestamp - origin
        window_id = int(elapsed // WINDOW_SECONDS)

        if not (0 <= window_id < total_windows):
            continue

        w = windows[window_id]

        w["packet_count"] += 1
        w["total_bytes"] += integer(frame_len)

        protocol = integer(proto, -1)

        if protocol == 6:
            w["tcp_packets"] += 1
        elif protocol == 17:
            w["udp_packets"] += 1
        elif protocol == 1:
            w["icmp_packets"] += 1

        if src and dst:
            if tcp_src or tcp_dst:
                flow = (
                    src, dst, "TCP", tcp_src, tcp_dst
                )
            elif udp_src or udp_dst:
                flow = (
                    src, dst, "UDP", udp_src, udp_dst
                )
            else:
                flow = (
                    src, dst, str(proto), "", ""
                )

            w["flows"].add(flow)

        if retrans and integer(tcp_len) > 0:
            w["retransmissions"] += 1

        if integer(reset) == 1:
            w["tcp_resets"] += 1

        rtt = number(ack_rtt)

        if rtt is not None:
            w["rtt_values"].append(rtt * 1000)

    if first_packet is None:
        raise RuntimeError("No readable packets found.")

    raw_probes = read_csv(raw_path)
    summaries = read_csv(summary_path)

    if not raw_probes:
        raise RuntimeError("No active probes found.")

    # Verify the raw probe timestamps against
    # the origin recorded in the manifest.
    for probe in raw_probes:
        probe_time = datetime.fromisoformat(
            probe["timestamp_utc"].replace(
                "Z", "+00:00"
            )
        ).timestamp()

        elapsed = float(probe["elapsed_s"])

        if abs((probe_time - origin) - elapsed) > 2:
            raise RuntimeError(
                "Probe timestamps do not match origin."
            )

    summary_by_window = {
        int(float(row["window_start_s"])): row
        for row in summaries
    }

    rows = []

    for i in range(total_windows):
        start = i * WINDOW_SECONDS
        end = start + WINDOW_SECONDS

        absolute_start = origin + start
        absolute_end = origin + end

        # Conservative completeness check:
        # recorded packet range must span the window.
        if (
            first_packet > absolute_start
            or last_packet < absolute_end
        ):
            print(
                f"Skipping {start}-{end}s: "
                "incomplete packet coverage"
            )
            continue

        w = windows[i]

        if w["packet_count"] < MIN_PACKETS:
            print(
                f"Skipping {start}-{end}s: "
                "too few packets"
            )
            continue

        probe = summary_by_window.get(start)

        if probe is None:
            print(
                f"Skipping {start}-{end}s: "
                "missing probe summary"
            )
            continue

        tcp_count = w["tcp_packets"]

        retrans_rate = (
            w["retransmissions"] / tcp_count
            if tcp_count else 0.0
        )

        reset_rate = (
            w["tcp_resets"] / tcp_count
            if tcp_count else 0.0
        )

        rtts = w["rtt_values"]

        avg_rtt = (
            statistics.mean(rtts) if rtts else 0.0
        )

        std_rtt = (
            statistics.pstdev(rtts)
            if len(rtts) > 1 else 0.0
        )

        row = {
            "window_start_s": start,
            "window_end_s": end,

            "packet_count": w["packet_count"],
            "total_bytes": w["total_bytes"],
            "throughput_kbps": round(
                w["total_bytes"] * 8
                / WINDOW_SECONDS / 1000, 2
            ),
            "flow_count": len(w["flows"]),

            "tcp_packets": w["tcp_packets"],
            "udp_packets": w["udp_packets"],
            "icmp_packets": w["icmp_packets"],

            "retransmissions": w["retransmissions"],
            "retransmission_rate": round(
                retrans_rate, 5
            ),

            "tcp_resets": w["tcp_resets"],
            "reset_rate": round(reset_rate, 5),

            "avg_tcp_ack_rtt_ms": round(
                avg_rtt, 3
            ),
            "std_tcp_ack_rtt_ms": round(
                std_rtt, 3
            ),

            "probe_sent": integer(
                probe["probe_sent"]
            ),
            "icmp_received": integer(
                probe["icmp_received"]
            ),
            "icmp_status": probe["icmp_status"],
            "icmp_nonresponse_pct": number(
                probe["icmp_nonresponse_pct"]
            ),
            "icmp_rtt_mean_ms": number(
                probe["icmp_rtt_mean_ms"]
            ),

            "tcp_success_count": integer(
                probe["tcp_success_count"]
            ),
            "tcp_failure_pct": number(
                probe["tcp_failure_pct"]
            ),
            "tcp_connect_mean_ms": number(
                probe["tcp_connect_mean_ms"]
            ),
            "tcp_connect_std_ms": number(
                probe["tcp_connect_std_ms"]
            ),

            "label": label,
            "capture_file": capture_id,
        }

        rows.append(row)

    if not rows:
        raise RuntimeError(
            "No complete aligned windows found."
        )

    output_dir = Path("data/processed/v3")
    output_dir.mkdir(parents=True, exist_ok=True)

    output = output_dir / (
        f"{capture_id}_features.csv"
    )

    with output.open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f, fieldnames=list(rows[0])
        )
        writer.writeheader()
        writer.writerows(rows)

    print()
    print("V3 EXTRACTION COMPLETE")
    print(f"Aligned windows: {len(rows)}")
    print(f"Features saved: {output}")


if __name__ == "__main__":
    main()
