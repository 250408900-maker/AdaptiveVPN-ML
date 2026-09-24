import argparse
import csv
import subprocess
from collections import defaultdict
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# Each ML sample represents 10 seconds of network traffic.
WINDOW_SIZE = 10.0

# Our captures are intentionally 60 seconds long.
# This is important for ROUTE_FAILURE because TShark may see
# absolutely no packets during part of an outage.
CAPTURE_DURATION = 60.0

# Tiny windows are normally ignored.
# ROUTE_FAILURE is an exception because zero/low traffic itself
# can be the useful signal.
MIN_PACKETS_PER_WINDOW = 20


# ============================================================
# HELPERS
# ============================================================

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def safe_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def make_window():
    """
    Create an empty 10-second feature window.
    """

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


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # COMMAND-LINE ARGUMENTS
    # --------------------------------------------------------

    parser = argparse.ArgumentParser(
        description="Extract ML network features from a PCAP/PCAPNG file."
    )

    parser.add_argument(
        "pcap",
        help="Path to PCAP or PCAPNG capture",
    )

    parser.add_argument(
        "label",
        help="Traffic condition label, e.g. NORMAL or HIGH_LATENCY",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Optional custom output CSV path",
    )

    # These options allow us to keep only the portion where a
    # temporary condition was actually active.
    #
    # Example:
    #
    # --active-start 30 --active-end 60
    #
    # means:
    # keep 30-40, 40-50 and 50-60 second windows.

    parser.add_argument(
        "--active-start",
        type=float,
        default=None,
        help="Keep windows starting at or after this second",
    )

    parser.add_argument(
        "--active-end",
        type=float,
        default=None,
        help="Keep windows ending at or before this second",
    )

    args = parser.parse_args()

    pcap = Path(args.pcap)
    label = args.label.upper()

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not pcap.exists():
        raise FileNotFoundError(
            f"PCAP not found: {pcap}"
        )

    if not Path(TSHARK).exists():
        raise FileNotFoundError(
            f"TShark not found: {TSHARK}"
        )

    # --------------------------------------------------------
    # OUTPUT PATH
    # --------------------------------------------------------

    if args.output:

        output = Path(args.output)

    else:

        output = (
            Path("data")
            / "processed"
            / f"{pcap.stem}_features.csv"
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(f"Reading {pcap} ...")
    print(f"Label: {label}")

    # --------------------------------------------------------
    # TSHARK FIELDS
    # --------------------------------------------------------

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
        str(pcap),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]

    for field in fields:
        command.extend(
            ["-e", field]
        )

    # --------------------------------------------------------
    # RUN TSHARK
    # --------------------------------------------------------

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:

        raise RuntimeError(
            "TShark failed:\n"
            + result.stderr
        )

    # --------------------------------------------------------
    # CREATE ALL SIX WINDOWS FIRST
    # --------------------------------------------------------
    #
    # THIS IS THE IMPORTANT FIX.
    #
    # We know the capture lasts 60 seconds.
    #
    # Therefore:
    #
    # 0-10
    # 10-20
    # 20-30
    # 30-40
    # 40-50
    # 50-60
    #
    # are created BEFORE reading packets.
    #
    # If Wi-Fi disappears completely during one of these
    # periods, that window remains present with zeros.
    # --------------------------------------------------------

    total_windows = int(
        CAPTURE_DURATION / WINDOW_SIZE
    )

    windows = {
        window_id: make_window()
        for window_id in range(total_windows)
    }

    packet_seen = False

    # --------------------------------------------------------
    # PARSE PACKETS
    # --------------------------------------------------------

    for line in result.stdout.splitlines():

        parts = line.split("\t")

        # Ensure we always have enough columns.
        while len(parts) < len(fields):
            parts.append("")

        (
            time_relative,
            frame_len,
            ip_proto,
            ip_src,
            ip_dst,
            tcp_srcport,
            tcp_dstport,
            udp_srcport,
            udp_dstport,
            retransmission,
            tcp_reset,
            ack_rtt,
        ) = parts[:len(fields)]

        timestamp = safe_float(
            time_relative
        )

        if timestamp is None:
            continue

        packet_seen = True

        # ----------------------------------------------------
        # FIND WINDOW
        # ----------------------------------------------------

        window_id = int(
            timestamp // WINDOW_SIZE
        )

        # Ignore anything outside the expected 60 seconds.
        if window_id < 0:
            continue

        if window_id >= total_windows:
            continue

        w = windows[window_id]

        # ----------------------------------------------------
        # PACKET COUNT
        # ----------------------------------------------------

        w["packet_count"] += 1

        # ----------------------------------------------------
        # TOTAL BYTES
        # ----------------------------------------------------

        length = safe_int(
            frame_len
        )

        if length is not None:
            w["total_bytes"] += length

        # ----------------------------------------------------
        # PROTOCOL COUNTS
        # ----------------------------------------------------

        proto = safe_int(
            ip_proto
        )

        # TCP
        if proto == 6:

            w["tcp_packets"] += 1

        # UDP
        elif proto == 17:

            w["udp_packets"] += 1

        # ICMP
        elif proto == 1:

            w["icmp_packets"] += 1

        # ----------------------------------------------------
        # FLOW COUNT
        # ----------------------------------------------------

        if ip_src and ip_dst:

            # TCP flow
            if tcp_srcport or tcp_dstport:

                flow = (
                    ip_src,
                    ip_dst,
                    "TCP",
                    tcp_srcport,
                    tcp_dstport,
                )

                w["flows"].add(flow)

            # UDP flow
            elif udp_srcport or udp_dstport:

                flow = (
                    ip_src,
                    ip_dst,
                    "UDP",
                    udp_srcport,
                    udp_dstport,
                )

                w["flows"].add(flow)

            # Other IP protocol
            else:

                flow = (
                    ip_src,
                    ip_dst,
                    str(ip_proto),
                    "",
                    "",
                )

                w["flows"].add(flow)

        # ----------------------------------------------------
        # RETRANSMISSIONS
        # ----------------------------------------------------

        if retransmission:

            w["retransmissions"] += 1

        # ----------------------------------------------------
        # TCP RESET
        # ----------------------------------------------------

        if tcp_reset:

            try:

                if int(
                    tcp_reset,
                    0
                ) == 1:

                    w["tcp_resets"] += 1

            except ValueError:

                pass

        # ----------------------------------------------------
        # ACK RTT
        # ----------------------------------------------------

        rtt = safe_float(
            ack_rtt
        )

        if rtt is not None:

            # TShark gives ACK RTT in seconds.
            # Convert to milliseconds.

            w["rtt_values"].append(
                rtt * 1000
            )

    # --------------------------------------------------------
    # SAFETY CHECK
    # --------------------------------------------------------

    if not packet_seen:

        raise RuntimeError(
            f"No usable packets were extracted from {pcap}"
        )

    # --------------------------------------------------------
    # CONVERT WINDOWS TO ML FEATURE ROWS
    # --------------------------------------------------------

    rows = []

    for window_id in sorted(
        windows.keys()
    ):

        w = windows[window_id]

        window_start = (
            window_id
            * WINDOW_SIZE
        )

        window_end = (
            (window_id + 1)
            * WINDOW_SIZE
        )

        # ----------------------------------------------------
        # OPTIONAL ACTIVE INTERVAL
        # ----------------------------------------------------

        if args.active_start is not None:

            if (
                window_start
                < args.active_start
            ):

                continue

        if args.active_end is not None:

            if (
                window_end
                > args.active_end
            ):

                continue

        # ----------------------------------------------------
        # REMOVE TINY WINDOWS FOR ORDINARY CONDITIONS
        # ----------------------------------------------------
        #
        # Do NOT do this for ROUTE_FAILURE.
        #
        # A route failure can legitimately produce:
        #
        # packet_count = 0
        # total_bytes = 0
        # throughput = 0
        # flow_count = 0
        #
        # Those zeros are useful ML information.
        # ----------------------------------------------------

        if (
            label != "ROUTE_FAILURE"
            and
            w["packet_count"]
            < MIN_PACKETS_PER_WINDOW
        ):

            continue

        # ----------------------------------------------------
        # RETRANSMISSION RATE
        # ----------------------------------------------------

        if w["tcp_packets"] > 0:

            retransmission_rate = (
                w["retransmissions"]
                / w["tcp_packets"]
            )

            reset_rate = (
                w["tcp_resets"]
                / w["tcp_packets"]
            )

        else:

            retransmission_rate = 0.0
            reset_rate = 0.0

        # ----------------------------------------------------
        # AVERAGE RTT
        # ----------------------------------------------------

        if w["rtt_values"]:

            avg_rtt = (
                sum(
                    w["rtt_values"]
                )
                / len(
                    w["rtt_values"]
                )
            )

        else:

            avg_rtt = 0.0

        # ----------------------------------------------------
        # THROUGHPUT
        # ----------------------------------------------------

        throughput_kbps = (
            (
                w["total_bytes"]
                * 8
            )
            / WINDOW_SIZE
            / 1000
        )

        # ----------------------------------------------------
        # FINAL FEATURE ROW
        # ----------------------------------------------------

        row = {

            "window_start_s":
                round(
                    window_start,
                    2
                ),

            "window_end_s":
                round(
                    window_end,
                    2
                ),

            "packet_count":
                w["packet_count"],

            "total_bytes":
                w["total_bytes"],

            "throughput_kbps":
                round(
                    throughput_kbps,
                    2
                ),

            "flow_count":
                len(
                    w["flows"]
                ),

            "tcp_packets":
                w["tcp_packets"],

            "udp_packets":
                w["udp_packets"],

            "icmp_packets":
                w["icmp_packets"],

            "retransmissions":
                w["retransmissions"],

            "retransmission_rate":
                round(
                    retransmission_rate,
                    5
                ),

            "tcp_resets":
                w["tcp_resets"],

            "reset_rate":
                round(
                    reset_rate,
                    5
                ),

            "avg_tcp_ack_rtt_ms":
                round(
                    avg_rtt,
                    3
                ),

            "label":
                label,
        }

        rows.append(row)

    # --------------------------------------------------------
    # CHECK RESULT
    # --------------------------------------------------------

    if not rows:

        raise RuntimeError(
            "No feature windows remained after filtering."
        )

    # --------------------------------------------------------
    # SAVE CSV
    # --------------------------------------------------------

    fieldnames = list(
        rows[0].keys()
    )

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            rows
        )

    # --------------------------------------------------------
    # FINISHED
    # --------------------------------------------------------

    print(
        f"Created {len(rows)} windows"
    )

    print(
        f"Saved -> {output}"
    )


if __name__ == "__main__":
    main()