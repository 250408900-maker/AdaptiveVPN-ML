from pathlib import Path
from datetime import datetime
import argparse
import csv
import re
import subprocess
import sys


# ============================================================
# AdaptiveVPN-ML Experiment Runner
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CAPTURE_ROOT = PROJECT_ROOT / "data" / "captures"
METADATA_FILE = PROJECT_ROOT / "data" / "metadata.csv"

EXTRACTOR = (
    PROJECT_ROOT
    / "src"
    / "features"
    / "extract_features.py"
)

TSHARK = Path(
    r"C:\Program Files\Wireshark\tshark.exe"
)

DEFAULT_INTERFACE = "5"
DEFAULT_DURATION = 60

VALID_LABELS = {
    "NORMAL",
    "HIGH_LATENCY",
    "HIGH_JITTER",
    "PACKET_LOSS",
    "ROUTE_FAILURE",
}

VALID_SEVERITIES = {
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
}

VALID_TRAFFIC_TYPES = {
    "BROWSING",
    "STREAMING",
    "DOWNLOAD",
    "MIXED",
    "IDLE",
}

METADATA_FIELDS = [
    "capture_id",
    "label",
    "severity",
    "traffic_type",
    "timestamp",
    "duration_s",
    "interface",
    "latency_ms",
    "jitter_ms",
    "packet_loss_pct",
    "pcap_path",
]


# ============================================================
# Capture ID
# ============================================================

def get_next_capture_id(label: str) -> str:

    folder_name = label.lower()

    capture_dir = (
        CAPTURE_ROOT
        / folder_name
    )

    capture_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    pattern = re.compile(
        rf"^{re.escape(folder_name)}_(\d+)\.pcapng$",
        re.IGNORECASE,
    )

    numbers = []

    for file in capture_dir.glob("*.pcapng"):

        match = pattern.match(file.name)

        if match:
            numbers.append(
                int(match.group(1))
            )

    next_number = (
        max(numbers) + 1
        if numbers
        else 1
    )

    return (
        f"{folder_name}_{next_number:03d}"
    )


# ============================================================
# Metadata migration
# ============================================================

def ensure_metadata_schema():

    if not METADATA_FILE.exists():
        return

    with METADATA_FILE.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(file)

        old_fields = reader.fieldnames or []

        rows = list(reader)

    if old_fields == METADATA_FIELDS:
        return

    print()
    print("Upgrading metadata schema...")

    upgraded_rows = []

    for row in rows:

        upgraded = {
            field: row.get(field, "")
            for field in METADATA_FIELDS
        }

        # Existing experiments were collected
        # before detailed metadata was introduced.
        upgraded_rows.append(upgraded)

    with METADATA_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=METADATA_FIELDS,
        )

        writer.writeheader()
        writer.writerows(upgraded_rows)

    print("Metadata schema upgraded.")


# ============================================================
# Save metadata
# ============================================================

def save_metadata(
    capture_id: str,
    label: str,
    severity: str,
    traffic_type: str,
    duration: int,
    interface: str,
    latency_ms: float,
    jitter_ms: float,
    packet_loss_pct: float,
    pcap_path: Path,
):

    METADATA_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    ensure_metadata_schema()

    file_exists = METADATA_FILE.exists()

    with METADATA_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=METADATA_FIELDS,
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(
            {
                "capture_id": capture_id,
                "label": label,
                "severity": severity,
                "traffic_type": traffic_type,
                "timestamp": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "duration_s": duration,
                "interface": interface,
                "latency_ms": latency_ms,
                "jitter_ms": jitter_ms,
                "packet_loss_pct": packet_loss_pct,
                "pcap_path": str(
                    pcap_path.relative_to(
                        PROJECT_ROOT
                    )
                ),
            }
        )


# ============================================================
# Validate experiment settings
# ============================================================

def validate_settings(args, label):

    if args.duration <= 0:
        raise ValueError(
            "Duration must be greater than 0."
        )

    if args.latency_ms < 0:
        raise ValueError(
            "Latency cannot be negative."
        )

    if args.jitter_ms < 0:
        raise ValueError(
            "Jitter cannot be negative."
        )

    if not 0 <= args.packet_loss_pct <= 100:
        raise ValueError(
            "Packet loss must be between 0 and 100."
        )

    if label == "NORMAL":

        if (
            args.latency_ms != 0
            or args.jitter_ms != 0
            or args.packet_loss_pct != 0
        ):
            raise ValueError(
                "NORMAL captures must have zero "
                "impairment values."
            )


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run one AdaptiveVPN-ML "
            "network experiment."
        )
    )

    parser.add_argument(
        "label",
        type=str,
        help=(
            "NORMAL, HIGH_LATENCY, HIGH_JITTER, "
            "PACKET_LOSS, or ROUTE_FAILURE"
        ),
    )

    parser.add_argument(
        "--severity",
        type=str,
        default="MEDIUM",
        help="NONE, LOW, MEDIUM, or HIGH",
    )

    parser.add_argument(
        "--traffic-type",
        type=str,
        default="BROWSING",
        help=(
            "BROWSING, STREAMING, DOWNLOAD, "
            "MIXED, or IDLE"
        ),
    )

    parser.add_argument(
        "--latency-ms",
        type=float,
        default=0,
    )

    parser.add_argument(
        "--jitter-ms",
        type=float,
        default=0,
    )

    parser.add_argument(
        "--packet-loss-pct",
        type=float,
        default=0,
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
    )

    parser.add_argument(
        "--interface",
        type=str,
        default=DEFAULT_INTERFACE,
    )

    args = parser.parse_args()

    label = args.label.upper()
    severity = args.severity.upper()
    traffic_type = args.traffic_type.upper()

    if label not in VALID_LABELS:

        raise ValueError(
            f"Invalid label: {label}"
        )

    if severity not in VALID_SEVERITIES:

        raise ValueError(
            f"Invalid severity: {severity}"
        )

    if traffic_type not in VALID_TRAFFIC_TYPES:

        raise ValueError(
            f"Invalid traffic type: {traffic_type}"
        )

    if label == "NORMAL":
        severity = "NONE"

    validate_settings(
        args,
        label,
    )

    if not TSHARK.exists():

        raise FileNotFoundError(
            f"TShark not found:\n{TSHARK}"
        )

    if not EXTRACTOR.exists():

        raise FileNotFoundError(
            f"Feature extractor not found:\n"
            f"{EXTRACTOR}"
        )

    ensure_metadata_schema()

    capture_id = get_next_capture_id(
        label
    )

    capture_dir = (
        CAPTURE_ROOT
        / label.lower()
    )

    pcap_path = (
        capture_dir
        / f"{capture_id}.pcapng"
    )

    # --------------------------------------------------------
    # Experiment summary
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("ADAPTIVEVPN-ML CONTROLLED EXPERIMENT")
    print("=" * 60)

    print(f"Capture ID:       {capture_id}")
    print(f"Label:            {label}")
    print(f"Severity:         {severity}")
    print(f"Traffic type:     {traffic_type}")
    print(f"Duration:         {args.duration} sec")
    print(f"Interface:        {args.interface}")
    print(f"Latency:          {args.latency_ms} ms")
    print(f"Jitter:           {args.jitter_ms} ms")
    print(
        f"Packet loss:      "
        f"{args.packet_loss_pct}%"
    )

    print()
    print(
        "IMPORTANT: the values above describe the "
        "condition you configured."
    )

    print(
        "Make sure Clumsy matches these settings "
        "before continuing."
    )

    print()

    input(
        "Press ENTER when the network condition "
        "is ready..."
    )

    # --------------------------------------------------------
    # Capture
    # --------------------------------------------------------

    print()
    print(
        f"Capturing for {args.duration} seconds..."
    )

    command = [
        str(TSHARK),
        "-i",
        args.interface,
        "-a",
        f"duration:{args.duration}",
        "-w",
        str(pcap_path),
    ]

    try:

        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
        )

    except KeyboardInterrupt:

        print("\nCapture cancelled.")
        sys.exit(1)

    if result.returncode != 0:

        print(
            "\nERROR: TShark capture failed."
        )

        sys.exit(
            result.returncode
        )

    if not pcap_path.exists():

        raise RuntimeError(
            "Capture completed but PCAP "
            "was not created."
        )

    size_bytes = (
        pcap_path.stat().st_size
    )

    print()
    print("Capture complete.")

    print(
        f"PCAP size: "
        f"{size_bytes:,} bytes"
    )

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("EXTRACTING FEATURES")
    print("=" * 60)
    print()

    extract_command = [
        sys.executable,
        str(EXTRACTOR),
        str(pcap_path),
        label,
    ]

    result = subprocess.run(
        extract_command,
        cwd=PROJECT_ROOT,
    )

    if result.returncode != 0:

        print()
        print(
            "ERROR: Feature extraction failed."
        )

        print(
            "PCAP preserved for debugging."
        )

        sys.exit(
            result.returncode
        )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    save_metadata(
        capture_id=capture_id,
        label=label,
        severity=severity,
        traffic_type=traffic_type,
        duration=args.duration,
        interface=args.interface,
        latency_ms=args.latency_ms,
        jitter_ms=args.jitter_ms,
        packet_loss_pct=args.packet_loss_pct,
        pcap_path=pcap_path,
    )

    # --------------------------------------------------------
    # Finished
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("EXPERIMENT COMPLETE")
    print("=" * 60)

    print(f"Capture:      {capture_id}")
    print(f"Label:        {label}")
    print(f"Severity:     {severity}")
    print(f"Traffic:      {traffic_type}")

    print(
        f"PCAP:         "
        f"{pcap_path.relative_to(PROJECT_ROOT)}"
    )

    print(
        f"Metadata:     "
        f"{METADATA_FILE.relative_to(PROJECT_ROOT)}"
    )

    print()
    print(
        "Capture + features + experimental "
        "metadata completed successfully."
    )


if __name__ == "__main__":
    main()