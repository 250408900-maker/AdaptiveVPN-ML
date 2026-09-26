"""
Canonical feature definition for AdaptiveVPN-ML.

This module defines the feature contract shared by:
- offline dataset generation
- model training
- future live monitoring / inference

IMPORTANT:
Training and live inference must use the same feature order.
"""

WINDOW_SECONDS = 10


FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "throughput_kbps",
    "flow_count",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "retransmissions",
    "retransmission_rate",
    "tcp_resets",
    "reset_rate",
    "avg_tcp_ack_rtt_ms",
]


METADATA_COLUMNS = [
    "window_start_s",
    "window_end_s",
]


TARGET_COLUMN = "label"


CSV_COLUMNS = (
    METADATA_COLUMNS
    + FEATURE_COLUMNS
    + [TARGET_COLUMN]
)


def validate_feature_row(row: dict) -> None:
    """
    Make sure a feature row contains every feature expected by the model.
    """

    missing = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in row
    ]

    if missing:
        raise ValueError(
            f"Missing features: {missing}"
        )


def model_vector(row: dict) -> list:
    """
    Convert a feature dictionary into the exact feature order
    expected by the ML model.
    """

    validate_feature_row(row)

    return [
        row[feature]
        for feature in FEATURE_COLUMNS
    ]


if __name__ == "__main__":

    print("AdaptiveVPN-ML feature contract")
    print("--------------------------------")
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print(f"ML features: {len(FEATURE_COLUMNS)}")

    for i, feature in enumerate(
        FEATURE_COLUMNS,
        start=1,
    ):
        print(f"{i:02d}. {feature}")

    print("\nFeature contract OK")