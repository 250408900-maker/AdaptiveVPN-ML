import csv
from pathlib import Path

from experiments.run_live_v4_pipeline import run_pipeline


def test_v4_pipeline_with_real_model(tmp_path):
    input_file = tmp_path / "input.csv"
    output_file = tmp_path / "output.csv"

    with input_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp_utc",
                "tcp_connect_mean_ms",
                "tcp_connect_std_ms",
                "tcp_failure_pct",
                "icmp_nonresponse_pct",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "timestamp_utc": "2026-10-21T06:00:00+00:00",
            "tcp_connect_mean_ms": 25,
            "tcp_connect_std_ms": 3,
            "tcp_failure_pct": 0,
            "icmp_nonresponse_pct": 0,
        })

    results = run_pipeline(input_file, output_file)

    assert len(results) == 1
    assert results[0]["prediction"] in {
        "NORMAL", "HIGH_LATENCY", "PACKET_LOSS"
    }
    assert results[0]["routing_action"] in {
        "KEEP", "MONITOR", "EVALUATE_ALTERNATIVES"
    }
    assert output_file.exists()
