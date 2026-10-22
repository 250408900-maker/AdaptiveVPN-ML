import csv

import pytest

from experiments.compare_observed_paths import summarize


FIELDS = [
    "tcp_attempts",
    "tcp_failure_pct",
    "tcp_connect_mean_ms",
    "interface_before",
]


def make_csv(tmp_path, rows):
    path = tmp_path / "measurements.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_healthy_path(tmp_path):
    path = make_csv(tmp_path, [
        {
            "tcp_attempts": 5,
            "tcp_failure_pct": 0,
            "tcp_connect_mean_ms": 10,
            "interface_before": "eth0",
        },
        {
            "tcp_attempts": 5,
            "tcp_failure_pct": 0,
            "tcp_connect_mean_ms": 20,
            "interface_before": "eth0",
        },
    ])
    result = summarize(path, "WSL2")
    assert result["tcp_successes"] == 10
    assert result["tcp_failures"] == 0
    assert result["mean_window_latency_ms"] == 15
    assert result["interfaces"] == ["eth0"]


def test_complete_outage_has_no_latency(tmp_path):
    path = make_csv(tmp_path, [{
        "tcp_attempts": 5,
        "tcp_failure_pct": 100,
        "tcp_connect_mean_ms": "nan",
        "interface_before": "laptop",
    }])
    result = summarize(path, "WIREGUARD_SELECTED")
    assert result["tcp_failures"] == 5
    assert result["tcp_successes"] == 0
    assert result["mean_window_latency_ms"] is None


def test_empty_dataset_rejected(tmp_path):
    path = make_csv(tmp_path, [])
    with pytest.raises(ValueError, match="Empty dataset"):
        summarize(path, "EMPTY")
