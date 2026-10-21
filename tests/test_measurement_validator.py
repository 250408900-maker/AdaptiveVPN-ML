import pytest

from src.monitor.measurement_validator import validate_window


def valid_row():
    return {
        "timestamp_utc": "2026-10-21T14:30:00+00:00",
        "tcp_attempts": 5,
        "tcp_connect_mean_ms": 15.0,
        "tcp_failure_pct": 0.0,
        "icmp_nonresponse_pct": 0.0,
    }


def test_valid_measurement():
    assert validate_window(valid_row()) == []


def test_valid_complete_outage():
    row = valid_row()
    row["tcp_connect_mean_ms"] = float("nan")
    row["tcp_failure_pct"] = 100.0
    assert validate_window(row) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("tcp_attempts", 0),
        ("tcp_connect_mean_ms", -5),
        ("tcp_failure_pct", 110),
        ("tcp_failure_pct", float("nan")),
        ("icmp_nonresponse_pct", -1),
        ("timestamp_utc", ""),
    ],
)
def test_invalid_measurements(field, value):
    row = valid_row()
    row[field] = value
    assert validate_window(row)
