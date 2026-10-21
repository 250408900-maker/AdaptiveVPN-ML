import csv
import sys

from experiments import run_continuous_v4 as monitor


def test_continuous_monitor_handles_twelve_outages(monkeypatch, tmp_path):
    measurement = {
        "timestamp_utc": "2026-10-21T07:11:05+00:00",
        "tcp_connect_mean_ms": float("nan"),
        "tcp_connect_std_ms": float("nan"),
        "tcp_failure_pct": 100.0,
        "icmp_nonresponse_pct": 100.0,
        "interface_before": "laptop",
        "interface_after": "laptop",
        "route_stable": True,
        "vpn_path_verified": False,
    }

    calls = []

    def fake_measure_window(*args):
        calls.append(1)
        return measurement.copy()

    class FakeModel:
        def predict(self, frame):
            raise AssertionError("ML must be skipped during a full outage")

        def predict_proba(self, frame):
            raise AssertionError("ML must be skipped during a full outage")

    monkeypatch.setattr(monitor, "measure_window", fake_measure_window)
    monkeypatch.setattr(
        monitor.joblib,
        "load",
        lambda path: {
            "model": FakeModel(),
            "features": [
                "tcp_connect_mean_ms",
                "tcp_connect_std_ms",
                "tcp_failure_pct",
                "icmp_nonresponse_pct",
            ],
        },
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["monitor", "--windows", "12", "--seconds", "1", "--attempts", "5"],
    )

    monitor.main()

    files = list((tmp_path / "data/processed/live").glob("continuous_v4_*.csv"))
    assert len(files) == 1

    with files[0].open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(calls) == 12
    assert len(rows) == 12
    assert all(row["reachability"] == "PATH_UNREACHABLE" for row in rows)
    assert all(row["prediction"] == "NOT_EVALUATED" for row in rows)

    actions = [row["routing_action"] for row in rows]
    assert actions == (
        ["MONITOR", "MONITOR", "EVALUATE_ALTERNATIVES"]
        + ["MONITOR"] * 9
    )

    assert all(row["vpn_path_verified"] == "False" for row in rows)
