from unittest.mock import patch
import json
import pytest

from src.monitor.windows_route_lookup import windows_route_lookup


def test_valid_windows_route():
    class Result:
        returncode = 0
        stderr = ""
        stdout = json.dumps({
            "InterfaceAlias": "Wi-Fi",
            "InterfaceIndex": 8,
            "NextHop": "192.168.1.1",
            "DestinationPrefix": "0.0.0.0/0",
        })

    with patch("src.monitor.windows_route_lookup.subprocess.run", return_value=Result()):
        result = windows_route_lookup("1.1.1.1")

    assert result["interface"] == "Wi-Fi"
    assert result["interface_index"] == 8
    assert result["evidence_level"] == "route_selection_only"


def test_rejects_invalid_destination():
    with pytest.raises(ValueError):
        windows_route_lookup("not-an-ip")


def test_rejects_failed_lookup():
    class Result:
        returncode = 1
        stderr = "Route lookup failed"
        stdout = ""

    with patch("src.monitor.windows_route_lookup.subprocess.run", return_value=Result()):
        with pytest.raises(RuntimeError):
            windows_route_lookup("1.1.1.1")
