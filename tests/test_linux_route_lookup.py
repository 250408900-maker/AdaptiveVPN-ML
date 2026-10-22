import json
import subprocess
from unittest.mock import patch, Mock

from src.monitor.linux_route_lookup import inspect_linux_route


def test_valid_linux_route():
    result = Mock(
        stdout=json.dumps([{
            "dst": "1.1.1.1",
            "dev": "eth0",
            "gateway": "192.168.64.1",
            "prefsrc": "192.168.65.137",
        }])
    )

    with patch("subprocess.run", return_value=result):
        route = inspect_linux_route("1.1.1.1")

    assert route["status"] == "ROUTE_OBSERVED"
    assert route["interface"] == "eth0"
    assert route["vpn_path_verified"] is False
    assert route["switch_allowed"] is False


def test_invalid_destination():
    route = inspect_linux_route("not-an-ip")

    assert route["status"] == "UNVERIFIED"
    assert route["switch_allowed"] is False


def test_missing_linux_command():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        route = inspect_linux_route("1.1.1.1")

    assert route["status"] == "UNVERIFIED"
    assert route["vpn_path_verified"] is False


def test_missing_interface():
    result = Mock(stdout=json.dumps([{"dst": "1.1.1.1"}]))

    with patch("subprocess.run", return_value=result):
        route = inspect_linux_route("1.1.1.1")

    assert route["status"] == "UNVERIFIED"
