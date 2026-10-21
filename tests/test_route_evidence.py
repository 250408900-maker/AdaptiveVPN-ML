from unittest.mock import patch

from src.monitor.route_evidence import inspect_current_route


def test_route_observation_does_not_verify_vpn():
    with patch(
        "src.monitor.route_evidence.windows_route_lookup",
        return_value={
            "interface": "Wi-Fi",
            "interface_index": 8,
        },
    ):
        result = inspect_current_route()

    assert result["status"] == "ROUTE_OBSERVED"
    assert result["vpn_path_verified"] is False
    assert result["switch_allowed"] is False


def test_missing_interface_is_unverified():
    with patch(
        "src.monitor.route_evidence.windows_route_lookup",
        return_value={"interface": None},
    ):
        result = inspect_current_route()

    assert result["status"] == "UNVERIFIED"
    assert result["switch_allowed"] is False


def test_lookup_failure_is_unverified():
    with patch(
        "src.monitor.route_evidence.windows_route_lookup",
        side_effect=RuntimeError("No route found"),
    ):
        result = inspect_current_route()

    assert result["status"] == "UNVERIFIED"
    assert result["vpn_path_verified"] is False
    assert result["switch_allowed"] is False
