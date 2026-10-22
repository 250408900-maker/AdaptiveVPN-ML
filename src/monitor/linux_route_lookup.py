import ipaddress
import json
import re
import subprocess


def inspect_linux_route(destination="1.1.1.1"):
    """Inspect Linux route selection; never verify VPN paths."""
    try:
        address = str(ipaddress.ip_address(destination))
    except ValueError:
        return {
            "status": "UNVERIFIED",
            "reason": "Destination must be a valid IP address",
            "vpn_path_verified": False,
            "switch_allowed": False,
        }

    try:
        result = subprocess.run(
            ["ip", "-j", "route", "get", address],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        routes = json.loads(result.stdout)
        route = routes[0] if routes else {}
        interface = route.get("dev")

        if not interface:
            raise ValueError("No selected interface returned")

        return {
            "status": "ROUTE_OBSERVED",
            "destination": address,
            "interface": interface,
            "gateway": route.get("gateway"),
            "source_ip": route.get("prefsrc"),
            "evidence_level": "route_selection_only",
            "vpn_path_verified": False,
            "switch_allowed": False,
        }
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        ValueError,
        IndexError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "status": "UNVERIFIED",
            "reason": str(exc),
            "vpn_path_verified": False,
            "switch_allowed": False,
        }
