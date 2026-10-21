from src.monitor.windows_route_lookup import windows_route_lookup


def inspect_current_route(destination="1.1.1.1"):
    """Read-only route inspection, not proof of VPN tunnel traffic."""
    try:
        result = windows_route_lookup(destination)
    except (RuntimeError, ValueError, KeyError, TypeError) as exc:
        return {
            "status": "UNVERIFIED",
            "reason": str(exc),
            "vpn_path_verified": False,
            "switch_allowed": False,
        }

    if not result.get("interface"):
        return {
            "status": "UNVERIFIED",
            "reason": "No selected interface found",
            "vpn_path_verified": False,
            "switch_allowed": False,
        }

    return {
        "status": "ROUTE_OBSERVED",
        "interface": result["interface"],
        "interface_index": result.get("interface_index"),
        "destination": destination,
        "evidence_level": "route_selection_only",
        "vpn_path_verified": False,
        "switch_allowed": False,
    }
