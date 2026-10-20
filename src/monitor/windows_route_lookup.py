import ipaddress
import json
import subprocess


def windows_route_lookup(destination):
    """Inspect the Windows-selected route. Does not send a probe."""
    try:
        ipaddress.ip_address(destination)
    except ValueError as exc:
        raise ValueError("Destination must be an IP address") from exc

    script = """
    $ErrorActionPreference = 'Stop'
    $route = Find-NetRoute -RemoteIPAddress '%s' |
        Select-Object -First 1

    if ($null -eq $route) {
        throw 'No route found'
    }

    $route | Select-Object InterfaceAlias, InterfaceIndex,
        NextHop, DestinationPrefix |
        ConvertTo-Json -Compress
    """ % destination

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Windows route lookup failed"
        )

    data = json.loads(result.stdout)

    return {
        "destination": destination,
        "interface": data["InterfaceAlias"],
        "interface_index": data["InterfaceIndex"],
        "next_hop": data["NextHop"],
        "destination_prefix": data["DestinationPrefix"],
        "verification_method": "os_route_lookup",
        "evidence_level": "route_selection_only",
    }
