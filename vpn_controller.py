import ctypes
import socket
import sys
from pathlib import Path
import subprocess



VLESS_PROXY_HOST = "127.0.0.1"
VLESS_PROXY_PORT = 10808


def is_vless_available(timeout=1.5):
    """Return True if the local v2rayN SOCKS/mixed proxy is reachable."""
    try:
        with socket.create_connection(
            (VLESS_PROXY_HOST, VLESS_PROXY_PORT),
            timeout=timeout,
        ):
            return True
    except OSError:
        return False


def activate_protocol(protocol):
    """
    Prepare or verify the requested protocol.

    For VLESS, v2rayN is currently managed externally and this controller
    verifies that its local proxy is available before considering it active.
    """
    protocol = str(protocol).strip().lower()

    if protocol == "vless":
        if is_vless_available():
            return True, "VLESS proxy is active and ready."
        return False, (
            "VLESS was recommended, but v2rayN proxy 127.0.0.1:10808 "
            "is not available."
        )

    if protocol == "wireguard":
        executable = Path(r"C:\Program Files\WireGuard\wireguard.exe")
        config = Path.home() / "Downloads" / "laptop.conf"

        if not executable.exists():
            return False, "WireGuard was not found."

        if not config.exists():
            return False, f"WireGuard configuration was not found: {config}"

        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(executable),
            f'/installtunnelservice "{config}"',
            None,
            1,
        )

        if result <= 32:
            return False, f"WireGuard activation failed with code {result}."

        return True, (
            "WireGuard activation requested. Approve the Windows "
            "administrator prompt to start the laptop tunnel."
        )

    if protocol == "openvpn":
        executable = Path(
            r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe"
        )
        profile = Path(
            str(Path.home() / "Downloads" / "client1-tcp.ovpn")
        )
        profile_name = "AdaptiveVPN-ML"

        if not executable.exists():
            return False, "OpenVPN Connect was not found."

        if not profile.exists():
            return False, f"OpenVPN profile was not found: {profile}"

        profiles = subprocess.run(
            [str(executable), "--list-profiles"],
            capture_output=True,
            text=True,
        )

        if profile_name.lower() not in profiles.stdout.lower():
            imported = subprocess.run(
                [
                    str(executable),
                    f"--import-profile={profile}",
                    f"--name={profile_name}",
                ],
                capture_output=True,
                text=True,
            )

            if imported.returncode != 0:
                message = imported.stderr or imported.stdout
                return False, f"Profile import failed: {message.strip()}"

        subprocess.Popen([str(executable)])
        return True, (
            "OpenVPN Connect opened with the AdaptiveVPN-ML profile. "
            "Press Connect inside OpenVPN Connect to confirm."
        )

def main():
    if len(sys.argv) != 2:
        print("Usage: python vpn_controller.py <protocol>")
        return 1

    success, message = activate_protocol(sys.argv[1])
    print(message)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
