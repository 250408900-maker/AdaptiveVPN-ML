#!/usr/bin/env bash
set -u

# Safe read-only OpenVPN diagnostic for Oracle Linux 9
# Purpose: identify why UDP 1194 traffic never reaches the OpenVPN server.
# This script MUST NOT change firewall, networking, OpenVPN, WireGuard, packages, or config.

# shellcheck disable=SC2015

LOG_PREFIX="[openvpn-diag]"

header() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

run_cmd() {
    local label="$1"
    shift
    echo
    echo "${LOG_PREFIX} $label"
    echo "Command: $*"
    if command -v "$1" >/dev/null 2>&1; then
        "$@" || true
    else
        echo "Command not found: $1"
    fi
}

# Basic environment
header "Environment"
run_cmd "Host" uname -a
run_cmd "Whoami" id
run_cmd "OS release" cat /etc/os-release 2>/dev/null || true
run_cmd "Kernel IP forwarding" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
run_cmd "sysctl IPv4 forwarding" sysctl net.ipv4.ip_forward 2>/dev/null || true

# OpenVPN service and config
header "OpenVPN service and config"
run_cmd "OpenVPN status" systemctl status openvpn-server@server --no-pager 2>&1 || true
run_cmd "OpenVPN logs" journalctl -u openvpn-server@server -n 200 --no-pager 2>&1 || true
run_cmd "OpenVPN server config" sed -n '1,220p' /etc/openvpn/server/server.conf 2>/dev/null || true
run_cmd "OpenVPN server dir listing" ls -l /etc/openvpn/server 2>/dev/null || true
run_cmd "OpenVPN unit file" systemctl cat openvpn-server@server 2>/dev/null || true

# Listening sockets / port checks
header "UDP 1194 and listening sockets"
run_cmd "ss UDP listeners" ss -lunp 2>/dev/null || true
run_cmd "netstat UDP listeners" netstat -lunp 2>/dev/null || true
run_cmd "lsof UDP 1194" lsof -nP -iUDP:1194 2>/dev/null || true
run_cmd "socat UDP check" timeout 5 sh -c 'echo >/dev/tcp/127.0.0.1/1194' 2>/dev/null || true

# Network interfaces and addresses
header "Interfaces and addressing"
run_cmd "ip addr" ip addr show 2>/dev/null || true
run_cmd "ip route" ip route show 2>/dev/null || true
run_cmd "ip route table main" ip route show table main 2>/dev/null || true
run_cmd "ip rule" ip rule show 2>/dev/null || true
run_cmd "hostname -I" hostname -I 2>/dev/null || true
run_cmd "interface stats" ip -s link show 2>/dev/null || true

# Oracle Linux / NetworkManager / ifcfg details
header "Oracle Linux networking details"
run_cmd "NetworkManager connections" nmcli -g GENERAL.CONNECTION,DEVICE,TYPE,STATE connection show 2>/dev/null || true
run_cmd "Network scripts" ls -l /etc/sysconfig/network-scripts 2>/dev/null || true
run_cmd "ifcfg files" grep -R "^\|DEVICE\|BOOTPROTO\|ONBOOT\|IPADDR\|PREFIX\|GATEWAY\|NM_CONTROLLED" /etc/sysconfig/network-scripts 2>/dev/null || true
run_cmd "NetworkManager status" systemctl status NetworkManager --no-pager 2>&1 || true
run_cmd "network-scripts files" find /etc/sysconfig/network-scripts -maxdepth 1 -type f -print 2>/dev/null | head -50 || true

# Routing and loopback checks
header "Routing and reachability"
run_cmd "Route to public IP" ip route get 130.61.28.42 2>/dev/null || true
run_cmd "Route to default gateway" ip route get 1.1.1.1 2>/dev/null || true
run_cmd "Ping default gateway" ping -c 2 -W 2 $(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}') 2>/dev/null || true
run_cmd "Ping local loopback" ping -c 2 -W 2 127.0.0.1 2>/dev/null || true
run_cmd "Trace to public IP" tracepath -n 130.61.28.42 2>/dev/null || true

# Firewalld and nftables
header "Firewall diagnostics"
run_cmd "firewalld status" systemctl status firewalld --no-pager 2>&1 || true
run_cmd "firewall-cmd default zone" firewall-cmd --get-default-zone 2>/dev/null || true
run_cmd "firewall-cmd active zones" firewall-cmd --get-active-zones 2>/dev/null || true
run_cmd "firewall-cmd list-all" firewall-cmd --list-all --zone=public 2>/dev/null || true
run_cmd "firewall-cmd list-all zones" firewall-cmd --list-all-zones 2>/dev/null || true
run_cmd "iptables rules" iptables -S 2>/dev/null || true
run_cmd "ip6tables rules" ip6tables -S 2>/dev/null || true
run_cmd "nft list ruleset" nft list ruleset 2>/dev/null || true
run_cmd "firewalld rich rules" firewall-cmd --info-rich-rules 2>/dev/null || true

# NAT / forwarding check
header "NAT and forwarding diagnostics"
run_cmd "iptables nat table" iptables -t nat -S 2>/dev/null || true
run_cmd "nft nat table" nft list table ip nat 2>/dev/null || true
run_cmd "route policy" ip route show table all 2>/dev/null || true
run_cmd "sysctl net.ipv4.conf.all.rp_filter" sysctl net.ipv4.conf.all.rp_filter 2>/dev/null || true
run_cmd "sysctl all forwarding confs" sysctl net.ipv4.conf.all.forwarding net.ipv4.conf.default.forwarding 2>/dev/null || true

# Packet capture availability / packet sanity
header "Packet capture and interface checks"
run_cmd "tcpdump version" tcpdump --version 2>/dev/null || true
run_cmd "tcpdump UDP 1194 capture on all interfaces" timeout 8 tcpdump -ni any 'udp port 1194' 2>/dev/null || true
run_cmd "ethtool on main interface" ethtool $(ip -o link show | awk -F': ' '{print $2}' | head -1) 2>/dev/null || true

# Oracle cloud / metadata specific path checks
header "Oracle cloud / metadata related checks"
run_cmd "oci metadata path" ls -ld /var/lib/cloud 2>/dev/null || true
run_cmd "check cloud-init net config" ls -l /etc/sysconfig/network-scripts 2>/dev/null || true
run_cmd "cloud-init status" cloud-init status --long 2>/dev/null || true
run_cmd "OCI interface hints" grep -R "oci\|oracle" /etc/sysconfig/network-scripts /etc/NetworkManager /etc/cloud 2>/dev/null || true

# WireGuard presence (read-only, no changes)
header "WireGuard presence (read-only)"
run_cmd "WireGuard status" wg show 2>/dev/null || true
run_cmd "WireGuard config files" ls -l /etc/wireguard 2>/dev/null || true
run_cmd "WireGuard interface list" ip link show 2>/dev/null | grep -i wireguard || true

# Manual checks for OpenVPN file paths
header "OpenVPN related file checks"
run_cmd "OpenVPN unit file" ls -l /usr/lib/systemd/system/openvpn-server@.service /usr/lib/systemd/system/openvpn-server@server.service 2>/dev/null || true
run_cmd "OpenVPN service file" grep -n "ExecStart\|Description\|User\|Group\|Capabilities\|PermissionsStartOnly" /usr/lib/systemd/system/openvpn-server@.service /usr/lib/systemd/system/openvpn-server@server.service 2>/dev/null || true
run_cmd "OpenVPN logs dir" ls -ld /var/log/openvpn* 2>/dev/null || true

# Summary and suggested fixes
header "Diagnostic summary"
echo "${LOG_PREFIX} Review the output above for the following likely causes:"
echo "  1) UDP 1194 is not bound to the correct interface/address or is not listening"
echo "  2) firewalld or nftables is dropping inbound UDP 1194 before it reaches OpenVPN"
echo "  3) Oracle Cloud security rules do not allow UDP 1194 to the VM"
echo "  4) interface route or public IP is wrong, or the VM is on a NAT/private network"
echo "  5) IPv4 forwarding is disabled or routed incorrectly"
echo "  6) OpenVPN is listening on the wrong address / wrong socket / wrong config"
echo "  7) the server is using a conflicting WireGuard or other VPN stack"
echo "  8) traffic is being filtered by a cloud firewall, host firewall, or network namespace"

echo
header "Suggested fixes to check later (read-only diagnosis only)"
echo "- Confirm the public interface is the correct NIC used by the VM and that the VM actually has the intended public IP."
echo "- Confirm the server config uses: port 1194 / proto udp / dev tun and the correct server subnet."
echo "- Verify the instance's Oracle Cloud NSG/security list allows UDP 1194 inbound from the client source or 0.0.0.0/0."
echo "- Check that firewalld and nftables are not dropping or rejecting UDP 1194 before it reaches OpenVPN."
echo "- Ensure IPv4 forwarding is enabled and the correct public interface is used for NAT/masquerading."
echo "- Confirm the VM is not behind a NAT / private IP-only path that does not expose UDP 1194 publicly."
echo "- Check if a different interface, VLAN, or cloud networking rule is intercepting traffic."
echo "- If the server is dual-stack, ensure the correct interface and route are used for UDP 1194."
echo "- If using Oracle Cloud, verify the VCN subnets and NSG rules and that the host OS actually sees the public IP."

echo
header "End of read-only diagnostic"

exit 0
