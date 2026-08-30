#!/usr/bin/env bash
set -euo pipefail

# Oracle Linux 9 OpenVPN routing/NAT repair script
# Safe and minimal: backup configs, apply only the rules needed for traffic
# from 10.8.0.0/24 to reach the internet via enp0s6 while preserving:
# - WireGuard wg0 and its configuration
# - Docker networking and bridges
# - Existing OpenVPN config and firewalld state outside the targeted fix
#
# This script intentionally avoids flushing nftables, resetting firewalld,
# removing Docker networks, or modifying WireGuard.

TUN_IF="tun0"
OUT_IF="enp0s6"
VPN_NET="10.8.0.0/24"

BACKUP_DIR="/root/openvpn-routing-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "[openvpn-fix] Backing up config/state to $BACKUP_DIR"
cp -a /etc/openvpn/server/server.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/firewalld/firewalld.conf "$BACKUP_DIR/" 2>/dev/null || true
for f in /etc/firewalld/zones/*.xml; do
    [ -f "$f" ] && cp -a "$f" "$BACKUP_DIR/" 2>/dev/null || true
done
nft list ruleset > "$BACKUP_DIR/nftables.ruleset" 2>/dev/null || true
firewall-cmd --runtime-to-permanent >/dev/null 2>&1 || true

ensure_firewalld() {
    if ! systemctl is-enabled firewalld >/dev/null 2>&1; then
        systemctl enable firewalld >/dev/null 2>&1 || true
    fi
    if ! systemctl is-active --quiet firewalld; then
        systemctl start firewalld >/dev/null 2>&1 || true
    fi
}

check_pass_fail() {
    local label="$1"
    local result="$2"
    if [ "$result" = "PASS" ]; then
        echo "PASS: $label"
    else
        echo "FAIL: $label"
    fi
}

rule_exists() {
    local table="$1"
    local chain="$2"
    local rule="$3"
    firewall-cmd --direct --query-rule "$table" "$chain" "$rule" 2>/dev/null | grep -q 'yes'
}

add_direct_rule_once() {
    local table="$1"
    local chain="$2"
    local priority="$3"
    local rule="$4"

    if ! rule_exists "$table" "$chain" "$priority $rule"; then
        firewall-cmd --permanent --direct --add-rule "$table" "$chain" "$priority" $rule
    fi
}

# Main validation / preflight
echo "[openvpn-fix] Verifying environment"
if [ $(id -u) -ne 0 ]; then
    echo "ERROR: run this script as root."
    exit 1
fi

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $1"
        exit 1
    }
}

require_cmd ip
require_cmd firewall-cmd
require_cmd nft
require_cmd systemctl

ensure_firewalld

# Collect existing state before changes
OPENVPN_ACTIVE="FAIL"
if systemctl is-active --quiet openvpn-server@server; then
    OPENVPN_ACTIVE="PASS"
fi
check_pass_fail "OpenVPN service" "$OPENVPN_ACTIVE"

if ip link show "$TUN_IF" >/dev/null 2>&1; then
    echo "PASS: tun0 exists"
else
    echo "FAIL: tun0 does not exist"
fi

if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" = "1" ]; then
    echo "PASS: IPv4 forwarding enabled"
else
    echo "FAIL: IPv4 forwarding disabled"
fi

if ip route show dev "$OUT_IF" 2>/dev/null | grep -q "default"; then
    echo "PASS: outbound interface $OUT_IF has a default route"
else
    echo "FAIL: outbound interface $OUT_IF does not have a default route"
fi

if ip route show 2>/dev/null | grep -q "${VPN_NET} dev ${TUN_IF}"; then
    echo "PASS: OpenVPN route for $VPN_NET via $TUN_IF exists"
else
    echo "FAIL: route for $VPN_NET via $TUN_IF missing"
fi

if firewall-cmd --zone=public --query-interface="$OUT_IF" >/dev/null 2>&1; then
    echo "PASS: $OUT_IF is in firewalld public zone"
else
    echo "FAIL: $OUT_IF is not in firewalld public zone"
fi

if firewall-cmd --zone=trusted --query-interface="$TUN_IF" >/dev/null 2>&1; then
    echo "PASS: $TUN_IF is in firewalld trusted zone"
else
    echo "FAIL: $TUN_IF is not in firewalld trusted zone"
fi

# Apply minimal routing/NAT fix only if required.
# The intent is to allow traffic from 10.8.0.0/24 to be forwarded to enp0s6,
# NATed there, and allow return traffic from enp0s6 back to tun0.

# Add tun0 to trusted zone if missing
if ! firewall-cmd --zone=trusted --query-interface="$TUN_IF" >/dev/null 2>&1; then
    firewall-cmd --permanent --zone=trusted --add-interface="$TUN_IF" >/dev/null 2>&1 || true
fi
if ! firewall-cmd --zone=trusted --query-source="$VPN_NET" >/dev/null 2>&1; then
    firewall-cmd --permanent --zone=trusted --add-source="$VPN_NET" >/dev/null 2>&1 || true
fi

# Direct rules: minimal and explicit, while leaving all other nftables rules alone.
# These allow forward from tun0 to enp0s6 and return traffic from enp0s6 to tun0.
add_direct_rule_once ipv4 filter FORWARD 0 "-i $TUN_IF -o $OUT_IF -j ACCEPT"
add_direct_rule_once ipv4 filter FORWARD 0 "-i $OUT_IF -o $TUN_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
add_direct_rule_once ipv4 nat POSTROUTING 0 "-s $VPN_NET -o $OUT_IF -j MASQUERADE"

# Make sure the public zone allows forwarding as needed.
firewall-cmd --permanent --zone=public --set-target=ACCEPT >/dev/null 2>&1 || true
firewall-cmd --permanent --zone=trusted --set-target=ACCEPT >/dev/null 2>&1 || true

# Reload firewalld, but do not flush rulesets.
firewall-cmd --reload >/dev/null 2>&1 || true

# Verify the repair
echo
echo "[openvpn-fix] Verifying rules after repair"

# OpenVPN service
if systemctl is-active --quiet openvpn-server@server; then
    check_pass_fail "OpenVPN service" "PASS"
else
    check_pass_fail "OpenVPN service" "FAIL"
fi

# tun0
if ip link show "$TUN_IF" >/dev/null 2>&1; then
    check_pass_fail "tun0" "PASS"
else
    check_pass_fail "tun0" "FAIL"
fi

# IPv4 forwarding
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" = "1" ]; then
    check_pass_fail "IPv4 forwarding" "PASS"
else
    check_pass_fail "IPv4 forwarding" "FAIL"
fi

# Outbound interface
if ip route show dev "$OUT_IF" 2>/dev/null | grep -q "default"; then
    check_pass_fail "outbound interface" "PASS"
else
    check_pass_fail "outbound interface" "FAIL"
fi

# Forwarding rules
FORWARD_OK="FAIL"
if firewall-cmd --direct --query-rule ipv4 filter FORWARD 0 "-i $TUN_IF -o $OUT_IF -j ACCEPT" 2>/dev/null | grep -q 'yes'; then
    if firewall-cmd --direct --query-rule ipv4 filter FORWARD 0 "-i $OUT_IF -o $TUN_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" 2>/dev/null | grep -q 'yes'; then
        FORWARD_OK="PASS"
    fi
fi
check_pass_fail "forwarding rules" "$FORWARD_OK"

# NAT/masquerade
NAT_OK="FAIL"
if firewall-cmd --direct --query-rule ipv4 nat POSTROUTING 0 "-s $VPN_NET -o $OUT_IF -j MASQUERADE" 2>/dev/null | grep -q 'yes'; then
    NAT_OK="PASS"
fi
check_pass_fail "NAT/masquerade" "$NAT_OK"

# Show resulting rules
echo
echo "[openvpn-fix] Current route summary"
ip route show 2>/dev/null | grep -E "default|${VPN_NET}|${TUN_IF}|${OUT_IF}" || true

echo
echo "[openvpn-fix] Current direct firewall rules"
firewall-cmd --direct --get-all-rules 2>/dev/null | grep -E 'FORWARD|POSTROUTING|MASQUERADE|tun0|enp0s6' || true

echo
echo "[openvpn-fix] Current nftables ruleset (top-level)"
(nft list ruleset 2>/dev/null || true) | grep -E 'inet|table|chain|tun0|enp0s6|10\.8\.0\.0/24|MASQUERADE|RELATED|ESTABLISHED' || true

echo
echo "[openvpn-fix] Rollback commands"
cat <<EOF
# Restore from the backup directory created at:
# $BACKUP_DIR
#
# To restore the previous OpenVPN config:
#   cp -a "$BACKUP_DIR/server.conf" /etc/openvpn/server/server.conf
#
# To restore firewalld config from backup XML files:
#   cp -a "$BACKUP_DIR"/*.xml /etc/firewalld/zones/
#
# To restore nftables ruleset:
#   nft -f "$BACKUP_DIR/nftables.ruleset"
#
# Direct rule removal (minimum rollback):
firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 "-i $TUN_IF -o $OUT_IF -j ACCEPT" || true
firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 "-i $OUT_IF -o $TUN_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" || true
firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 "-s $VPN_NET -o $OUT_IF -j MASQUERADE" || true
#
# Optional zone cleanup if added:
firewall-cmd --permanent --zone=trusted --remove-interface=$TUN_IF || true
firewall-cmd --permanent --zone=trusted --remove-source=$VPN_NET || true
#
# A clean reload after rollback:
firewall-cmd --reload || true
EOF

echo
echo "[openvpn-fix] Script complete."

echo "Important: this script intentionally does not flush nftables, reset firewalld, disable WireGuard, or alter Docker networking."

echo "If OpenVPN still has no internet after this, inspect the actual client route, DNS, and whether the client is using the tunnel as default gateway."
