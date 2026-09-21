#!/usr/bin/env bash
# Builds a victim with a full-tunnel "VPN" (wg-quick style policy routing) and a rogue DHCP server
# that pushes TunnelVision option 121 routes, then shows detection, mitigation and re-enforcement.
set -euo pipefail
cd /opt/tvv
V="ip netns exec victim"
A="ip netns exec attacker"
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Creating attacker/victim namespaces"
ip netns add attacker; ip netns add victim
ip link add veth-a type veth peer name veth-v
ip link set veth-a netns attacker; ip link set veth-v netns victim
$A ip addr add 192.168.66.1/24 dev veth-a; $A ip link set veth-a up; $A ip link set lo up
$V ip link set veth-v up; $V ip link set lo up

step "Victim connects a full-tunnel VPN (tun0, wg-quick style policy routing)"
$V ip tuntap add dev tun0 mode tun
$V ip addr add 10.8.0.2/24 dev tun0
$V ip link set tun0 up
$V ip route add default dev tun0 table 51820
$V ip rule add not fwmark 51820 table 51820 priority 32765
$V ip rule add table main suppress_prefixlength 0 priority 32764

step "Attacker starts a rogue DHCP server that pushes option 121: 0.0.0.0/1 and 128.0.0.0/1 via itself"
$A dnsmasq --no-daemon --port=0 --interface=veth-a --bind-interfaces \
  --dhcp-range=192.168.66.100,192.168.66.150,255.255.255.0,2m \
  --dhcp-option=3,192.168.66.1 \
  --dhcp-option=121,0.0.0.0/1,192.168.66.1,128.0.0.0/1,192.168.66.1,0.0.0.0/0,192.168.66.1 \
  --dhcp-leasefile=/tmp/dnsmasq.leases --log-dhcp >/tmp/dnsmasq.log 2>&1 &
sleep 1

step "Victim gets a lease from the rogue server"
$V dhclient -v -1 -lf /var/lib/dhcp/dhclient.leases veth-v 2>&1 | grep -E "DHCPACK|bound" || true
$V ip route show table all | grep -v "table local"

step "Where does traffic to 1.1.1.1 go? (should be tun0; TunnelVision makes it veth-v)"
$V ip route get 1.1.1.1

step "tvv check (expect CRITICAL findings, exit code 1)"
set +e; $V python3 -m tunnelvisionvision check; echo "exit code: $?"; set -e

step "Running the daemon with auto_action=mitigate to demonstrate the response path"
echo '{"auto_action":"mitigate","auto_action_delay":0,"poll_interval":2,"api_port":47121}' > /tmp/tvv.json
$V python3 -m tunnelvisionvision --config /tmp/tvv.json daemon >/tmp/tvv.log 2>&1 &
sleep 6
$V ip route get 1.1.1.1
$V python3 -m tunnelvisionvision --config /tmp/tvv.json status || true

step "DHCP renewal re-pushes the routes; the daemon removes them again"
$V dhclient -v -1 -lf /var/lib/dhcp/dhclient.leases veth-v 2>&1 | grep -E "DHCPACK|bound" || true
sleep 5
$V ip route show | grep -E "^(0|128)\.0\.0\.0/1" && echo "rogue routes still present" || echo "rogue routes removed (enforcement working)"
$V ip route get 1.1.1.1

step "Daemon log"
cat /tmp/tvv.log
