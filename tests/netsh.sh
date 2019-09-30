#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

set -e

exec 3>&1
export WG_HIDE_KEYS=never
netns0="wg-test-$$-0"
netns1="wg-test-$$-1"
netns2="wg-test-$$-2"
pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
n0() { pretty 0 "$*"; maybe_exec ip netns exec $netns0 "$@"; }
n1() { pretty 1 "$*"; maybe_exec ip netns exec $netns1 "$@"; }
n2() { pretty 2 "$*"; maybe_exec ip netns exec $netns2 "$@"; }
ip0() { pretty 0 "ip $*"; ip -n $netns0 "$@"; }
ip1() { pretty 1 "ip $*"; ip -n $netns1 "$@"; }
ip2() { pretty 2 "ip $*"; ip -n $netns2 "$@"; }

cleanup() {
	set +e
	exec 2>/dev/null
	ip0 link del dev wg0
	ip1 link del dev wg0
	ip2 link del dev wg0
	local to_kill="$(ip netns pids $netns0) $(ip netns pids $netns1) $(ip netns pids $netns2)"
	[[ -n $to_kill ]] && kill $to_kill
	pp ip netns del $netns0
	pp ip netns del $netns1
	pp ip netns del $netns2
	exit
}

trap cleanup EXIT

ip netns del $netns0 2>/dev/null || true
ip netns del $netns1 2>/dev/null || true
ip netns del $netns2 2>/dev/null || true
pp ip netns add $netns0
pp ip netns add $netns1
pp ip netns add $netns2
ip0 link set up dev lo

ip0 link add dev wg0 type wireguard
ip0 link set wg0 netns $netns1
ip0 link add dev wg0 type wireguard
ip0 link set wg0 netns $netns2
server_private=$(wg genkey)
server_public=$(wg pubkey <<< $server_private)
client_private=$(wg genkey)
client_public=$(wg pubkey <<< $client_private)

configure_peers() {
	ip1 addr add fe80::/64 dev wg0
	ip2 addr add fe80::badc:0ffe:e0dd:f00d/128 dev wg0

	n1 wg set wg0 \
		private-key <(echo $server_private) \
		listen-port 1 \
		peer $client_public \
			allowed-ips fe80::badc:0ffe:e0dd:f00d/128

	n2 wg set wg0 \
		private-key <(echo $client_private) \
		listen-port 2 \
		peer $server_public \
			allowed-ips 0.0.0.0/0,::/0

	ip1 link set up dev wg0
	ip2 link set up dev wg0

	ip2 route add fe80::/128 dev wg0
	ip1 route add 192.168.4.0/28 dev wg0
	ip1 route add 192.168.73.0/27 dev wg0
	ip1 route add 2001:db8:1234::/124 dev wg0
	ip1 route add 2001:db8:7777::/124 dev wg0
}
configure_peers

n1 wg set wg0 peer "$client_public" endpoint [::1]:2
n2 wg set wg0 peer "$server_public" endpoint [::1]:1
n2 ping6 -c 10 -f -W 1 fe80::%wg0
n1 ping6 -c 10 -f -W 1 fe80::badc:0ffe:e0dd:f00d%wg0

n1 ./wg-dynamic-server --leasetime 10 wg0
