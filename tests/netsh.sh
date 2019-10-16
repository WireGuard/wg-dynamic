#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

set -e

exec 3>&1

[ $# -ge 1 ] && ( n_clients="$1"; shift; )

export WG_HIDE_KEYS=never
netnsn() { echo wg-test-$$-$1; }
pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
nn() { local netns=$(netnsn $1) n=$1; shift; pretty $n "$*"; maybe_exec ip netns exec $netns "$@"; }
ipn() { local netns=$(netnsn $1) n=$1; shift; pretty $n "ip $*"; ip -n $netns "$@"; }

ns="0 1 2"

cleanup() {
	set +e
	exec 2>/dev/null

	for n in $ns; do ipn $n link del dev wg0; done

	local to_kill="$(for n in $ns; do $(ip netns pids $(netnsn $n)); done)"
	[[ -n $to_kill ]] && kill $to_kill

	for n in $ns; do pp ip netns del $(netnsn $n); done

	exit
}

trap cleanup EXIT

pp ip netns add $(netnsn 0)
pp ip netns add $(netnsn 1)
pp ip netns add $(netnsn 2)
ipn 0 link set up dev lo

ipn 0 link add dev wg0 type wireguard
ipn 0 link set wg0 netns $(netnsn 1)
ipn 0 link add dev wg0 type wireguard
ipn 0 link set wg0 netns $(netnsn 2)
server_private=$(wg genkey)
server_public=$(wg pubkey <<< $server_private)
client_private=$(wg genkey)
client_public=$(wg pubkey <<< $client_private)

configure_peers() {
	ipn 1 addr add fe80::/64 dev wg0
	ipn 2 addr add fe80::badc:0ffe:e0dd:f00d/128 dev wg0

	nn 1 wg set wg0 \
		private-key <(echo $server_private) \
		listen-port 1 \
		peer $client_public \
			allowed-ips fe80::badc:0ffe:e0dd:f00d/128

	nn 2 wg set wg0 \
		private-key <(echo $client_private) \
		listen-port 2 \
		peer $server_public \
			allowed-ips 0.0.0.0/0,::/0

	ipn 1 link set up dev wg0
	ipn 2 link set up dev wg0

	ipn 2 route add fe80::/128 dev wg0
	ipn 1 route add 192.168.4.0/28 dev wg0
	ipn 1 route add 192.168.73.0/27 dev wg0
	ipn 1 route add 2001:db8:1234::/124 dev wg0
	ipn 1 route add 2001:db8:7777::/124 dev wg0
}
configure_peers

nn 1 wg set wg0 peer "$client_public" endpoint [::1]:2
nn 2 wg set wg0 peer "$server_public" endpoint [::1]:1
nn 2 ping6 -c 10 -f -W 1 fe80::%wg0
nn 1 ping6 -c 10 -f -W 1 fe80::badc:0ffe:e0dd:f00d%wg0

pretty "" "clientsh.bash can be run with the following arguments:"
echo
echo wg-test-$$ $server_public
echo

nn 1 gdb -ex r --args ./wg-dynamic-server --leasetime 10 wg0
