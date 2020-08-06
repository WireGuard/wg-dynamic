#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

set -e

exec 3>&1
netnsprefix="wg-test-$$"
export WG_HIDE_KEYS=never
netnsn() { echo $netnsprefix-$1; }
pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
nn() {
    [[ "$1" != "-q" ]] && pretty $1 "$*" || shift
    local netns=$(netnsn $1); shift
    maybe_exec ip netns exec $netns "$@";
}
ipn() {
    [[ "$1" != "-q" ]] && pretty $1 "ip $*" || shift
    local netns=$(netnsn $1); shift
    ip -n $netns "$@";
}

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

### Server
ip netns del $(netnsn 0) 2>/dev/null || true
pp ip netns add $(netnsn 0)
ip netns del $(netnsn 1) 2>/dev/null || true
pp ip netns add $(netnsn 1)
ipn 0 link set up dev lo
ns="0 1"

ipn 0 link add dev wg0 type wireguard
ipn 0 link set wg0 netns $(netnsn 1)
server_private=$(wg genkey)
server_public=$(wg pubkey <<< $server_private)

ipn 1 addr add fe80::/64 dev wg0
nn 1 wg set wg0 \
   private-key <(echo $server_private) \
   listen-port 1
ipn 1 link set up dev wg0

# Add prefixes to pool.
ipn 1 route add 192.168.4.0/28 dev wg0
ipn 1 route add 192.168.73.0/27 dev wg0
ipn 1 route add 2001:db8:1234::/124 dev wg0
ipn 1 route add 2001:db8:7777::/124 dev wg0

# Start server.
nn 1 ./wg-dynamic-server --leasetime 10 wg0 &
sleep 1		      # FIXME: synchronise with server output instead?

### Clients
declare -a IPV4
declare -a IPV6
declare -a LEASESTART
declare -a LEASETIME
declare -a ERRNO

setup_client_peer() {
    local n=$1; shift
    ns+=" $n"

    ip netns del $(netnsn $n) 2>/dev/null || true
    pp ip netns add $(netnsn $n)
    ipn 0 link add dev wg0 type wireguard
    ipn 0 link set wg0 netns $(netnsn $n)

    privkey=$(wg genkey)
    pubkey=$(wg pubkey <<< $privkey)

    ipn $n addr add fe80::badc:0ffe:e0dd:$n/64 dev wg0
    nn $n wg set wg0 \
       private-key <(echo $privkey) \
       listen-port $n \
       peer $server_public \
       allowed-ips 0.0.0.0/0,::/0

    ipn $n link set up dev wg0
    ipn $n route add fe80::/128 dev wg0

    nn $n wg set wg0 peer "$server_public" endpoint [::1]:1
    nn 1 wg set wg0 peer "$pubkey" \
       allowed-ips fe80::badc:0ffe:e0dd:$n/128 \
       endpoint [::1]:$n

    nn $n ping6 -c 10 -f -W 1 fe80::%wg0 > /dev/null
    nn 1 ping6 -c 10 -f -W 1 fe80::badc:0ffe:e0dd:$n%wg0 > /dev/null
}

# check_alowedips(PUBKEY, IPV4, IPV6) verifies that IPV4 and IPV6
# are allowed on server. Empty argument means there must be no address
# for the given family, except the lladdr for v6.
check_alowedips() {
    local pubkey="$1"; shift
    local ipv4="$1"; shift
    local ipv6="$1"; shift

    local v4_found=
    local v6_found=
    while read -r _pubkey _ips; do
	[[ "$_pubkey" = "$pubkey" ]] || continue
	for _ip in $_ips; do
	    case $_ip in
		fe80:badc:ffe:e0dd:*)
		    continue ;;
		*:*)
		    [[ -n "$v6_found" ]] && { echo "bad allowedip: $_ip"; return 1; }
		    [[ "$ipv6" = "$_ip" ]] && v6_found=$_ip
		    continue ;;
		*)
		    [[ -n "$v4_found" ]] && { echo "bad allowedip: $_ip"; return 1; }
		    [[ "$ipv4" = "$_ip" ]] && v4_found=$_ip
		    continue ;;
	    esac
	done
    done < <(nn -q 1 wg show wg0 allowed-ips)

    [[ "$ipv4" != "$v4_found" ]] && { echo "missing allowedip: $ipv4"; return 1; }
    [[ "$ipv6" != "$v6_found" ]] && { echo "missing allowedip: $ipv6"; return 1; }

    return 0
}

send_cmd() {
    local n=$1; shift
    local REQ="$1"; shift

    # It would have been nice to use /dev/tcp/fe80::%w0/970 instead of
    # ncat, but we need to use a specific source port.
    while read -r line && [[ -n $line ]] ; do
	key="${line%%=*}"
	value="${line#*=}"
	case "$key" in
	    ip)
		if [[ "$value" =~ : ]]; then
		    IPV6[$n]="$value"
		else
		    IPV4[$n]="$value"
		fi
		continue ;;
	    leasestart) LEASESTART[$n]="$value"; continue ;;
	    leasetime) LEASETIME[$n]="$value"; continue ;;
	    errno) ERRNO[$n]="$value"; continue ;;
	esac
    done < <(printf $REQ | nn -q $n ncat -p 970 fe80::%wg0 970 2>/dev/null)
}

# req(N, IPV4, IPV6) sends a request for client N, asking for IPV4 and
# IPv6. An empty string or "-" results in a request for releasing an
# address rather than allocating one. NOTE: Asking for 0.0.0.0 or ::0
# means asking for any address in the pool.
req() {
    local n=$1; shift
    local ipv4_req=
    [ $# -gt 0 ] && [ -n "$1" ] && { ipv4_req="ip=$1\n"; shift; }
    [ "$ipv4_req" = "ip=-\n" ] && ipv4_req=
    local ipv6_req=
    [ $# -gt 0 ] && [ -n "$1" ] && { ipv6_req="ip=$1\n"; shift; }
    [ "$ipv6_req" = "ip=-\n" ] && ipv6_req=

    IPV4[$n]=
    IPV6[$n]=
    LEASESTART[$n]=
    LEASETIME[$n]=
    ERRNO[$n]=

    REQ="request_ip=1\n${ipv4_req}${ipv6_req}\n"
    send_cmd $n "$REQ"
}

req_check() {
    local n=$1

    req $*

    pubkey=$(nn -q $n wg show wg0 public-key)
    check_alowedips "$pubkey" "${IPV4[$n]}" "${IPV6[$n]}"
}

fail() {
    echo "FAIL \"$1\""
    exit 1
}

test_case_1() {
    # One client -- 3.
    setup_client_peer 3

    pretty 3 "Badly formed request => errno=1 -- EXPECTED FAILURE: errno=2"
    send_cmd 3 "ip_request=\n\n"
    [[ ${ERRNO[3]} = 2 ]] || fail "errno: ${ERRNO[3]} != 2"

    pretty 3 "Request addresses not in the pool"
    req 3 "1.1.1.1" "fd00::1"
    [[ ${ERRNO[3]} = 3 ]] || fail "errno: ${ERRNO[3]} != 3"
    [[ -z ${IPV4[3]} ]] || fail "ipv4 not empty: ${IPV4[3]}"
    [[ -z ${IPV6[3]} ]] || fail "ipv6 not empty: ${IPV6[3]}"

    pretty "" "SUCCESS\n"
}

test_case_2() {
    # Two clients -- 4 and 5.
    for i in 4 5; do setup_client_peer $i; done

    pretty 4 "Any v4, any v6"
    req_check 4 0.0.0.0 ::
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    local C4_FIRST_V4=${IPV4[4]}
    [[ -z $C4_FIRST_V4 ]] && fail "no ipv4"
    local C4_FIRST_V6=${IPV6[4]}
    [[ -z $C4_FIRST_V6 ]] && fail "no ipv6"

    pretty 4 "Extend v4, extend v6"
    req_check 4 $C4_FIRST_V4 $C4_FIRST_V6
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    [[ ${IPV4[4]} = $C4_FIRST_V4 ]] || fail "${IPV4[4]} != $C4_FIRST_V4"
    [[ ${IPV6[4]} = $C4_FIRST_V6 ]] || fail "${IPV6[4]} != $C4_FIRST_V6"

    pretty 4 "Extend v4, drop v6"
    req_check 4 $C4_FIRST_V4 -
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    [[ ${IPV4[4]} = $C4_FIRST_V4  ]] || fail "${IPV4[4]} != $C4_FIRST_V4"
    [[ -z ${IPV6[4]} ]] || fail "ipv6 not empty: ${IPV6[4]}"

    pretty 5 "Requesting the v4 of client 4 and no v6 => errno=3 and no addrs"
    req 5 $C4_FIRST_V4 -
    [[ ${ERRNO[5]} = 3 ]] || fail "errno: ${ERRNO[5]} != 3"
    [[ -z ${IPV4[5]} ]] || fail "ipv4 not empty: ${IPV4[5]}"
    [[ -z ${IPV6[5]} ]] || fail "ipv6 not empty: ${IPV6[5]}"

    pretty 5 "Wait for lease to expire and try again"
    pp sleep ${LEASETIME[4]}
    req_check 5 $C4_FIRST_V4 -
    [[ ${ERRNO[5]} = 0 ]] || fail "errno: ${ERRNO[5]}"
    [[ ${IPV4[5]} = $C4_FIRST_V4  ]] || fail "${IPV4[5]} != $C4_FIRST_V4"
    [[ -z ${IPV6[5]} ]] || fail "ipv6 not empty: ${IPV6[5]}"

    pretty "" "SUCCESS\n"
}

test_case_3() {
    # Two clients -- 6 and 7.
    for i in 6 7; do setup_client_peer $i; done

    pretty 6 "Any v4, any v6"
    req_check 6 0.0.0.0 ::
    [[ ${ERRNO[6]} = 0 ]] || fail "errno: ${ERRNO[6]}"
    local C6_FIRST_V4=${IPV4[6]}
    [[ -z $C6_FIRST_V4 ]] && fail "no ipv4"
    local C6_FIRST_V6=${IPV6[6]}
    [[ -z $C6_FIRST_V6 ]] && fail "no ipv6"

    pretty 6 "Drop v4, extend v6"
    req_check 6 - $C6_FIRST_V6
    [[ ${ERRNO[6]} = 0 ]] || fail "errno: ${ERRNO[6]}"
    [[ -z ${IPV4[6]} ]] || fail "ipv4 not empty: ${IPV4[6]}"
    [[ ${IPV6[6]} = $C6_FIRST_V6 ]] || fail "${IPV6[6]} != $C6_FIRST_V6"

    pretty "" "SUCCESS\n"
}

# run_k_at_random(NCLIENTS, K) is invoked by test_forever() and runs
# req_check() for a random number of clients (the up to K first
# ones). The check performed is one of nine possible combinations of
# requesting a specific address (ipv4 and ipv6), requesting any type
# of address and releasing one or both addresses allocated.
run_k_at_random() {
    local nclients=$1; shift
    local k=$1; shift
    local n=10			# First client.
    local i

    if [[ $nclients -gt $k ]]; then
	n=$(( $n + $RANDOM % ($n - $k) ))
    fi

    for i in $(seq $n $(( $n + $k - 1 ))); do
	case $(( $RANDOM % 9 )) in
	    0) req_check $i 0.0.0.0     ::0         ; continue ;; # any v4, any v6
	    1) req_check $i 0.0.0.0     -           ; continue ;; # any v4, drop v6
	    2) req_check $i -           ::0         ; continue ;; # drop v4, any v6
	    3) req_check $i -           -           ; continue ;; # drop v4, drop v6

	    4) req_check $i ${IPV4[$i]} ::0         ; continue ;; # extend v4, any v6
	    5) req_check $i ${IPV4[$i]} -           ; continue ;; # extend v4, drop v6
	    6) req_check $i 0.0.0.0     ${IPV6[$i]} ; continue ;; # any v4, extend v6
	    7) req_check $i -           ${IPV6[$i]} ; continue ;; # drop v4, extend v6

	    8) req_check $i ${IPV4[$i]} ${IPV6[$i]} ; continue ;; # extend v4, extend v6
	esac
    done
}

# run_k_fill(NCLIENTS, _ignored) is invoked by test_forever() and runs
# req_check() for NCLIENTS, asking for any IPv4 and any IPv6 address.
run_k_fill() {
    local nclients=$1; shift
    shift
    local i

    for i in $(seq $nclients); do
	req_check $(( 10 + $i - 1 )) 0.0.0.0 ::0
    done
}

# test_forever(NCLIENTS, FUNC, ARG) sets up NCLIENTS clients, numbered
# from 10 and upwards, runs one req_check() per client and enters an
# infinite loop invoking FUNC with NCLIENTS and ARGS.
test_forever() {
    local nclients=$1; shift
    local func=$1; shift
    local arg=$1; shift
    local i

    for i in $(seq 10 $(( 10 + $nclients - 1 ))); do
	setup_client_peer $i
    done

    for i in $(seq 10 $(( 10 + $nclients - 1 ))); do
	req_check $i
    done

    while sleep 1; do
	if [ $(( $RANDOM % 100 )) -lt 50 ]; then
	    $func $nclients $arg
	fi
    done
}

### Tests.

# Ordinary test cases.
test_case_1
test_case_2
test_case_3

# Long running test cases, forever actually.
[ $# -gt 0 ] && { NCLIENTS=$1; shift; } || NCLIENTS=20
[ $# -gt 0 ] && { ARGS=$1; shift; } || ARGS=4
#test_forever $NCLIENTS run_k_at_random $ARGS
#test_forever $NCLIENTS run_k_fill $ARGS
