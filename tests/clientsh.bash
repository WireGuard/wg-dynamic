#! /bin/bash

set -e

exec 3>&1

DEBUG=1
netnsprefix="$1"; shift		# wg-test-$PID
server_public="$1"; shift

netnsn() { echo $netnsprefix-$1; }
pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
nn() {
    [[ "$1" != "-q" ]] && pretty $n "$*" || shift
    local netns=$(netnsn $1) n=$1; shift;
    maybe_exec ip netns exec $netns "$@";
}
ipn() {
    [[ "$1" != "-q" ]] && pretty $n "ip $*" || shift
    local netns=$(netnsn $1) n=$1; shift;
    ip -n $netns "$@";
}

ns=

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

setup_client_peer() {
    local n=$1; shift
    ns+=" $n"

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

    nn $n ping6 -c 10 -f -W 1 fe80::%wg0
    nn 1 ping6 -c 10 -f -W 1 fe80::badc:0ffe:e0dd:$n%wg0
}

# Positive check -- verify that $1 is allowed on server.
check_alowedips() {
    local n="$1"; shift
    local pubkey="$1"; shift
    local ip="$1"; shift

    [[ -z "$ip" ]] && return 0

    nn -q 1 wg show wg0 allowed-ips |
	while read -r _pubkey _ips; do
	    [[ "$_pubkey" = "$pubkey" ]] || continue
	    for _ip in $_ips; do
		[[ "$_ip" = "$ip" ]] && return 0
	    done
	done && return 0

    pretty $n "Missing $ip in allowedips"
    return 1
}

declare -a IPV4
declare -a IPV6
declare -a LEASESTART
declare -a LEASETIME
declare -a ERRNO

send_cmd() {
    local n=$1; shift
    local REQ="$1"; shift

    # - It would have been nice to use /dev/tcp/fe80::%w0/970 instead
    # of nc, but we need to use a specific source port.
    eval $(
	printf $REQ | nn -q $n ncat -p 970 fe80::%wg0 970 |
	    while read -r line; do
		key="${line%%=*}"
		value="${line#*=}"
		case "$key" in
		    ipv4) echo IPV4[$n]="$value"; continue ;;
		    ipv6) echo IPV6[$n]="$value"; continue ;;
		    leasestart) echo LEASESTART[$n]="$value"; continue ;;
		    leasetime) echo LEASETIME[$n]="$value"; continue ;;
		    errno) echo ERRNO[$n]="$value"; continue ;;
		esac
	    done
	)
}

req() {
    local n=$1; shift
    local ipv4_req=
    [ $# -gt 0 ] && [ -n "$1" ] && { ipv4_req="ipv4=$1\n"; shift; }
    [ "$ipv4_req" = "ipv4=-\n" ] && ipv4_req="ipv4=\n"
    local ipv6_req=
    [ $# -gt 0 ] && [ -n "$1" ] && { ipv6_req="ipv6=$1\n"; shift; }
    [ "$ipv6_req" = "ipv6=-\n" ] && ipv6_req="ipv6=\n"

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
    check_alowedips $n "$pubkey" "${IPV4[$n]}"
    check_alowedips $n "$pubkey" "${IPV6[$n]}"
}

run_k_at_random() {
    local NCLIENTS=$1; shift
    local k=$1; shift
    local n=10
    local i

    if [[ $NCLIENTS -gt $k ]]; then
	n=$(( 10 + $RANDOM % ($NCLIENTS - $k) ))
    fi

    for i in $(seq $n $(( $n + $k - 1))); do
	case $(( $RANDOM % 9 )) in
	    0) req_check $i ""          ""          ; continue ;;
	    1) req_check $i ""          "-"         ; continue ;;
	    2) req_check $i "-"         ""          ; continue ;;
	    3) req_check $i "-"         "-"         ; continue ;;

	    4) req_check $i ${IPV4[$i]} ""          ; continue ;;
	    5) req_check $i ${IPV4[$i]} "-"         ; continue ;;
	    6) req_check $i ""          ${IPV6[$i]} ; continue ;;
	    7) req_check $i "-"         ${IPV6[$i]} ; continue ;;

	    8) req_check $i ${IPV4[$i]} ${IPV6[$i]} ; continue;;
	esac
    done
}

test_random() {
    local NCLIENTS=$1; shift
    local n

    for n in $(seq 10 $(( 9+$NCLIENTS ))); do setup_client_peer $n; done

    # NOTE: When running this script a second time, doing cleanup as
    # we exit the first invocation, ncat is hanging on receiving the
    # response. tcpdump shows that the response is indeed sent by the
    # server.
    for n in $(seq 10 $(( 9+$NCLIENTS ))); do
	req_check $n
	#t=$(( 1 + $RANDOM % 2 ))
	#sleep $t
    done

    while sleep 1; do
	if [ $(( $RANDOM % 100 )) -lt 50 ]; then
	    run_k_at_random $NCLIENTS 5
	fi
    done
}

fail() {
    echo "FAIL \"$1\""
    exit 1
}

test_case_1() {
    # One client -- 9.
    setup_client_peer 9

    pretty 9 "Badly formed request => errno=1"
    send_cmd 9 "ip_request=\n\n"
    [[ ${ERRNO[9]} = 1 ]] || fail "errno: ${ERRNO[9]}"

    ## Check disabled 2019-09-27. Enable again when ipp_add_v4() and
    ## ipp_add_v6() have checks.
    #pretty 9 "Request an address we won't get => errno=2"
    #req 9 "1.1.1.0/32" "-"
    #[[ ${ERRNO[9]} = 2 ]] || fail "errno: ${ERRNO[9]}"

    pretty "" "SUCCESS\n"
}

test_case_2() {
    # Two clients -- 10 and 11.
    for i in 10 11; do setup_client_peer $i; done

    pretty 10 "Any v4, any v6"
    req_check 10
    [[ ${ERRNO[10]} = 0 ]] || fail "errno: ${ERRNO[10]}"
    local C10_FIRST_V4=${IPV4[10]}
    local C10_FIRST_V6=${IPV6[10]}

    pretty 10 "Extend v4, extend v6"
    req_check 10 $C10_FIRST_V4 $C10_FIRST_V6
    [[ ${ERRNO[10]} = 0 ]] || fail "errno: ${ERRNO[10]}"
    [[ ${IPV4[10]} = $C10_FIRST_V4 ]] || fail "ipv4: ${IPV4[10]}"
    [[ ${IPV6[10]} = $C10_FIRST_V6 ]] || fail "ipv6: ${IPV6[10]}"

    pretty 10 "Extend v4, drop v6"
    req_check 10 $C10_FIRST_V4 "-"
    [[ ${ERRNO[10]} = 0 ]] || fail "errno: ${ERRNO[10]}"
    [[ ${IPV4[10]} = $C10_FIRST_V4  ]] || fail "ipv4: ${IPV4[10]}"
    [[ -z "${IPV6[10]}" ]] || fail "ipv6: ${IPV6[10]}"

    pretty 11 "Requesting the v4 of client 10 and no v6 => errno=0 and no addrs"
    req 11 $C10_FIRST_V4 "-"
    [[ ${ERRNO[11]} = 0 ]] || fail "errno: ${ERRNO[11]}"
    [[ -z "${IPV4[11]}" ]] || fail "ipv4 not empty: ${IPV4[11]}"
    [[ -z "${IPV6[11]}" ]] || fail "ipv6 not empty: ${IPV6[11]}"

    pretty 11 "Wait for lease to expire and try again"
    pp sleep ${LEASETIME[10]}
    req_check 11 $C10_FIRST_V4 "-"
    [[ ${ERRNO[11]} = 0 ]] || fail "errno: ${ERRNO[11]}"
    [[ ${IPV4[11]} = $C10_FIRST_V4  ]] || fail "ipv4: ${IPV4[11]}"
    [[ -z "${IPV6[11]}" ]] || fail "ipv6 not empty: ${IPV6[11]}"

    pretty "" "SUCCESS\n"
}

#test_random 50

test_case_1
test_case_2
