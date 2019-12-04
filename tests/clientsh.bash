#! /bin/bash

# BUG: When running this a second time targeting the same
# wg-dynamic-server, first ncat is hanging on receiving a response.
# tcpdump shows that the response is indeed sent by the server.

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

    # It would have been nice to use /dev/tcp/fe80::%w0/970 instead of
    # nc, but we need to use a specific source port.
    eval $(
	printf $REQ | nn -q $n ncat -p 970 fe80::%wg0 970 2>/dev/null |
	    while read -r line && [[ -n $line ]] ; do
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

run_k_fill() {
    local nclients=$1; shift
    local k=$1; shift
    local i

    for i in $(seq $nclients); do
	req_check $(( 9 + $i ))
    done
}

test_many() {
    local func=$1; shift
    local NCLIENTS=$1; shift
    local k=$1; shift
    local n

    for n in $(seq 10 $(( 9+$NCLIENTS ))); do setup_client_peer $n; done

    for n in $(seq 10 $(( 9+$NCLIENTS ))); do
	req_check $n
	#t=$(( 1 + $RANDOM % 2 ))
	#sleep $t
    done

    while sleep 1; do
	if [ $(( $RANDOM % 100 )) -lt 50 ]; then
	    $func $NCLIENTS $k
	fi
    done
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
    [[ ${ERRNO[3]} = 2 ]] || fail "errno: ${ERRNO[3]}"

    ## Check disabled 2019-09-27. Enable again when ipp_add_v4() and
    ## ipp_add_v6() have checks.
    #pretty 3 "Request an address we won't get => errno=2"
    #req 3 "1.1.1.0/32" "-"
    #[[ ${ERRNO[3]} = 2 ]] || fail "errno: ${ERRNO[3]}"

    pretty "" "SUCCESS\n"
}

test_case_2() {
    # Two clients -- 4 and 5.
    for i in 4 5; do setup_client_peer $i; done

    pretty 4 "Any v4, any v6"
    req_check 4
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    local C4_FIRST_V4=${IPV4[4]}
    local C4_FIRST_V6=${IPV6[4]}

    pretty 4 "Extend v4, extend v6"
    req_check 4 $C4_FIRST_V4 $C4_FIRST_V6
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    [[ ${IPV4[4]} = $C4_FIRST_V4 ]] || fail "ipv4: ${IPV4[4]}"
    [[ ${IPV6[4]} = $C4_FIRST_V6 ]] || fail "ipv6: ${IPV6[4]}"

    pretty 4 "Extend v4, drop v6"
    req_check 4 $C4_FIRST_V4 "-"
    [[ ${ERRNO[4]} = 0 ]] || fail "errno: ${ERRNO[4]}"
    [[ ${IPV4[4]} = $C4_FIRST_V4  ]] || fail "ipv4: ${IPV4[4]}"
    [[ -z "${IPV6[4]}" ]] || fail "ipv6: ${IPV6[4]}"

    pretty 5 "Requesting the v4 of client 4 and no v6 => errno=0 and no addrs"
    req 5 $C4_FIRST_V4 "-"
    [[ ${ERRNO[5]} = 0 ]] || fail "errno: ${ERRNO[5]}"
    [[ -z "${IPV4[5]}" ]] || fail "ipv4 not empty: ${IPV4[5]}"
    [[ -z "${IPV6[5]}" ]] || fail "ipv6 not empty: ${IPV6[5]}"

    pretty 5 "Wait for lease to expire and try again"
    pp sleep ${LEASETIME[4]}
    req_check 5 $C4_FIRST_V4 "-"
    [[ ${ERRNO[5]} = 0 ]] || fail "errno: ${ERRNO[5]}"
    [[ ${IPV4[5]} = $C4_FIRST_V4  ]] || fail "ipv4: ${IPV4[5]} != $C4_FIRST_V4"
    [[ -z "${IPV6[5]}" ]] || fail "ipv6 not empty: ${IPV6[5]}"

    pretty "" "SUCCESS\n"
}

test_case_3() {
    # Two clients -- 6 and 7.
    for i in 6 7; do setup_client_peer $i; done

    pretty 6 "Any v4, any v6"
    req_check 6
    [[ ${ERRNO[6]} = 0 ]] || fail "errno: ${ERRNO[6]}"
    local C6_FIRST_V4=${IPV4[6]}
    local C6_FIRST_V6=${IPV6[6]}

    pretty 6 "Drop v4, extend v6"
    req_check 6 "-" $C6_FIRST_V6
    [[ ${ERRNO[6]} = 0 ]] || fail "errno: ${ERRNO[6]} != 0"
    [[ -z ${IPV4[6]} ]] || fail "ipv4: ${IPV4[6]} != 0.0.0.0/32"
    [[ ${IPV6[6]} = $C6_FIRST_V6 ]] || fail "ipv6: ${IPV6[6]} != $C6_FIRST_V6"

    pretty "" "SUCCESS\n"
}

test_case_1
test_case_2
test_case_3

N_RANDOM=20
K_RANDOM=4
[ $# -gt 0 ] && { N_RANDOM=$1; shift; }
[ $# -gt 0 ] && { K_RANDOM=$1; shift; }

test_many run_k_at_random $N_RANDOM $K_RANDOM
#test_many run_k_fill $N_RANDOM $K_RANDOM
