set -e
exec 3>&1

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

## Start server in the background with 30s lease time
exec 4< <(nn 1 ./wg-dynamic-server --leasetime 30 wg0)
server_pid=$!
pretty "" "server_pid: $server_pid"

## Get a lease
send_cmd() {
    local n=$1; shift
    local REQ="$1"; shift

    eval $(
	printf $REQ | nn $n ncat -v -p 970 fe80::%wg0 970 |
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
check_alowedips() {
    local pubkey="$1"; shift
    local ip="$1"; shift

    [[ -z "$ip" ]] && return 0

    nn 1 wg show wg0 allowed-ips |
	while read -r _pubkey _ips; do
	    [[ "$_pubkey" = "$pubkey" ]] || continue
	    for _ip in $_ips; do
		[[ "$_ip" = "$ip" ]] && return 0
	    done
	done && return 0

    pretty "" "Missing $ip in allowedips"
    return 1
}
declare -a IPV4
declare -a IPV6
declare -a LEASESTART
declare -a LEASETIME
declare -a ERRNO

send_cmd 2 "request_ip=1\n\n"
check_alowedips "$client_public" "${IPV4[2]}"
check_alowedips "$client_public" "${IPV6[2]}"

## Restart server with 10s leasetime
nn 1 kill $server_pid
sleep 1
exec 4< <(nn 1 ./wg-dynamic-server --leasetime 3 wg0) || { pretty "" $?; false; }
server_pid=$!
pretty "" "server_pid 2: $server_pid"

## Verify that the lease has been restored
check_alowedips "$client_public" "${IPV4[2]}"
check_alowedips "$client_public" "${IPV6[2]}"

## Wait for the lease to expire
pp sleep 4

## Restart server
nn 1 kill $server_pid
sleep 1
exec 4< <(nn 1 ./wg-dynamic-server wg0)

## Verify that the lease has not reappeared
notlladdr='192.168.*/32|2001:.*/128'
nn 1 wg show wg0 allowed-ips |
    while read -r _pubkey _ips; do
	[[ "$_pubkey" = "$client_public" ]] || continue
	for _ip in $_ips; do
	    [[ "$_ip" =~ $notlladdr ]] && { pretty "" "FAIL: $_ip"; false; }
	done
    done && true

pretty "" "SUCCESS\n"
