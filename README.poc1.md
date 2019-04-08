# wg-dynamic poc1 warning

wg-dynamic ln/poc1 is unreleased code. It has not been reviewed. It's
full of bugs.

This code is meant for very early integration testing. Beware that any
and all of the interfaces for interacting with wg-dynamic may change.

# Building

Download and build

    sudo apt install libmnl0 libmnl-dev
    git clone -b ln/poc1 https://git.zx2c4.com/wg-dynamic
    cd wg-dynamic
    make

# Running a server on wg0

Configure server side wg0 to have fe80::/64:

    sudo ip addr add fe80::/64 dev wg0

Start wg-dynamic-server:

    sudo ./wg-dynamic-server wg0

# Running a client on wg0

NOTE: In order to run client and server on the same host, see
IP-NETNS(8) and tests/netsh.sh.

Configure client side wg0 to have an address with prefix length 128 in
fe80::/64 and make sure that the server can be reached. Example:

    sudo ip addr add fe80::badc:ffe:e0dd:f00d/128 dev wg0
    sudo ip route add fe80::/128 dev wg0

Start wg-dynamic-client:

    sudo ./wg-dynamic-client wg0

# Known limitations

- No running in the background like real daemons.

- No real IP allocation from a pool -- the server simply replies with
  whatever the client asks for, or predefined addresses (192.168.47.11
  / fd00::badc:0ffe:e) in case client has no suggestions.

- Server does not expire leases.
