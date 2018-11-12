# SPDX-License-Identifier: MIT
#
# Copyright (C) 2018 Wireguard LLC
#

@0xed77208fb3340cc1;

# client request message
struct WgClientMsg {
       request @0 :WgClientRequestType;
       
       enum WgClientRequestType {
            simple @0;
       }
}

# IPv4 address
struct WgIpv4Addr {
       addr @0 :UInt32; # IPv4 address
       cidr @1 :UInt8; # CIDR of IPv4 address
}

# IPv6 address
struct WgIpv6Addr {
       addr @0 :Data; # IPv6 address
       cidr @1: UInt8; # CIDR of IPv6 address
}

# server response message
struct WgServerSimpleMsg {
       leasedIpv4 @0 :WgIpv4Addr; # dynamic IPv4 leased to client
       leaseTimeout @1 :UInt32; # activity timeout for the IP lease in seconds
       ipv4Routes @2 :List(WgIpv4Addr); # IPv4 routes for client
}
