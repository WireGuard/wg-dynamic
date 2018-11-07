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

# server response message
struct WgServerSimpleMsg {
       leasedIpv4 @0 :UInt32; # dynamic IPv4 leased to client
       leasedIpv4Cidr @1 :UInt32; # CIDR of dynamic IPv4 leased to client
       leaseTimeout @2 :UInt32; # activity timeout for the IP lease in seconds
       route @3 :UInt32; # route for client
       routeCidr @4 :UInt32; # CIDR of route for client
}
