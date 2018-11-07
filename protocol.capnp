# SPDX-License-Identifier: MIT
#
# Copyright (C) 2018 Wireguard LLC
#

@0xed77208fb3340cc1

# client request message
struct wg_client_msg {
       request @0 :wg_client_request_type;
       
       enum wg_client_request_type {
            WG_REQUEST_SIMPLE @0;
       }
}

# server response message
struct wg_server_simple_msg {
       leased_ipv4 @0 :UInt32; # dynamic IPv4 leased to client
       leased_ipv4_cidr @1 :UInt32; # CIDR of dynamic IPv4 leased to client
       lease_timeout @2 :UInt32; # activity timeout for the IP lease in seconds
       route @3 :UInt32; # route for client
       route @4 :Uint32; # CIDR of route for client
}
