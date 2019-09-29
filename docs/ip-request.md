
DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT
DRAFT                                     DRAFT
DRAFT                                     DRAFT
DRAFT             2019-09-27              DRAFT
DRAFT                                     DRAFT
DRAFT                                     DRAFT
DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT DRAFT

# Dynamic IP address allocation

This document describes version 1 of the wg-dynamic `request_ip`
command.

See protocol.md for a general description of the protocol.


## Server

The wg-dynamic server is a daemon responsible for handing out IP
addresses in form of leases to wg-dynamic clients requesting them.

Unless the client asks for a specific address, one is picked uniformly
random from a pool of free addresses and is handed out to wg-dynamic
clients upon request.

A pool of available addresses, both IPv4 and IPv6, is being maintained
by the server. The pool is populated with the list of addresses being
routed over the wg interface and updated as leases are being granted
and expire. The first and last IPv4 addresses of an address block with
a prefix length less than 31 bits are not handed out.

A request for a specific IP address is granted if the address is
present in the pool and the server plans on keeping it in the pool for
the lifetime of the lease.

A request not including an IP address should result in a lease for one
IPv4 address and one IPv6 address. The server is allowed to impose
rate limiting on the churn of addresses granted to a given client.

A given client is at any given time granted at most one IPv4 address
and at most one IPv6 address.

A lease is valid for a configured amount of time, by default 3600
seconds.


## Client

The wg-dynamic client is a daemon responsible for requesting IP
address leases from a wg-dynamic server, for a given wg
interface. Requests for leases are sent over the clients wg interface
to a server on a well known IPv6 link local address and well known low
TCP port. The source port used MUST be the same as the well known
server port.

At any given time, a client has one or zero leases. A lease has one or
zero IPv4 addresses and one or zero IPv6 addresses.

A client starts refreshing its lease 300 seconds (plus/minus a random
jitter, 0s-30s) before the lease runs out. It keeps refreshing its
lease until it has one with a lifetime longer than 300 seconds.

### Security

A client MUST send requests from an IPv6 link local address with
netmask 128 and with the scope of the wg interface. It MUST use the
same low TCP port as being used by the server. This way wg-dynamic
requests are guaranteed to be sent only to and received only from the
configured wg-dynamic server endpoint and only sent by a process with
permissions to bind to a low port.

TODO: no routing information is being accepted by clients, eg only
configuring /32 and /128 addresses

## Protocol

A client requests IP address leasees by sending a request\_ip
command. The request\_ip command has the following optional attribute:

- ipv4 (optional)

  Omitting this attribute indicates that the client is fine with any
  IPv4 address and gets an address by random, given that the IPv4 pool
  is not exhausted.

  Sending this attribute with an IPv4 address in CIDR notation as its
  value means that the client would like to have this particular
  address granted.

  Sending this attribute without a value ("ipv4=") means that the
  client does not want an IPv4 address and that any IPv4 address being
  allocated for it should be released.

- ipv6 (optional)

  Omitting this attribute indicates that the client is fine with any
  IPv6 address and gets an address by random, given that the IPv6 pool
  is not exhausted.

  Sending this attribute with an IPv6 address in CIDR notation as its
  value means that the client would like to have this particular
  address granted.

  Sending this attribute without a value ("ipv6=") means that the
  client does not want an IPv6 address and that any IPv6 address being
  allocated for it should be released.


The server response to a request\_ip command contains an errno
attribute and, if the request was succesful, up to three attributes
containing the result:

- ipv4

  IPv4 address for the client to use. A server MUST offer IPv4
  addresses with a prefix length of 32 bits and a client MUST refuse an
  address with a shorter prefix.

- ipv6

  IPv6 address for the client to use. A server MUST offer IPv6
  addresses with a prefix length of 128 bits and a client MUST refuse
  an address with a shorter prefix.

- leasestart

  The start time of the lease, in seconds since the epoch.

  A client receiving a response with a leasestart that deviates from
  current time of the client by more than 15 seconds MUST use current
  time instead of leasestart.

- leasetime

  The number of seconds that this lease is valid, starting from
  leasestart.

  MUST be the current time of the server.

- errno

  Errno is 0 for a successful operation.

A point in time is expressed as seconds since the epoch (1970-01-01
00:00 UTC). When this document talks about current time, the current
time of the computers clock in UTC is what's being refered to.

If the request fails, errno is != 0 and an errmsg attribute is the
only other attribute in the response:

- errno

  A positive integer indicating what made the request fail. The
  following error codes are defined:

  - 1: Undefined internal error

- errmsg

  A text suitable for human consumption, describing what made the
  request fail.

### Examples

#### Example 1

Client asking for any IPv4 address and any IPv6 address, receiving
both. This results in two leases being recorded by the client, one per
address.

client -> server request

    request_ip=1

server -> client response

    request_ip=1
    ipv4=192.168.47.11/32
    ipv6=fd00::4711/128
    leasestart=1569234893
    leasetime=1800
    errno=0

#### Example 2

Client asking for a specific IPv4 address and a specific IPv6 address,
receiving both.

client -> server request

    request_ip=1
    ipv4=192.168.47.11/32
    ipv6=fd00::4711/128

server -> client response

    request_ip=1
    ipv4=192.168.47.11/32
    ipv6=fd00::4711/128
    leasestart=1569236593
    leasetime=1800
    errno=0

#### Example 3

Client asking for a specific IPv4 address and a specific IPv6 address,
receiving none because both the IPv4 and IPv6 pools are empty.

client -> server request

    request_ip=1
    ipv4=192.168.47.11/32
    ipv6=fd00::4711/128

server -> client response

    request_ip=1
    errno=0

#### Example 4

Client asking for any IPv4 address and a specific IPv6 address,
receiving no IPv4 address because that pool is empty and another IPv6
because the requested address is not free.

client -> server request

    request_ip=1
    ipv6=fd00::4711/128

server -> client response

    request_ip=1
    ipv6=fd00::42/128
    leasestart=1569273827
    leasetime=1800
    errno=0

#### Example 5

Client asking for any IPv4 address and no IPv6 address, receiving an
IPv4 address and no IPv6 address. If the client did have an IPv6
address allocated at the time of the request it's now been released.

client -> server request

    request_ip=1
    ipv6=

server -> client response

    request_ip=1
    ipv4=192.168.47.22/32
    errno=0
