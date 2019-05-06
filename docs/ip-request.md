# Dynamic IP address allocation

This document describes version 1 of the wg-dynamic `request_ip`
command.

See protocol.md for a general description of the protocol.


## Server

The wg-dynamic server is a daemon responsible for handing out IP
addresses in form of leases to wg-dynamic clients requesting them.

### Address allocation

The pool of available addresses is made up of the list of addresses
that are part of the prefixes being routed over the wg
interface. Leases are picked uniformly random from this pool and
handed out to wg-dynamic clients upon request.

A client including an IP address in a request is granted that address
if and only if this address is already assigned to the
client. Specifically, a request for an IP address which is not
allocated to the client requesting it is _not_ assigned this address
but is instead assigned an address by random.

TODO: lease time

### Data and state

- lease: 0..*

  - data:
    - ipv4-address [in_addr, cidr]
    - ipv6-address [in6_addr, cidr]
    - expires-at [integer]
    - allocated-to [peer]

  - states and possible transitions:
    - <new>   -> CREATED
    - CREATED -> DELETED
    - DELETED -> <delete>

  - triggers:
    - request: incoming ip_request from client
    - expired: now > expires-at

  - state transitions
    - <new>:
      - request -> CREATED
    - CREATED:
      - expired -> DELETED
    - DELETED:
      - <delete>


## Client

The wg-dynamic client is a daemon responsible for requesting IP
address leases from a wg-dynamic server, for a given wg
interface. Requests for leases are sent over the same wg interface to
a server on a well known IPv6 link local address and well known low
TCP port. A lease has at least one IP address and has at most one IPv4
address and at most one IPv6 address.

### Security

TODO: guaranteed to be sent only to and received only from the server
endpoint

TODO: no routing information is being accepted, eg only accepting /32
and /128 addresses

### Single lease

Clients keep track of exactly one lease, active or inactive. At
inception time, clients assume at most one global IPv4 and one global
IPv6 address configured for the wg interface to be part of a lease
valid for 15 seconds.

Addresses received in a lease are being added to the wg
interface. Addresses in an expired lease are being removed from the wg
interface.

### Data and state

- lease: 1

  - data:
    - ipv4-address [in_addr, cidr]
    - ipv6-address [in6_addr, cidr]
    - start-time [integer]
    - lease-time [integer]

  - states and possible transitions:
    - VALID          -> VALID-EXPIRING, INVALID
    - VALID-EXPIRING -> VALID, INVALID
    - INVALID        -> VALID

  - triggers:
    - got-lease: valid request_ip response
    - aging: less than 2/3 of lease-time left
    - aged: now > start-time + lease_time

  - state transitions:
    - VALID:
      - aging -> VALID-EXPIRING
      - aged -> INVALID
    - VALID-EXPIRING:
      - got-lease -> VALID
      - aged -> INVALID
    - INVALID:
      - got-lease -> VALID


## Protocol

A client requests an IP address lease by sending a request\_ip
command. The request\_ip command accepts the following attributes, all
optional:

IP addresses are expressed in CIDR notation. A point in time is
expressed as seconds since the epoch (1970-01-01 UTC). When this
document talks about current time, the current time of the computers
clock in UTC is what's being refered to.

- ipv4 (optional)

  IPv4 address hint in CIDR notation. The client would like to have
  this IPv4 address to use. The server MUST NOT honour the request for
  this particular address unless the client already has got a valid
  lease for it.

- ipv6 (optional)

  IPv6 address hint in CIDR notation. The client would like to have
  this IPv6 address to use.

- leasetime (optional)

  Lease time hint in seconds. The client would like the lease to be
  valid for at least this long.

The server response to a request\_ip command contains an errno
attribute and, if the request was succesful, up to four attributes
containing the result:

- ipv4

  IPv4 address for the client to use. Unless the IPv4 address hint in

- ipv6

  IPv6 address for the client to use.

- leasestart

  The start time of the lease.

  A client receiving a response with a leasestart that deviates from
  current time of the client by more than 15 seconds MUST use current
  time instead of leasestart.

- leasetime

  The number of seconds that this lease is valid, starting from
  leasestart.

- errno

  Errno is 0 for a successful operation.

At least one of the ipv4 and ipv6 attributes in a response with
errno=0 MUST be a valid address picked by random from the pool of free
addresses. This does not appliy for addresses chosen from a valid
address hint received in the request, see above

leasestart MUST be the current time of the server.

TODO: put restrictions on leasetime, minimal or maximal?


If the request failed, errno is != 0 and an errmsg attribute is
included in the response:

- errno

  A positive integer indicating what made the request fail. The
  following error codes are defined:

  - 1: Undefined internal error
  - 2: Out of IP addresses

- errmsg

  A text suitable for a human, describing what made the request fail.

### Example

client -> server request

    request_ip=1
	[empty line]

server -> client response

    request_ip=1
	ipv4=192.168.47.11/32
	ipv6=fd00::4711/128
	leasestart=1555074514
	leasetime=3600
	errno=0
	[empty line]
