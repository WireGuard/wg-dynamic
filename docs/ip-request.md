# Dynamic IP address allocation

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
    - CREATED -> DELETED
    - DELETED -> CREATED

  - triggers:
    - request: incoming ip_request from client
    - expired: now > expires-at

  - state transitions
    - <NEW>:
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

Example:

    client -> server: request_ip=1\n\n
    server -> client: request_ip=1\nipv4=192.168.47.11/32\nipv6=fd00::4711/128\nleasestart=1555074514\nleasetime=3600\nerrno=0\n\n
