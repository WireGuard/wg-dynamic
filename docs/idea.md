wg-dynamic
==========

If this looks like an interesting project to you, get in touch with
the WireGuard development team.

WireGuard currently uses static addresses everywhere. This is because
that is mostly a better way to design your network. But in some cases,
insane people want dynamic IP addresses or other dynamic
configuration.

This paper explores a couple approaches to WireGuard in-band
configuration. Ultimately, however, custom in-band communication
brings with it many difficulties, such as introducing new non-standard
APIs and having to reinvent the wheel with reliable transport
protocols.

Traditionally, configuration of IP addresses has been done at a layer
in between 2 and 3 using DHCP. DHCP, however, has numerous drawbacks
that make it unsuitable for use with WireGuard:

 * Relies on broadcast.
 * Unicast DHCP is not well supported nor mature.
 * Two different protocols for v6 and v4, and v4-in-v6 dhcp is a bit insane.
 * Cumbersome and old.

Fortunately IPv6 link-local addresses give us exactly the semantics we
need for an in-band configuration protocol, without needing to
introduce new layer 3 types. Since a server must know each of its
clients public keys beforehand, it is not ridiculous to, at the same
time, assign a unique link-local IP address to that client. In this
setup, the server knows a priori the client’s public key and the
client’s link local IPv6 address. The client needs only to know the
server’s public key.

When wg-dynamic is run on a certain WireGuard interface, say wg0, it
determines whether that interface has a link-local IP address that is
actually a /128 and also has a peer whose allowedips include
`fe80::/128`. If not, it exits. If so, it initiates the protocol with
`fe80::%wg0` -- notice the use of the link-local scope identifier.

In the protocol, the server -- communicated with via `fe80::%wg0` --
assigns the client dynamically determined global IPv4 and IPv6
addresses and masks from an address pool, with a lease, and usual
dhcp-like renewal semantics commence. All leased IP addresses are
added to that peer’s set of allowed IPs, so that the client can
actually use them. The protocol could also push routes to be added to
allowedips and the routing table. The protocol would likely use TCP
rather than UDP, since we have the luxury of unicast and being inside
of a secure tunnel.

In the future, the protocol could also push information about other
peers, transitioning wg-dynamic from a basic boring dhcp-substitute
into a full fledged WireGuard mesh networking utility.

Thus, the above consists of implementing a lightweight client daemon
and server daemon in C with no dependencies, to become part of the
standard set of WireGuard tools. The UI of the client daemon is
simplest in its usage:

    $ wg-dynamic-client wg0

After this, it validates wg0 has the necessary configuration for it to
function, and then it forks into the background, listens to up/down
events, and lives until wg0 is removed, at which time it exits.

This will then hook nicely into wg-quick(8) configurations. The
following configuration will initiate a wg-dynamic IP address
assignment on the client side:


    [Interface]
    PrivateKey = …
    Address = fe80::abcd:abcd:abcd:abcd/128, auto
    [Peer]
    PublicKey = …
    AllowedIPs = 0.0.0.0/0, ::/0

The “auto” in the list of addresses means “spawn wg-dynamic.” And
notice that `fe80::/128` is a subset of the included `::/0`. However,
this would be equally as valid:

    [Interface]
    PrivateKey = …
    Address = fe80::abcd:abcd:abcd:abcd/128, auto
    [Peer]
    PublicKey = …
    AllowedIPs = fe80::/128

Though part of the standard set of WireGuard utilities, which is
GPLv2, the code from wg-dynamic would likely be recycled in various
client apps; thus MIT license is preferred for this.

The app will require various APIs and competencies:

 * Standard linux socket programming.
 * Rtnetlink for configuring device, listening to events, and so forth, preferably using libmnl.
 * Genetlink for talking to wireguard, preferably using the mini wireguard library.
 * Design of a new protocol wire format that is sane and appropriate for 2019.
 * Implementation of code that parses untrusted packets, makes
   decisions with this data, and does not get your box owned in the
   process. This is harder than it may seem.
