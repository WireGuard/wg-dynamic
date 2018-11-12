#include "protocol.capnp.h"
/* AUTO GENERATED - DO NOT EDIT */
#ifdef __GNUC__
# define capnp_unused __attribute__((unused))
# define capnp_use(x) (void) x;
#else
# define capnp_unused
# define capnp_use(x)
#endif


WgClientMsg_ptr new_WgClientMsg(struct capn_segment *s) {
	WgClientMsg_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
WgClientMsg_list new_WgClientMsg_list(struct capn_segment *s, int len) {
	WgClientMsg_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_WgClientMsg(struct WgClientMsg *s capnp_unused, WgClientMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->request = (enum WgClientMsg_WgClientRequestType)(int) capn_read16(p.p, 0);
}
void write_WgClientMsg(const struct WgClientMsg *s capnp_unused, WgClientMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, (uint16_t) (s->request));
}
void get_WgClientMsg(struct WgClientMsg *s, WgClientMsg_list l, int i) {
	WgClientMsg_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_WgClientMsg(s, p);
}
void set_WgClientMsg(const struct WgClientMsg *s, WgClientMsg_list l, int i) {
	WgClientMsg_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_WgClientMsg(s, p);
}

WgIpv4Addr_ptr new_WgIpv4Addr(struct capn_segment *s) {
	WgIpv4Addr_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
WgIpv4Addr_list new_WgIpv4Addr_list(struct capn_segment *s, int len) {
	WgIpv4Addr_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_WgIpv4Addr(struct WgIpv4Addr *s capnp_unused, WgIpv4Addr_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->addr = capn_read32(p.p, 0);
	s->cidr = capn_read8(p.p, 4);
}
void write_WgIpv4Addr(const struct WgIpv4Addr *s capnp_unused, WgIpv4Addr_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->addr);
	capn_write8(p.p, 4, s->cidr);
}
void get_WgIpv4Addr(struct WgIpv4Addr *s, WgIpv4Addr_list l, int i) {
	WgIpv4Addr_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_WgIpv4Addr(s, p);
}
void set_WgIpv4Addr(const struct WgIpv4Addr *s, WgIpv4Addr_list l, int i) {
	WgIpv4Addr_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_WgIpv4Addr(s, p);
}

WgIpv6Addr_ptr new_WgIpv6Addr(struct capn_segment *s) {
	WgIpv6Addr_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
WgIpv6Addr_list new_WgIpv6Addr_list(struct capn_segment *s, int len) {
	WgIpv6Addr_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_WgIpv6Addr(struct WgIpv6Addr *s capnp_unused, WgIpv6Addr_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->addr = capn_get_data(p.p, 0);
	s->cidr = capn_read8(p.p, 0);
}
void write_WgIpv6Addr(const struct WgIpv6Addr *s capnp_unused, WgIpv6Addr_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->addr.p);
	capn_write8(p.p, 0, s->cidr);
}
void get_WgIpv6Addr(struct WgIpv6Addr *s, WgIpv6Addr_list l, int i) {
	WgIpv6Addr_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_WgIpv6Addr(s, p);
}
void set_WgIpv6Addr(const struct WgIpv6Addr *s, WgIpv6Addr_list l, int i) {
	WgIpv6Addr_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_WgIpv6Addr(s, p);
}

WgServerSimpleMsg_ptr new_WgServerSimpleMsg(struct capn_segment *s) {
	WgServerSimpleMsg_ptr p;
	p.p = capn_new_struct(s, 8, 2);
	return p;
}
WgServerSimpleMsg_list new_WgServerSimpleMsg_list(struct capn_segment *s, int len) {
	WgServerSimpleMsg_list p;
	p.p = capn_new_list(s, len, 8, 2);
	return p;
}
void read_WgServerSimpleMsg(struct WgServerSimpleMsg *s capnp_unused, WgServerSimpleMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->leasedIpv4.p = capn_getp(p.p, 0, 0);
	s->leaseTimeout = capn_read32(p.p, 0);
	s->ipv4Routes.p = capn_getp(p.p, 1, 0);
}
void write_WgServerSimpleMsg(const struct WgServerSimpleMsg *s capnp_unused, WgServerSimpleMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->leasedIpv4.p);
	capn_write32(p.p, 0, s->leaseTimeout);
	capn_setp(p.p, 1, s->ipv4Routes.p);
}
void get_WgServerSimpleMsg(struct WgServerSimpleMsg *s, WgServerSimpleMsg_list l, int i) {
	WgServerSimpleMsg_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_WgServerSimpleMsg(s, p);
}
void set_WgServerSimpleMsg(const struct WgServerSimpleMsg *s, WgServerSimpleMsg_list l, int i) {
	WgServerSimpleMsg_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_WgServerSimpleMsg(s, p);
}
