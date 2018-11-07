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

WgServerSimpleMsg_ptr new_WgServerSimpleMsg(struct capn_segment *s) {
	WgServerSimpleMsg_ptr p;
	p.p = capn_new_struct(s, 24, 0);
	return p;
}
WgServerSimpleMsg_list new_WgServerSimpleMsg_list(struct capn_segment *s, int len) {
	WgServerSimpleMsg_list p;
	p.p = capn_new_list(s, len, 24, 0);
	return p;
}
void read_WgServerSimpleMsg(struct WgServerSimpleMsg *s capnp_unused, WgServerSimpleMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->leasedIpv4 = capn_read32(p.p, 0);
	s->leasedIpv4Cidr = capn_read32(p.p, 4);
	s->leaseTimeout = capn_read32(p.p, 8);
	s->route = capn_read32(p.p, 12);
	s->routeCidr = capn_read32(p.p, 16);
}
void write_WgServerSimpleMsg(const struct WgServerSimpleMsg *s capnp_unused, WgServerSimpleMsg_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->leasedIpv4);
	capn_write32(p.p, 4, s->leasedIpv4Cidr);
	capn_write32(p.p, 8, s->leaseTimeout);
	capn_write32(p.p, 12, s->route);
	capn_write32(p.p, 16, s->routeCidr);
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
