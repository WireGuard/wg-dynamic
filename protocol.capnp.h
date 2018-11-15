#ifndef CAPN_ED77208FB3340CC1
#define CAPN_ED77208FB3340CC1
/* AUTO GENERATED - DO NOT EDIT */
#include <capnp_c.h>

#if CAPN_VERSION != 1
#error "version mismatch between capnp_c.h and generated code"
#endif

#ifndef capnp_nowarn
# ifdef __GNUC__
#  define capnp_nowarn __extension__
# else
#  define capnp_nowarn
# endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct WgClientMsg;
struct WgIpv4Addr;
struct WgIpv6Addr;
struct WgServerSimpleIpv4Msg;

typedef struct {capn_ptr p;} WgClientMsg_ptr;
typedef struct {capn_ptr p;} WgIpv4Addr_ptr;
typedef struct {capn_ptr p;} WgIpv6Addr_ptr;
typedef struct {capn_ptr p;} WgServerSimpleIpv4Msg_ptr;

typedef struct {capn_ptr p;} WgClientMsg_list;
typedef struct {capn_ptr p;} WgIpv4Addr_list;
typedef struct {capn_ptr p;} WgIpv6Addr_list;
typedef struct {capn_ptr p;} WgServerSimpleIpv4Msg_list;

enum WgClientMsg_WgClientRequestType {
	WgClientMsg_WgClientRequestType_simpleIpv4 = 0
};

struct WgClientMsg {
	enum WgClientMsg_WgClientRequestType request;
};

static const size_t WgClientMsg_word_count = 1;

static const size_t WgClientMsg_pointer_count = 0;

static const size_t WgClientMsg_struct_bytes_count = 8;

struct WgIpv4Addr {
	uint32_t addr;
	uint8_t cidr;
};

static const size_t WgIpv4Addr_word_count = 1;

static const size_t WgIpv4Addr_pointer_count = 0;

static const size_t WgIpv4Addr_struct_bytes_count = 8;

struct WgIpv6Addr {
	capn_data addr;
	uint8_t cidr;
};

static const size_t WgIpv6Addr_word_count = 1;

static const size_t WgIpv6Addr_pointer_count = 1;

static const size_t WgIpv6Addr_struct_bytes_count = 16;

struct WgServerSimpleIpv4Msg {
	WgIpv4Addr_ptr leasedIpv4;
	uint32_t leaseTimeout;
	WgIpv4Addr_list ipv4Routes;
};

static const size_t WgServerSimpleIpv4Msg_word_count = 1;

static const size_t WgServerSimpleIpv4Msg_pointer_count = 2;

static const size_t WgServerSimpleIpv4Msg_struct_bytes_count = 24;

WgClientMsg_ptr new_WgClientMsg(struct capn_segment*);
WgIpv4Addr_ptr new_WgIpv4Addr(struct capn_segment*);
WgIpv6Addr_ptr new_WgIpv6Addr(struct capn_segment*);
WgServerSimpleIpv4Msg_ptr new_WgServerSimpleIpv4Msg(struct capn_segment*);

WgClientMsg_list new_WgClientMsg_list(struct capn_segment*, int len);
WgIpv4Addr_list new_WgIpv4Addr_list(struct capn_segment*, int len);
WgIpv6Addr_list new_WgIpv6Addr_list(struct capn_segment*, int len);
WgServerSimpleIpv4Msg_list new_WgServerSimpleIpv4Msg_list(struct capn_segment*, int len);

void read_WgClientMsg(struct WgClientMsg*, WgClientMsg_ptr);
void read_WgIpv4Addr(struct WgIpv4Addr*, WgIpv4Addr_ptr);
void read_WgIpv6Addr(struct WgIpv6Addr*, WgIpv6Addr_ptr);
void read_WgServerSimpleIpv4Msg(struct WgServerSimpleIpv4Msg*, WgServerSimpleIpv4Msg_ptr);

void write_WgClientMsg(const struct WgClientMsg*, WgClientMsg_ptr);
void write_WgIpv4Addr(const struct WgIpv4Addr*, WgIpv4Addr_ptr);
void write_WgIpv6Addr(const struct WgIpv6Addr*, WgIpv6Addr_ptr);
void write_WgServerSimpleIpv4Msg(const struct WgServerSimpleIpv4Msg*, WgServerSimpleIpv4Msg_ptr);

void get_WgClientMsg(struct WgClientMsg*, WgClientMsg_list, int i);
void get_WgIpv4Addr(struct WgIpv4Addr*, WgIpv4Addr_list, int i);
void get_WgIpv6Addr(struct WgIpv6Addr*, WgIpv6Addr_list, int i);
void get_WgServerSimpleIpv4Msg(struct WgServerSimpleIpv4Msg*, WgServerSimpleIpv4Msg_list, int i);

void set_WgClientMsg(const struct WgClientMsg*, WgClientMsg_list, int i);
void set_WgIpv4Addr(const struct WgIpv4Addr*, WgIpv4Addr_list, int i);
void set_WgIpv6Addr(const struct WgIpv6Addr*, WgIpv6Addr_list, int i);
void set_WgServerSimpleIpv4Msg(const struct WgServerSimpleIpv4Msg*, WgServerSimpleIpv4Msg_list, int i);

#ifdef __cplusplus
}
#endif
#endif
