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
struct WgServerSimpleMsg;

typedef struct {capn_ptr p;} WgClientMsg_ptr;
typedef struct {capn_ptr p;} WgServerSimpleMsg_ptr;

typedef struct {capn_ptr p;} WgClientMsg_list;
typedef struct {capn_ptr p;} WgServerSimpleMsg_list;

enum WgClientMsg_WgClientRequestType {
	WgClientMsg_WgClientRequestType_simple = 0
};

struct WgClientMsg {
	enum WgClientMsg_WgClientRequestType request;
};

static const size_t WgClientMsg_word_count = 1;

static const size_t WgClientMsg_pointer_count = 0;

static const size_t WgClientMsg_struct_bytes_count = 8;

struct WgServerSimpleMsg {
	uint32_t leasedIpv4;
	uint32_t leasedIpv4Cidr;
	uint32_t leaseTimeout;
	uint32_t route;
	uint32_t routeCidr;
};

static const size_t WgServerSimpleMsg_word_count = 3;

static const size_t WgServerSimpleMsg_pointer_count = 0;

static const size_t WgServerSimpleMsg_struct_bytes_count = 24;

WgClientMsg_ptr new_WgClientMsg(struct capn_segment*);
WgServerSimpleMsg_ptr new_WgServerSimpleMsg(struct capn_segment*);

WgClientMsg_list new_WgClientMsg_list(struct capn_segment*, int len);
WgServerSimpleMsg_list new_WgServerSimpleMsg_list(struct capn_segment*, int len);

void read_WgClientMsg(struct WgClientMsg*, WgClientMsg_ptr);
void read_WgServerSimpleMsg(struct WgServerSimpleMsg*, WgServerSimpleMsg_ptr);

void write_WgClientMsg(const struct WgClientMsg*, WgClientMsg_ptr);
void write_WgServerSimpleMsg(const struct WgServerSimpleMsg*, WgServerSimpleMsg_ptr);

void get_WgClientMsg(struct WgClientMsg*, WgClientMsg_list, int i);
void get_WgServerSimpleMsg(struct WgServerSimpleMsg*, WgServerSimpleMsg_list, int i);

void set_WgClientMsg(const struct WgClientMsg*, WgClientMsg_list, int i);
void set_WgServerSimpleMsg(const struct WgServerSimpleMsg*, WgServerSimpleMsg_list, int i);

#ifdef __cplusplus
}
#endif
#endif
