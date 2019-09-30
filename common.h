/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "netlink.h"

#define MAX_CONNECTIONS 16

#define MAX_LINESIZE 4096

#define RECV_BUFSIZE 8192

#define MAX_RESPONSE_SIZE 8192

static const char WG_DYNAMIC_ADDR[] = "fe80::";
static const uint16_t WG_DYNAMIC_PORT = 970; /* ASCII sum of "wireguard" */

#define ITEMS                                                                  \
	E(WGKEY_UNKNOWN, "") /* must be the first entry */                     \
	/* CMD START */                                                        \
	E(WGKEY_REQUEST_IP, "request_ip")                                      \
	E(WGKEY_ENDCMD, "")                                                    \
	/* CMD END */                                                          \
	E(WGKEY_INCOMPLETE, "")                                                \
	E(WGKEY_IPV4, "ipv4")                                                  \
	E(WGKEY_IPV6, "ipv6")                                                  \
	E(WGKEY_LEASESTART, "leasestart")                                      \
	E(WGKEY_LEASETIME, "leasetime")                                        \
	E(WGKEY_ERRNO, "errno")                                                \
	E(WGKEY_ERRMSG, "errmsg")

#define E(x, y) x,
enum wg_dynamic_key { ITEMS };
#undef E
#define E(x, y) y,
static const char *const WG_DYNAMIC_KEY[] = { ITEMS };
#undef E
#undef ITEMS

#define ITEMS                                                                  \
	E(E_NO_ERROR, "Success") /* must be the first entry */                 \
	E(E_INVALID_REQ, "Invalid request")                                    \
	E(E_IP_UNAVAIL, "Chosen IP unavailable")

#define E(x, y) x,
enum wg_dynamic_err { ITEMS };
#undef E
#define E(x, y) y,
static const char *const WG_DYNAMIC_ERR[] = { ITEMS };
#undef E
#undef ITEMS

struct wg_dynamic_attr {
	enum wg_dynamic_key key;
	size_t len;
	struct wg_dynamic_attr *next;
	unsigned char value[];
};

struct wg_dynamic_request {
	enum wg_dynamic_key cmd;
	uint32_t version;
	int fd;
	wg_key pubkey;
	struct in6_addr lladdr;
	unsigned char *buf;
	size_t buflen;
	struct wg_dynamic_attr *first, *last;
};

struct wg_combined_ip {
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint16_t family;
	uint8_t cidr;
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void free_wg_dynamic_request(struct wg_dynamic_request *req);
bool handle_request(struct wg_dynamic_request *req,
		    bool (*success)(struct wg_dynamic_request *),
		    bool (*error)(struct wg_dynamic_request *, int));
bool send_message(struct wg_dynamic_request *req, const void *buf, size_t len);
void print_to_buf(char *buf, size_t bufsize, size_t *offset, char *fmt, ...);
uint32_t current_time();
void close_connection(struct wg_dynamic_request *req);
bool is_link_local(unsigned char *addr);
void iface_get_all_addrs(uint8_t family, mnl_cb_t data_cb, void *cb_data);
int data_attr_cb(const struct nlattr *attr, void *data);
#endif
