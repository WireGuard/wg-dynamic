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
	E(WGKEY_EOMSG, "")                                                     \
	/* CMD START */                                                        \
	E(WGKEY_REQUEST_IP, "request_ip")                                      \
	E(WGKEY_ENDCMD, "")                                                    \
	/* CMD END */                                                          \
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
	E(E_UNSUPP_PROTO, "Unsupported protocol")                              \
	E(E_IP_UNAVAIL, "Chosen IP unavailable")

#define E(x, y) x,
enum wg_dynamic_err { ITEMS };
#undef E
#define E(x, y) y,
static const char *const WG_DYNAMIC_ERR[] = { ITEMS };
#undef E
#undef ITEMS

struct wg_dynamic_request {
	enum wg_dynamic_key cmd;
	uint32_t version;
	unsigned char *buf;
	size_t len; /* <= MAX_LINESIZE */
	void *result;
};

struct wg_dynamic_request_ip {
	struct in_addr ipv4;
	struct in6_addr ipv6;
	uint8_t cidrv4, cidrv6;
	uint32_t leasetime, start, wg_errno;
	bool has_ipv4, has_ipv6;
	char *errmsg;
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

int handle_request(int fd, struct wg_dynamic_request *req,
		   unsigned char buf[RECV_BUFSIZE + MAX_LINESIZE],
		   size_t *remaining);
void free_wg_dynamic_request(struct wg_dynamic_request *req);
size_t serialize_request_ip(bool include_header, char *buf, size_t len,
			    struct wg_dynamic_request_ip *rip);
void print_to_buf(char *buf, size_t bufsize, size_t *offset, char *fmt, ...);
bool is_link_local(unsigned char *addr);
#endif
