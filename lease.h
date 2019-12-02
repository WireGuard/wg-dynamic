/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __LEASE_H__
#define __LEASE_H__

#include <stdint.h>
#include <sys/socket.h>
#include <libmnl/libmnl.h>

#include "common.h"
#include "netlink.h"

#define WG_DYNAMIC_LEASE_CHUNKSIZE 256

struct wg_dynamic_lease {
	time_t start_real;
	time_t start_mono;
	uint32_t leasetime; /* in seconds */
	struct in_addr ipv4;
	struct in6_addr ipv6;
	struct in6_addr lladdr;
};

/*
 * Initializes internal state, retrieves routes from nlsock and reads leases
 * from fname.
 */
void leases_init(const char *device_name, int interface_index, char *fname,
		 struct mnl_socket *nlsock);

/*
 * Frees everything, closes file.
 */
void leases_free();

/*
 * Creates a new lease and returns a pointer to it, or NULL if either
 * we ran out of assignable IPs or the requested IP's are already
 * taken. Frees currently held lease, if any. Updates allowedips for
 * the peer.
 */
struct wg_dynamic_lease *set_lease(wg_key pubkey, uint32_t leasetime,
				   const struct in6_addr *lladdr,
				   const struct in_addr *ipv4,
				   const struct in6_addr *ipv6);

/*
 * Returns all leases belonging to pubkey, or NULL if there are none.
 */
struct wg_dynamic_lease *get_leases(wg_key pubkey);

/* Refreshes all leases, meaning expired ones will be removed. Returns the
 * amount of seconds until the next lease will expire, or at most INT_MAX/1000.
 */
int leases_refresh();

/*
 * Updates all pools with information from the mnl socket nlsock.
 */
void leases_update_pools(struct mnl_socket *nlsock);

#endif
