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
	struct wg_dynamic_lease *next;
};

/*
 * Initializes internal state, retrieves routes from nlsock and reads leases
 * from fname.
 */
void leases_init(char *fname, struct mnl_socket *nlsock);

/*
 * Frees everything, closes file.
 */
void leases_free();

/*
 * Creates a new lease and returns a pointer to it, or NULL if either we ran out
 * of assignable IPs or if requested IP(s) are already taken.
 */
struct wg_dynamic_lease *new_lease(wg_key pubkey, uint32_t leasetime,
				   const struct in_addr *ipv4,
				   const struct in6_addr *ipv6,
				   struct wg_dynamic_lease *current);


/*
 * Returns all leases belonging to pubkey, or NULL if there are none.
 */
struct wg_dynamic_lease *get_leases(wg_key pubkey);

/*
 * Release the lease and free allocated memory.
 */
bool release_lease(struct wg_dynamic_lease *lease, wg_key pubkey);

/*
 * Refreshes all leases, meaning expired ones will be removed. Returns the
 * amount of seconds until the next lease will expire, or at most INT_MAX/1000.
 */
int leases_refresh(void (*update_cb)(wg_key *, int));

/*
 * Updates all pools with information from the mnl socket nlsock.
 */
void leases_update_pools(struct mnl_socket *nlsock);

/*
 * Return true if lease is !NULL and has not expired.
 */
bool lease_is_valid(const struct wg_dynamic_lease *lease);

#ifdef DEBUG
char *lease_to_str(const struct wg_dynamic_lease *l);
#endif

#endif
