/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __LEASE_H__
#define __LEASE_H__

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "common.h"
#include "netlink.h"

struct wg_dynamic_lease {
	time_t start_real;
	time_t start_mono;
	uint32_t leasetime; /* in seconds */
	struct in_addr ipv4;
	struct in6_addr ipv6;
	struct wg_dynamic_lease *next;
};

/*
 * Initializes internal state, reads leases from fname.
 */
void leases_init(char *fname);

/*
 * Frees everything, closes file.
 */
void leases_free();

/*
 * Creates a new lease and returns a pointer to it, or NULL if either we ran out
 * of assignable IPs or the requested IP is already taken.
 * expires contains the (monotonic) timestamp after which the next lease,
 * possibly the newly created one, will expire.
 */
struct wg_dynamic_lease *new_lease(wg_key pubkey, uint32_t leasetime,
				   struct in_addr *ipv4, struct in6_addr *ipv6,
				   time_t *expires);

/*
 * Returns all leases belonging to pubkey, or NULL if there are none.
 */
struct wg_dynamic_lease *get_leases(wg_key pubkey);

/*
 * Extend the lease to be leasetime long again. Returns true on error, or false
 * otherwise. expires behaves exactly as in new_lease().
 */
bool extend_lease(struct wg_dynamic_lease *lease, uint32_t leasetime,
		  time_t *expires);

/*
 * Refreshes all leases, meaning expired ones will be removed. Returns the
 * expiration timestamp of the lease that will expire next.
 */
time_t leases_refresh();

/*
 * Updates all pools with information from the netlink file descriptor fd.
 */
void leases_update_pools(int fd);

#endif
