#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include "dbg.h"
#include "khash.h"
#include "lease.h"
#include "netlink.h"
#include "radix-trie.h"
#include "random.h"

static struct ip_pool pools;
static time_t gexpires;

KHASH_MAP_INIT_WGKEY(leaseht, struct wg_dynamic_lease *)
khash_t(leaseht) * leases_ht;

static uint64_t totall_ipv6;
static uint32_t totalh_ipv6, total_ipv4;

static time_t get_monotonic_time()
{
	struct timespec monotime;
#ifdef __linux__
	/* in linux 4.17, CLOCK_MONOTONIC was changed to be like CLOCK_BOOTTIME,
	 * see https://git.kernel.org/torvalds/c/d6ed449, but glibc's wrapper
	 * seems to still have the old behavior
	 */
	if (clock_gettime(CLOCK_BOOTTIME, &monotime))
		fatal("clock_gettime(CLOCK_BOOTTIME)");
#else
	/* CLOCK_MONOTONIC works on openbsd, but apparently not (yet) on
	 * freebsd: https://lists.freebsd.org/pipermail/freebsd-hackers/2018-June/052899.html
	 */
	if (clock_gettime(CLOCK_MONOTONIC, &monotime))
		fatal("clock_gettime(CLOCK_MONOTONIC)");

#endif
	/* TODO: what about darwin? */

	return monotime.tv_sec;
}

void leases_init(char *fname)
{
	UNUSED(fname); /* TODO: open file and initialize from it */

	leases_ht = kh_init(leaseht);

	ipp_init(&pools);

	/* TODO: initialize pools properly from routes */
	struct in_addr pool1_v4, pool2_v4;
	struct in6_addr pool1_v6, pool2_v6;
	inet_pton(AF_INET, "192.168.4.0", &pool1_v4);
	inet_pton(AF_INET, "192.168.73.0", &pool2_v4);
	inet_pton(AF_INET6, "2001:db8:1234::", &pool1_v6);
	inet_pton(AF_INET6, "2001:db8:7777::", &pool2_v6);

	ipp_addpool_v4(&pools, &pool1_v4, 28);
	ipp_addpool_v4(&pools, &pool2_v4, 27);
	ipp_addpool_v6(&pools, &pool1_v6, 124);
	ipp_addpool_v6(&pools, &pool2_v6, 124);

	total_ipv4 = ipp_gettotal_v4(&pools);
	totall_ipv6 = ipp_gettotal_v6(&pools, &totalh_ipv6);
}

void leases_free()
{
	kh_destroy(leaseht, leases_ht);
	ipp_free(&pools);
}

struct wg_dynamic_lease *new_lease(wg_key pubkey, uint32_t leasetime,
				   struct in_addr *ipv4, struct in6_addr *ipv6,
				   time_t *expires)
{
	struct wg_dynamic_lease *lease, *parent;
	uint64_t index_low;
	uint32_t index, index_high;
	struct timespec tp;
	khiter_t k;
	int ret;

	lease = malloc(sizeof *lease);
	if (!lease)
		fatal("malloc()");

	if (!ipv4 || ipv4->s_addr) {
		if (total_ipv4 == 0)
			return NULL;

		--total_ipv4;
	}
	if (!ipv6 || !IN6_IS_ADDR_UNSPECIFIED(ipv6)) {
		if (totalh_ipv6 == 0 && totall_ipv6 == 0) {
			if (!ipv4 || ipv4->s_addr)
				++total_ipv4;

			return NULL;
		}

		if (totall_ipv6 == 0)
			--totalh_ipv6;

		--totall_ipv6;
	}

	if (!ipv4 || ipv4->s_addr) {
		if (!ipv4) {
			index = random_bounded(total_ipv4);
			debug("new_lease(v4): %u of %u\n", index, total_ipv4);
			ipp_addnth_v4(&pools, &lease->ipv4, index);
		} else {
			if (ipp_add_v4(&pools, ipv4, 32))
				return NULL;
			memcpy(&lease->ipv4, ipv4, sizeof *ipv4);
		}
	}
	if (!ipv6 || !IN6_IS_ADDR_UNSPECIFIED(ipv6)) {
		if (!ipv6) {
			if (totalh_ipv6 > 0) {
				index_low = random_bounded(UINT64_MAX);
				if (totall_ipv6 - index_low > totall_ipv6)
					--totalh_ipv6;

				index_high = random_bounded(totalh_ipv6);
			} else {
				index_low = random_bounded(totall_ipv6);
				index_high = 0;
			}
			debug("new_lease(v6): %u:%ju of %u:%ju\n", index_high,
			      index_low, totalh_ipv6, totall_ipv6);

			ipp_addnth_v6(&pools, &lease->ipv6, index_low,
				      index_high);
		} else {
			if (ipp_add_v6(&pools, ipv6, 128))
				return NULL; /* TODO: free ipv4 addr */
			memcpy(&lease->ipv6, ipv6, sizeof *ipv6);
		}
	}

	if (clock_gettime(CLOCK_REALTIME, &tp))
		fatal("clock_gettime(CLOCK_REALTIME)");

	lease->start_real = tp.tv_sec;
	lease->start_mono = get_monotonic_time();
	lease->leasetime = leasetime;
	lease->next = NULL;

	k = kh_put(leaseht, leases_ht, pubkey, &ret);
	if (ret < 0) {
		die("kh_put()");
	} else if (ret == 0) {
		parent = kh_value(leases_ht, k);
		while (parent->next)
			parent = parent->next;

		parent->next = lease;
	} else {
		kh_value(leases_ht, k) = lease;
	}

	if (lease->start_mono < gexpires)
		gexpires = lease->start_mono;

	*expires = gexpires;

	/* TODO: add record to file */

	return lease;
}

struct wg_dynamic_lease *get_leases(wg_key pubkey)
{
	khiter_t k = kh_get(leaseht, leases_ht, pubkey);

	if (k == kh_end(leases_ht))
		return NULL;
	else
		return kh_val(leases_ht, k);
}

bool extend_lease(struct wg_dynamic_lease *lease, uint32_t leasetime,
		  time_t *expires)
{
	UNUSED(lease);
	UNUSED(leasetime);
	UNUSED(expires);
	return false;
}

time_t leases_refresh()
{
	/* TODO: remove expired leases */
	return gexpires;
}

void leases_update_pools(int fd)
{
	UNUSED(fd);
}
