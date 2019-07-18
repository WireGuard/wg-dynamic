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

#define TIME_T_MAX (((time_t)1 << (sizeof(time_t) * CHAR_BIT - 2)) - 1) * 2 + 1

static struct ip_pool pool;
static time_t gexpires = TIME_T_MAX;

KHASH_MAP_INIT_WGKEY(leaseht, struct wg_dynamic_lease *)
khash_t(leaseht) * leases_ht;

static time_t get_monotonic_time()
{
	struct timespec monotime;
#ifdef __linux__
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

	ipp_init(&pool);

	/* TODO: initialize pool properly from routes */
	struct in_addr pool1_v4, pool2_v4;
	struct in6_addr pool1_v6, pool2_v6;
	inet_pton(AF_INET, "192.168.4.0", &pool1_v4);
	inet_pton(AF_INET, "192.168.73.0", &pool2_v4);
	inet_pton(AF_INET6, "2001:db8:1234::", &pool1_v6);
	inet_pton(AF_INET6, "2001:db8:7777::", &pool2_v6);

	ipp_addpool_v4(&pool, &pool1_v4, 28);
	ipp_addpool_v4(&pool, &pool2_v4, 27);
	ipp_addpool_v6(&pool, &pool1_v6, 124);
	ipp_addpool_v6(&pool, &pool2_v6, 124);
}

void leases_free()
{
	kh_destroy(leaseht, leases_ht);
	ipp_free(&pool);
}

struct wg_dynamic_lease *new_lease(wg_key pubkey, uint32_t leasetime,
				   struct in_addr *ipv4, struct in6_addr *ipv6)
{
	struct wg_dynamic_lease *lease, *parent;
	uint64_t index_l;
	uint32_t index, index_h;
	struct timespec tp;
	khiter_t k;
	int ret;
	bool wants_ipv4 = !ipv4 || ipv4->s_addr;
	bool wants_ipv6 = !ipv6 || !IN6_IS_ADDR_UNSPECIFIED(ipv6);

	lease = malloc(sizeof *lease);
	if (!lease)
		fatal("malloc()");

	if (wants_ipv4 && !pool.total_ipv4)
		return NULL; /* no ipv4 addresses available */

	if (wants_ipv6 && !pool.totalh_ipv6 && !pool.totall_ipv6)
		return NULL; /* no ipv6 addresses available */

	if (wants_ipv4) {
		if (!ipv4) {
			index = random_bounded(pool.total_ipv4 - 1);
			debug("new_lease(v4): %u of %u\n", index,
			      pool.total_ipv4);

			ipp_addnth_v4(&pool, &lease->ipv4, index);
		} else {
			if (ipp_add_v4(&pool, ipv4, 32))
				return NULL;

			memcpy(&lease->ipv4, ipv4, sizeof *ipv4);
		}
	}

	if (wants_ipv6) {
		if (!ipv6) {
			if (pool.totalh_ipv6 > 0) {
				index_l = random_bounded(UINT64_MAX);
				index_h = random_bounded(pool.totalh_ipv6 - 1);
			} else {
				index_l = random_bounded(pool.totall_ipv6 - 1);
				index_h = 0;
			}

			debug("new_lease(v6): %u:%ju of %u:%ju\n", index_h,
			      index_l, pool.totalh_ipv6, pool.totall_ipv6);
			ipp_addnth_v6(&pool, &lease->ipv6, index_l, index_h);
		} else {
			if (ipp_add_v6(&pool, ipv6, 128)) {
				if (!ipv4 || ipv4->s_addr)
					ipp_del_v4(&pool, ipv4, 32);

				return NULL;
			}

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
		fatal("kh_put()");
	} else if (ret == 0) {
		parent = kh_value(leases_ht, k);
		while (parent->next)
			parent = parent->next;

		parent->next = lease;
	} else {
		kh_value(leases_ht, k) = lease;
	}

	if (lease->start_mono + lease->leasetime < gexpires)
		gexpires = lease->start_mono + lease->leasetime;

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

bool extend_lease(struct wg_dynamic_lease *lease, uint32_t leasetime)
{
	UNUSED(lease);
	UNUSED(leasetime);
	return false;
}

int leases_refresh()
{
	time_t cur_time = get_monotonic_time();

	if (cur_time < gexpires)
		return MIN(INT_MAX / 1000, gexpires - cur_time);

	gexpires = TIME_T_MAX;

	for (khint_t k = kh_begin(leases_ht); k != kh_end(leases_ht); ++k) {
		if (!kh_exist(leases_ht, k))
			continue;

		struct wg_dynamic_lease **pp = &kh_val(leases_ht, k), *tmp;
		while (*pp) {
			struct in_addr *ipv4 = &(*pp)->ipv4;
			struct in6_addr *ipv6 = &(*pp)->ipv6;
			time_t expires = (*pp)->start_mono + (*pp)->leasetime;
			if (cur_time >= expires) {
				if (ipv4->s_addr)
					ipp_del_v4(&pool, ipv4, 32);

				if (!IN6_IS_ADDR_UNSPECIFIED(ipv6))
					ipp_del_v6(&pool, ipv6, 128);

				tmp = *pp;
				*pp = (*pp)->next;
				free(tmp);
			} else {
				if (expires < gexpires)
					gexpires = expires;

				pp = &(*pp)->next;
			}
		}

		if (!kh_val(leases_ht, k))
			kh_del(leaseht, leases_ht, k);
	}

	return MIN(INT_MAX / 1000, gexpires - cur_time);
}

void leases_update_pools(int fd)
{
	UNUSED(fd);
}
