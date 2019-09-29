/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include "common.h"
#include "dbg.h"
#include "khash.h"
#include "lease.h"
#include "netlink.h"
#include "radix-trie.h"
#include "random.h"

#define TIME_T_MAX (((time_t)1 << (sizeof(time_t) * CHAR_BIT - 2)) - 1) * 2 + 1

static struct ip_pool pool;
static time_t gexpires = TIME_T_MAX;
static bool synchronized;

KHASH_MAP_INIT_WGKEY(leaseht, struct wg_dynamic_lease *)
khash_t(leaseht) *leases_ht = NULL;

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

void leases_init(char *fname, struct mnl_socket *nlsock)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	char buf[MNL_NLMSG_HDRLEN + MNL_ALIGN(sizeof *rtm)];
	unsigned int seq;

	synchronized = false;
	leases_ht = kh_init(leaseht);
	ipp_init(&pool);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
	rtm->rtm_family = 0; /* both ipv4 and ipv6 */

	if (mnl_socket_sendto(nlsock, nlh, nlh->nlmsg_len) < 0)
		fatal("mnl_socket_sendto()");

	leases_update_pools(nlsock);
	synchronized = true;

	UNUSED(fname); /* TODO: open file and initialize from it */
}

void leases_free()
{
	if (leases_ht) {
		for (khint_t k = 0; k < kh_end(leases_ht); ++k)
			if (kh_exist(leases_ht, k))
				free((char *)kh_key(leases_ht, k));
	}
	kh_destroy(leaseht, leases_ht);

	ipp_free(&pool);
}

struct wg_dynamic_lease *new_lease(wg_key pubkey, uint32_t leasetime,
				   const struct in_addr *ipv4,
				   const struct in6_addr *ipv6,
				   struct wg_dynamic_lease *current)
{
	struct wg_dynamic_lease *lease;
	uint64_t index_l;
	uint32_t index, index_h;
	struct timespec tp;
	khiter_t k;
	int ret;
	bool wants_ipv4 = !ipv4 || ipv4->s_addr;
	bool wants_ipv6 = !ipv6 || !IN6_IS_ADDR_UNSPECIFIED(ipv6);
	bool ipv4_extended = false;
	bool ipv6_extended = false;

	char ipv4_asc[INET_ADDRSTRLEN], ipv6_asc[INET6_ADDRSTRLEN];
	wg_key_b64_string pubkey_asc;
	wg_key_to_base64(pubkey_asc, pubkey);

	lease = calloc(1, sizeof *lease);
	if (!lease)
		fatal("calloc()");

	/* Extend addresses explicitly asked for and which we already have. */
	if (lease_is_valid(current)) {
		if (current->ipv4.s_addr) {
			if (ipv4 && ipv4->s_addr == current->ipv4.s_addr) {
				inet_ntop(AF_INET, &current->ipv4, ipv4_asc,
					  INET_ADDRSTRLEN);
				debug("extending %s\n", ipv4_asc);

				memcpy(&lease->ipv4, &current->ipv4,
				       sizeof lease->ipv4);
				memset(&current->ipv4, 0, sizeof current->ipv4);
				ipv4_extended = true;
			}
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&current->ipv6)) {
			if (ipv6 && IN6_ARE_ADDR_EQUAL(ipv6, &current->ipv6)) {
				inet_ntop(AF_INET6, &current->ipv6, ipv6_asc,
					  INET6_ADDRSTRLEN);
				debug("extending %s\n", ipv6_asc);

				memcpy(&lease->ipv6, &current->ipv6,
				       sizeof lease->ipv6);
				memset(&current->ipv6, 0, sizeof current->ipv6);
				ipv6_extended = true;
			}
		}
	}

	if (ipv4)
		inet_ntop(AF_INET, ipv4, ipv4_asc, INET_ADDRSTRLEN); /* DEBUG */

	/* Allocate IPv4 if wanted and not already extended. */
	if (wants_ipv4 && !ipv4_extended) {
		if (!pool.total_ipv4) {
			debug("IPv4 pool empty\n");
		} else if (!ipv4) {
			index = random_bounded(pool.total_ipv4 - 1);

			debug("new_lease(v4): %u of %u\n", index,
			      pool.total_ipv4);

			ipp_addnth_v4(&pool, &lease->ipv4, index);
		} else {
			debug("wants %s: ", ipv4_asc);

			if (ipp_add_v4(&pool, ipv4, 32)) {
				debug("busy, possibly by us: %s\n",
				      lease_to_str(current));
			} else {
				debug("allocated\n");
				memcpy(&lease->ipv4, ipv4, sizeof lease->ipv4);
			}
		}
	}

	/* Release IPv4 if not wanted and not extended. */
	if (!wants_ipv4 && !ipv4_extended && ipv4 && ipv4->s_addr) {
		debug("releasing %s\n", ipv4_asc);

		if (ipp_del_v4(&pool, &lease->ipv4, 32))
			die("ipp_del_v4()\n");
		memset(&lease->ipv4, 0, sizeof lease->ipv4);
	}

	if (ipv6)
		inet_ntop(AF_INET6, ipv6, ipv6_asc,
			  INET6_ADDRSTRLEN); /* DEBUG */

	/* Allocate IPv6 if wanted and not already extended. */
	if (wants_ipv6 && !ipv6_extended) {
		if (!pool.totalh_ipv6 && !pool.totall_ipv6) {
			debug("IPv6 pool empty\n");
		} else if (!ipv6) {
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
			debug("wants %s: ", ipv6_asc);

			if (ipp_add_v6(&pool, ipv6, 128)) {
				debug("busy, possibly by us: %s\n",
				      lease_to_str(current));
			} else {
				debug("allocated\n");
				memcpy(&lease->ipv6, ipv6, sizeof lease->ipv6);
			}
		}
	}

	/* Release IPv6 if not wanted and not extended. */
	if (!wants_ipv6 && !ipv6_extended && ipv6 &&
	    !IN6_IS_ADDR_UNSPECIFIED(ipv6)) {
		debug("releasing %s\n", ipv6_asc);

		if (ipp_del_v6(&pool, &lease->ipv6, 128))
			die("ipp_del_v6()\n");
		memset(&lease->ipv6, 0, sizeof lease->ipv6);
	}

	/* Return NULL if we didn't get at least one address. */
	if (!lease->ipv4.s_addr && IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6)) {
		free(lease);
		return NULL;
	}

	/* Set leasetime. */
	if (clock_gettime(CLOCK_REALTIME, &tp))
		fatal("clock_gettime(CLOCK_REALTIME)");

	lease->start_real = tp.tv_sec;
	lease->start_mono = get_monotonic_time();
	lease->leasetime = leasetime;
	lease->next = NULL;

	/* Update hash table. */
	wg_key *pubcopy = malloc(sizeof(wg_key));
	if (!pubcopy)
		fatal("malloc()");

	memcpy(pubcopy, pubkey, sizeof(wg_key));
	k = kh_put(leaseht, leases_ht, *pubcopy, &ret);
	if (ret < 0) {
		fatal("kh_put()");
	} else if (ret == 0) {
		struct wg_dynamic_lease *parent = kh_value(leases_ht, k);
		while (parent->next)
			parent = parent->next;
		parent->next = lease;
	} else
		kh_value(leases_ht, k) = lease;
	debug("new lease: %s\n", lease_to_str(lease));

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

bool release_lease(struct wg_dynamic_lease *lease, wg_key pubkey)
{
	struct wg_dynamic_lease *first, *iter;
	khiter_t k;

	if (!lease)
		return true;

	k = kh_get(leaseht, leases_ht, pubkey);
	if (k == kh_end(leases_ht))
		return true;
	first = kh_val(leases_ht, k);

	for (iter = first; iter; iter = iter->next)
		if (iter == lease)
			break;
	if (iter != lease)
		return true;

	debug("Releasing lease: %s\n", lease_to_str(lease));
	if (lease->ipv4.s_addr && ipp_del_v4(&pool, &lease->ipv4, 32)) {
		debug("Unable to delete IPv4 address from pool: %s\n",
		      lease_to_str(lease));
		die("ipp_del_v4()\n");
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6) &&
	    ipp_del_v6(&pool, &lease->ipv6, 128)) {
		debug("Unable to delete IPv6 address from pool: %s\n",
		      lease_to_str(lease));
		die("ipp_del_v6()\n");
	}

	if (lease == first) {
		if (lease->next) {
			kh_val(leases_ht, k) = lease->next;
		} else {
			kh_del(leaseht, leases_ht, k);
		}
	} else {
		BUG_ON(first->next == NULL);
		first->next = NULL;
	}
	free(lease);

	return false;
}

int leases_refresh(void (*update_cb)(wg_key *, int))
{
	wg_key updates[WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 };
	time_t cur_time = get_monotonic_time();

	if (cur_time < gexpires)
		return MIN(INT_MAX / 1000, gexpires - cur_time);

	gexpires = TIME_T_MAX;

	int i = 0;
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

				memcpy(updates[i], kh_key(leases_ht, k),
				       sizeof(wg_key));
				{
					wg_key_b64_string pubkey_asc;
					wg_key_to_base64(pubkey_asc,
							 updates[i]);
					debug("Peer losing its lease: %s\n",
					      pubkey_asc);
				}
				i++;
				if (i == WG_DYNAMIC_LEASE_CHUNKSIZE) {
					update_cb(updates, i);
					i = 0;
					memset(updates, 0, sizeof updates);
				}

				tmp = *pp;
				*pp = (*pp)->next;
				free(tmp);
			} else {
				if (expires < gexpires)
					gexpires = expires;

				pp = &(*pp)->next;
			}
		}

		if (i)
			update_cb(updates, i);

		if (!kh_val(leases_ht, k)) {
			free((char *)kh_key(leases_ht, k));
			kh_del(leaseht, leases_ht, k);
		}
	}

	return MIN(INT_MAX / 1000, gexpires - cur_time);
}

static int data_ipv4_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	switch (type) {
	case RTA_DST:
	case RTA_GATEWAY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			log_err("mnl_attr_validate: %s\n", strerror(errno));
			return MNL_CB_ERROR;
		}
		break;
	default:
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_ipv6_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	switch (type) {
	case RTA_DST:
	case RTA_GATEWAY:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
				       sizeof(struct in6_addr)) < 0) {
			log_err("mnl_attr_validate: %s\n", strerror(errno));
			return MNL_CB_ERROR;
		}
		break;
	default:
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int process_nlpacket_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RTA_MAX + 1] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	UNUSED(data);

	if (rm->rtm_family == AF_INET)
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv4_attr_cb, tb);
	else if (rm->rtm_family == AF_INET6)
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv6_attr_cb, tb);

	if (tb[RTA_GATEWAY])
		return MNL_CB_OK;

	if (!tb[RTA_DST]) {
		debug("Netlink packet without RTA_DST, ignoring\n");
		return MNL_CB_OK;
	}

	void *addr = mnl_attr_get_payload(tb[RTA_DST]);
	if (rm->rtm_family == AF_INET6 &&
	    (is_link_local(addr) || IN6_IS_ADDR_MULTICAST(addr)))
		return MNL_CB_OK;

	if (nlh->nlmsg_type == RTM_NEWROUTE) {
		if (rm->rtm_family == AF_INET) {
			if (ipp_addpool_v4(&pool, addr, rm->rtm_dst_len))
				die("ipp_addpool_v4()\n");
		} else if (rm->rtm_family == AF_INET6) {
			if (ipp_addpool_v6(&pool, addr, rm->rtm_dst_len))
				die("ipp_addpool_v6()\n");
		}
	} else if (nlh->nlmsg_type == RTM_DELROUTE) {
		if (rm->rtm_family == AF_INET) {
			if (ipp_removepool_v4(&pool, addr) && synchronized)
				die("ipp_removepool_v4()\n");
		} else if (rm->rtm_family == AF_INET6) {
			if (ipp_removepool_v6(&pool, addr) && synchronized)
				die("ipp_removepool_v6()\n");
		}
	}

	return MNL_CB_OK;
}

void leases_update_pools(struct mnl_socket *nlsock)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	while ((ret = mnl_socket_recvfrom(nlsock, buf, sizeof buf)) > 0) {
		if (mnl_cb_run(buf, ret, 0, 0, process_nlpacket_cb, NULL) == -1)
			fatal("mnl_cb_run()");
	}

	if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
		fatal("mnl_socket_recvfrom()");
}

bool lease_is_valid(const struct wg_dynamic_lease *lease)
{
	if (!lease)
		return false;

	if (get_monotonic_time() >= lease->start_mono + lease->leasetime)
		return false;

	return true;
}

#ifdef DEBUG
char *lease_to_str(const struct wg_dynamic_lease *l)
{
	static char buf[4096];
	char v4[INET_ADDRSTRLEN], v6[INET6_ADDRSTRLEN];

	if (!l)
		return "(null)";

	inet_ntop(AF_INET, &l->ipv4, v4, sizeof v4);
	inet_ntop(AF_INET6, &l->ipv6, v6, sizeof v6);
	snprintf(buf, sizeof buf, "(%p) %s [%s]", l, v4, v6);
	return buf;
}
#endif
