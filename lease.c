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

static struct ipns ipns;
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
	ipp_init(&ipns);

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

	ipp_free(&ipns);
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

	if (wants_ipv4 && !ipns.total_ipv4)
		return NULL; /* no ipv4 addresses available */

	if (wants_ipv6 && !ipns.totalh_ipv6 && !ipns.totall_ipv6)
		return NULL; /* no ipv6 addresses available */

	if (wants_ipv4) {
		if (!ipv4) {
			index = random_bounded(ipns.total_ipv4);
			debug("new_lease(v4): %u of %ju\n", index,
			      ipns.total_ipv4);

			ipp_addnth_v4(&ipns, &lease->ipv4, index);
		} else {
			if (ipp_add_v4(&ipns, ipv4, 32))
				return NULL;

			memcpy(&lease->ipv4, ipv4, sizeof *ipv4);
		}
	}

	if (wants_ipv6) {
		if (!ipv6) {
			if (ipns.totalh_ipv6 > 0) {
				index_l = random_u64();
				index_h = random_bounded(ipns.totalh_ipv6);
			} else {
				index_l = random_bounded(ipns.totall_ipv6);
				index_h = 0;
			}

			debug("new_lease(v6): %u:%ju of %u:%ju\n", index_h,
			      index_l, ipns.totalh_ipv6, ipns.totall_ipv6);
			ipp_addnth_v6(&ipns, &lease->ipv6, index_l, index_h);
		} else {
			if (ipp_add_v6(&ipns, ipv6, 128)) {
				if (!ipv4 || ipv4->s_addr)
					ipp_del_v4(&ipns, ipv4, 32);

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

	wg_key *pubcopy = malloc(sizeof(wg_key));
	if (!pubcopy)
		fatal("malloc()");

	memcpy(pubcopy, pubkey, sizeof(wg_key));
	k = kh_put(leaseht, leases_ht, *pubcopy, &ret);
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
					ipp_del_v4(&ipns, ipv4, 32);

				if (!IN6_IS_ADDR_UNSPECIFIED(ipv6))
					ipp_del_v6(&ipns, ipv6, 128);

				tmp = *pp;
				*pp = (*pp)->next;
				free(tmp);
			} else {
				if (expires < gexpires)
					gexpires = expires;

				pp = &(*pp)->next;
			}
		}

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
			if (ipp_addpool_v4(&ipns, addr, rm->rtm_dst_len))
				die("ipp_addpool_v4()\n");
		} else if (rm->rtm_family == AF_INET6) {
			if (ipp_addpool_v6(&ipns, addr, rm->rtm_dst_len))
				die("ipp_addpool_v6()\n");
		}
	} else if (nlh->nlmsg_type == RTM_DELROUTE) {
		if (rm->rtm_family == AF_INET) {
			if (ipp_removepool_v4(&ipns, addr) && synchronized)
				die("ipp_removepool_v4()\n");
		} else if (rm->rtm_family == AF_INET6) {
			if (ipp_removepool_v6(&ipns, addr) && synchronized)
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
