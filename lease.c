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
#include <string.h>
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

static const char *devname = NULL;
static int ifindex = 0;
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

void leases_init(const char *device_name, int interface_index, char *fname,
		 struct mnl_socket *nlsock)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	char buf[MNL_NLMSG_HDRLEN + MNL_ALIGN(sizeof *rtm)];
	unsigned int seq;

	devname = device_name;
	ifindex = interface_index;

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

struct allowedips_update {
	wg_key peer_pubkey;
	struct wg_dynamic_lease *lease;
};

static char *updates_to_str(const struct allowedips_update *u)
{
	static char buf[4096];
	wg_key_b64_string pubkey_asc;
	char ll[INET6_ADDRSTRLEN] = { 0 }, v4[INET_ADDRSTRLEN] = { 0 },
	     v6[INET6_ADDRSTRLEN] = { 0 };

	if (!u)
		return "(null)";

	wg_key_to_base64(pubkey_asc, u->peer_pubkey);
	inet_ntop(AF_INET, &u->lease->ipv4, v4, sizeof v4);
	inet_ntop(AF_INET6, &u->lease->ipv6, v6, sizeof v6);
	inet_ntop(AF_INET6, &u->lease->lladdr, ll, sizeof ll);
	snprintf(buf, sizeof buf, "(%p) [%s] %s [%s]", u->lease, ll, v4, v6);

	return buf;
}

static void update_allowed_ips_bulk(const struct allowedips_update *updates,
				    int nupdates)
{
	wg_peer peers[WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 };
	wg_allowedip allowedips[3 * WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 };
	wg_device dev = { 0 };
	wg_peer **pp = &dev.first_peer;

	BUG_ON(nupdates > WG_DYNAMIC_LEASE_CHUNKSIZE);
	for (int i = 0; i < nupdates; i++) {
		debug("setting allowedips for %s\n",
		      updates_to_str(&updates[i]));

		peers[i].flags |= WGPEER_REPLACE_ALLOWEDIPS;
		memcpy(peers[i].public_key, updates[i].peer_pubkey,
		       sizeof(wg_key));
		wg_allowedip **aipp = &peers[i].first_allowedip;

		if (!IN6_IS_ADDR_UNSPECIFIED(&updates[i].lease->lladdr)) {
			allowedips[i * 3 + 0] = (wg_allowedip){
				.family = AF_INET6,
				.cidr = 128,
				.ip6 = updates[i].lease->lladdr,
			};
			*aipp = &allowedips[i * 3 + 0];
			aipp = &allowedips[i * 3 + 0].next_allowedip;
		}
		if (updates[i].lease->ipv4.s_addr) {
			allowedips[i * 3 + 1] = (wg_allowedip){
				.family = AF_INET,
				.cidr = 32,
				.ip4 = updates[i].lease->ipv4,
			};
			*aipp = &allowedips[i * 3 + 1];
			aipp = &allowedips[i * 3 + 1].next_allowedip;
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&updates[i].lease->ipv6)) {
			allowedips[i * 3 + 2] = (wg_allowedip){
				.family = AF_INET6,
				.cidr = 128,
				.ip6 = updates[i].lease->ipv6,
			};
			*aipp = &allowedips[i * 3 + 2];
		}

		*pp = &peers[i];
		pp = &peers[i].next_peer;
	}

	strncpy(dev.name, devname, sizeof(dev.name) - 1);
	if (wg_set_device(&dev))
		fatal("wg_set_device()");
}

/* Updates allowedips for peer_pubkey, adding what's in lease
 * (including lladdr), removing all others.
 */
static void update_allowed_ips(wg_key peer_pubkey,
			       struct wg_dynamic_lease *lease)
{
	struct allowedips_update update;

	memcpy(update.peer_pubkey, peer_pubkey, sizeof(wg_key));
	update.lease = lease;

	update_allowed_ips_bulk(&update, 1);
}

struct wg_dynamic_lease *set_lease(wg_key pubkey, uint32_t leasetime,
				   const struct in6_addr *lladdr,
				   const struct in_addr *ipv4,
				   const struct in6_addr *ipv6)
{
	bool delete_ipv4 = ipv4 && !ipv4->s_addr;
	bool delete_ipv6 = ipv6 && IN6_IS_ADDR_UNSPECIFIED(ipv6);
	struct wg_dynamic_lease *lease;
	struct timespec tp;
	khiter_t k;
	int kh_ret;

	lease = get_leases(pubkey);
	if (!lease) {
		lease = calloc(1, sizeof(*lease));
		lease->lladdr = *lladdr;
	}

	if (lease->ipv4.s_addr &&
	    (delete_ipv4 ||
	     (ipv4 && memcmp(&lease->ipv4, ipv4, sizeof(*ipv4))))) {
		if (ipp_del_v4(&ipns, &lease->ipv4, 32))
			die("ipp_del_v4()\n");
		memset(&lease->ipv4, 0, sizeof(lease->ipv4));
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6) &&
	    (delete_ipv6 ||
	     (ipv6 && memcmp(&lease->ipv6, ipv6, sizeof(*ipv6))))) {
		if (ipp_del_v6(&ipns, &lease->ipv6, 128))
			die("ipp_del_v6()\n");
		memset(&lease->ipv6, 0, sizeof(lease->ipv6));
	}

	if (!ipv4) { /* Wants random IPv4 address? */
		if (!ipns.total_ipv4) {
			debug("IPv4 pool empty\n");
			memset(&lease->ipv4, 0, sizeof(lease->ipv4));
		} else {
			uint32_t index = random_bounded(ipns.total_ipv4);
			debug("new_lease(v4): %u of %ju\n", index,
			      ipns.total_ipv4);
			ipp_addnth_v4(&ipns, &lease->ipv4, index);
		}
	} else if (ipv4->s_addr) {
		if (!memcmp(&lease->ipv4, ipv4, sizeof(*ipv4))) {
			debug("extending(v4)\n");
		} else {
			if (!ipp_add_v4(&ipns, ipv4, 32)) {
				lease->ipv4 = *ipv4;
			} else {
				memset(&lease->ipv4, 0, sizeof(lease->ipv4));
			}
		}
	}

	if (!ipv6) { /* Wants random IPv6 address? */
		if (!ipns.totalh_ipv6 && !ipns.totall_ipv6) {
			debug("IPv6 pool empty\n");
			memset(&lease->ipv6, 0, sizeof(lease->ipv6));
		} else {
			uint64_t index_l;
			uint32_t index_h;
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
		}
	} else if (!IN6_IS_ADDR_UNSPECIFIED(ipv6)) {
		if (!memcmp(&lease->ipv6, ipv6, sizeof(*ipv6))) {
			debug("extending(v6)\n");
		} else {
			if (!ipp_add_v6(&ipns, ipv6, 128)) {
				lease->ipv6 = *ipv6;
			} else {
				memset(&lease->ipv6, 0, sizeof(lease->ipv6));
			}
		}
	}

	update_allowed_ips(pubkey, lease);

	if (clock_gettime(CLOCK_REALTIME, &tp))
		fatal("clock_gettime(CLOCK_REALTIME)");
	lease->start_real = tp.tv_sec;
	lease->start_mono = get_monotonic_time();
	lease->leasetime = leasetime;

	wg_key *pubcopy = malloc(sizeof(wg_key));
	if (!pubcopy)
		fatal("malloc()");

	memcpy(pubcopy, pubkey, sizeof(wg_key));
	k = kh_put(leaseht, leases_ht, *pubcopy, &kh_ret);

	if (kh_ret < 0)
		die("kh_put(): %d\n", kh_ret);

	kh_value(leases_ht, k) = lease;

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

int leases_refresh()
{
	time_t cur_time = get_monotonic_time();
	struct allowedips_update updates[WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 };

	if (cur_time < gexpires)
		return MIN(INT_MAX / 1000, gexpires - cur_time);

	gexpires = TIME_T_MAX;

	int i = 0;
	for (khint_t k = kh_begin(leases_ht); k != kh_end(leases_ht); ++k) {
		if (!kh_exist(leases_ht, k))
			continue;
		struct wg_dynamic_lease *lease = kh_val(leases_ht, k);
		BUG_ON(!lease);
		time_t expires = lease->start_mono + lease->leasetime;
		if (cur_time >= expires) {
			if (lease->ipv4.s_addr)
				ipp_del_v4(&ipns, &lease->ipv4, 32);

			if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6))
				ipp_del_v6(&ipns, &lease->ipv6, 128);

			memcpy(updates[i].peer_pubkey, kh_key(leases_ht, k),
			       sizeof(wg_key));
			updates[i].lease = lease;

			wg_key_b64_string pubkey_asc;
			wg_key_to_base64(pubkey_asc, updates[i].peer_pubkey);
			debug("Peer losing its lease: %s\n", pubkey_asc);

			++i;
			if (i == WG_DYNAMIC_LEASE_CHUNKSIZE) {
				update_allowed_ips_bulk(updates, i);
				while (i)
					free(updates[--i].lease);
				memset(updates, 0, sizeof updates);
			}

			free((char *)kh_key(leases_ht, k));
			kh_del(leaseht, leases_ht, k);
		} else {
			if (expires < gexpires)
				gexpires = expires;
		}
	}

	if (i) {
		update_allowed_ips_bulk(updates, i);
		while (i)
			free(updates[--i].lease);
	}

	return MIN(INT_MAX / 1000, gexpires - cur_time);
}

static int data_ipv4_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	switch (type) {
	case RTA_DST:
	case RTA_OIF:
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
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
				       sizeof(struct in6_addr)) < 0) {
			log_err("mnl_attr_validate2: %s\n", strerror(errno));
			return MNL_CB_ERROR;
		}
		break;
	case RTA_OIF:
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

static int process_nlpacket_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RTA_MAX + 1] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	uint32_t ifindex;

	BUG_ON(!data);
	ifindex = *((int *)data);

	if (rm->rtm_family == AF_INET)
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv4_attr_cb, tb);
	else if (rm->rtm_family == AF_INET6)
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv6_attr_cb, tb);

	if (!tb[RTA_OIF] || mnl_attr_get_u32(tb[RTA_OIF]) != ifindex) {
		debug("ignoring interface %u (want %u)\n",
		      tb[RTA_OIF] ? mnl_attr_get_u32(tb[RTA_OIF]) : 0, ifindex);
		return MNL_CB_OK;
	}

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
			if (ipp_removepool_v4(&ipns, addr, rm->rtm_dst_len) &&
			    synchronized)
				die("ipp_removepool_v4()\n");
		} else if (rm->rtm_family == AF_INET6) {
			if (ipp_removepool_v6(&ipns, addr, rm->rtm_dst_len) &&
			    synchronized)
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
		if (mnl_cb_run(buf, ret, 0, 0, process_nlpacket_cb,
			       (void *)&ifindex) == -1)
			fatal("mnl_cb_run()");
	}

	if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
		fatal("mnl_socket_recvfrom()");
}
