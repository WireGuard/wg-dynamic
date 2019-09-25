/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <time.h>

#include "dbg.h"
#include "common.h"

struct mnl_cb_data {
	uint32_t ifindex;
	struct wg_combined_ip *ip;
	bool ip_found;
	bool duplicate;
};

static struct mnl_socket *nl = NULL;

static int iface_update(uint16_t cmd, uint16_t flags, uint32_t ifindex,
			const uint8_t *addr, uint8_t cidr, sa_family_t family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	unsigned int seq, portid;
	struct ifaddrmsg *ifaddr;
	int ret;

	portid = mnl_socket_get_portid(nl);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nlh->nlmsg_seq = seq = time(NULL);
	ifaddr = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifaddr->ifa_family = family;
	ifaddr->ifa_prefixlen = cidr;
	ifaddr->ifa_scope = RT_SCOPE_UNIVERSE;
	ifaddr->ifa_index = ifindex;
	mnl_attr_put(nlh, IFA_LOCAL, family == AF_INET ? 4 : 16, addr);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return -1;

	do {
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	} while (ret > 0);

	if (ret == -1)
		return -1;

	return 0;
}

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFA_ADDRESS:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[IFA_MAX + 1] = {};
	struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct mnl_cb_data *cb_data = (struct mnl_cb_data *)data;

	if (ifa->ifa_index != cb_data->ifindex)
		return MNL_CB_OK;

	if (ifa->ifa_scope != RT_SCOPE_LINK)
		return MNL_CB_OK;

	mnl_attr_parse(nlh, sizeof(*ifa), data_attr_cb, tb);

	if (!tb[IFA_ADDRESS])
		return MNL_CB_OK;

	if (cb_data->ip_found) {
		cb_data->duplicate = true;
		return MNL_CB_OK;
	}

	memcpy(cb_data->ip, mnl_attr_get_payload(tb[IFA_ADDRESS]),
	       ifa->ifa_family == AF_INET ? 4 : 16);
	cb_data->ip->cidr = ifa->ifa_prefixlen;
	cb_data->ip->family = ifa->ifa_family;

	char out[INET6_ADDRSTRLEN];
	inet_ntop(ifa->ifa_family, cb_data->ip, out, sizeof(out));
	debug("index=%d, family=%d, addr=%s\n", ifa->ifa_index, ifa->ifa_family,
	      out);

	cb_data->ip_found = true;

	return MNL_CB_OK;
}

static int iface_get_all_addrs(uint8_t family, void *cb_data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	/* TODO: rtln-addr-dump from libmnl uses rtgenmsg here? */
	struct ifaddrmsg *ifaddr;
	int ret;
	unsigned int seq, portid;

	/* You'd think that we could just request addresses from a specific
	 * interface, via NLM_F_MATCH or something, but we can't. See also:
	 * https://marc.info/?l=linux-netdev&m=132508164508217
	 */
	seq = time(NULL);
	portid = mnl_socket_get_portid(nl);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	ifaddr = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifaddr->ifa_family = family;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return -1;

	do {
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_cb_run(buf, ret, seq, portid, data_cb, cb_data);
	} while (ret > 0);

	if (ret == -1)
		return -1;

	return 0;
}

void ipm_init()
{
	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL)
		fatal("mnl_socket_open()");

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		fatal("mnl_socket_bind()");
}

void ipm_free()
{
	if (nl)
		mnl_socket_close(nl);
}

int ipm_newaddr_v4(uint32_t ifindex, const struct in_addr *ip)
{
	return iface_update(RTM_NEWADDR, NLM_F_REPLACE | NLM_F_CREATE, ifindex,
			    (uint8_t *)ip, 32, AF_INET);
}

int ipm_newaddr_v6(uint32_t ifindex, const struct in6_addr *ip)
{
	return iface_update(RTM_NEWADDR, NLM_F_REPLACE | NLM_F_CREATE, ifindex,
			    (uint8_t *)ip, 128, AF_INET6);
}

int ipm_deladdr_v4(uint32_t ifindex, const struct in_addr *ip)
{
	return iface_update(RTM_DELADDR, 0, ifindex, (uint8_t *)ip, 32,
			    AF_INET);
}

int ipm_deladdr_v6(uint32_t ifindex, const struct in6_addr *ip)
{
	return iface_update(RTM_DELADDR, 0, ifindex, (uint8_t *)ip, 128,
			    AF_INET6);
}

int ipm_getlladdr(uint32_t ifindex, struct wg_combined_ip *addr)
{
	struct mnl_cb_data cb_data = {
		.ifindex = ifindex,
		.ip = addr,
		.ip_found = false,
		.duplicate = false,
	};

	if (iface_get_all_addrs(AF_INET6, &cb_data))
		return -1;

	if (!cb_data.ip_found)
		return -2;

	if (cb_data.duplicate)
		return -3;

	return 0;
}
