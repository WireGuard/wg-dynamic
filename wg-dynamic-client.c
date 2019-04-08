/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "dbg.h"
#include "netlink.h"

#define LEASE_CHECK_INTERVAL 1000 /* 1s is convenient for testing */

static const char *progname;
static const char *wg_interface;
static wg_device *device = NULL;
static struct pollfd pollfds[1];
static struct in6_addr our_lladdr = { 0 };
static struct wg_combined_ip our_gaddr4 = { 0 };
static struct wg_combined_ip our_gaddr6 = { 0 };
static struct wg_dynamic_lease our_lease = { 0 };

struct mnl_cb_data {
	uint32_t ifindex;
	struct in6_addr *lladdr;
	struct wg_combined_ip *gaddr4;
	struct wg_combined_ip *gaddr6;
};

static void usage()
{
	die("usage: %s <wg-interface>\n", progname);
}

int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[IFA_MAX + 1] = {};
	struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct mnl_cb_data *cb_data = (struct mnl_cb_data *)data;
	unsigned char *addr;

	if (ifa->ifa_index != cb_data->ifindex)
		return MNL_CB_OK;

	mnl_attr_parse(nlh, sizeof(*ifa), data_attr_cb, tb);

	if (!tb[IFA_ADDRESS])
		return MNL_CB_OK;

	addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
	char out[INET6_ADDRSTRLEN];
	inet_ntop(ifa->ifa_family, addr, out, sizeof(out));
	debug("index=%d, family=%d, addr=%s\n", ifa->ifa_index, ifa->ifa_family,
	      out);

	if (ifa->ifa_scope == RT_SCOPE_LINK) {
		if (ifa->ifa_prefixlen != 128)
			return MNL_CB_OK;
		memcpy(cb_data->lladdr, addr, 16);
	} else if (ifa->ifa_scope == RT_SCOPE_UNIVERSE) {
		switch (ifa->ifa_family) {
		case AF_INET:
			cb_data->gaddr4->family = ifa->ifa_family;
			memcpy(&cb_data->gaddr4->ip, addr, 4);
			cb_data->gaddr4->cidr = ifa->ifa_prefixlen;
			break;
		case AF_INET6:
			cb_data->gaddr6->family = ifa->ifa_family;
			memcpy(&cb_data->gaddr6->ip, addr, 16);
			cb_data->gaddr6->cidr = ifa->ifa_prefixlen;
			break;
		default:
			die("Unknown address family: %u\n", ifa->ifa_family);
		}
	}

	return MNL_CB_OK;
}

static void iface_update(uint16_t cmd, uint16_t flags, uint32_t ifindex,
			 const struct wg_combined_ip *addr)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	unsigned int seq, portid;
	struct ifaddrmsg *ifaddr; /* linux/if_addr.h */
	int ret;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL)
		fatal("mnl_socket_open");

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		fatal("mnl_socket_bind");

	portid = mnl_socket_get_portid(nl);
	seq = time(NULL);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_type = cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	ifaddr = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifaddr->ifa_family = addr->family;
	ifaddr->ifa_prefixlen = addr->cidr;
	ifaddr->ifa_scope = RT_SCOPE_UNIVERSE; /* linux/rtnetlink.h */
	ifaddr->ifa_index = ifindex;
	mnl_attr_put(nlh, IFA_LOCAL, addr->family == AF_INET ? 4 : 16,
		     &addr->ip);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		fatal("mnl_socket_sendto");

	do {
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	} while (ret > 0);

	if (ret == -1)
		fatal("mnl_cb_run/mnl_socket_recvfrom");

	mnl_socket_close(nl);
}

static void iface_remove_addr(uint32_t ifindex,
			      const struct wg_combined_ip *addr)
{
	char ipstr[INET6_ADDRSTRLEN];
	debug("removing %s/%u from interface %u\n",
	      inet_ntop(addr->family, &addr->ip, ipstr, sizeof ipstr),
	      addr->cidr, ifindex);
	iface_update(RTM_DELADDR, 0, ifindex, addr);
}

static void iface_add_addr(uint32_t ifindex, const struct wg_combined_ip *addr)
{
	char ipstr[INET6_ADDRSTRLEN];
	debug("adding %s/%u to interface %u\n",
	      inet_ntop(addr->family, &addr->ip, ipstr, sizeof ipstr),
	      addr->cidr, ifindex);
	iface_update(RTM_NEWADDR, NLM_F_REPLACE | NLM_F_CREATE, ifindex, addr);
}

static bool get_and_validate_local_addrs(uint32_t ifindex,
					 struct in6_addr *lladdr,
					 struct wg_combined_ip *gaddr4,
					 struct wg_combined_ip *gaddr6)
{
	struct mnl_cb_data cb_data = {
		.ifindex = ifindex,
		.lladdr = lladdr,
		.gaddr4 = gaddr4,
		.gaddr6 = gaddr6,
	};

	iface_get_all_addrs(AF_INET, data_cb, &cb_data);
	iface_get_all_addrs(AF_INET6, data_cb, &cb_data);

	return !IN6_IS_ADDR_UNSPECIFIED(cb_data.lladdr);
}

#if 0
static void dump_leases()
{
	char ip4str[INET6_ADDRSTRLEN], ip6str[INET6_ADDRSTRLEN];
	struct wg_dynamic_lease *l = &our_lease;

	if (l->start == 0) {
		debug("lease NONE\n");
		return;
	}

	debug("lease %u %u %s/%u %s/%u\n", l->start + l->leasetime,
	      l->start + l->leasetime - current_time(),
	      inet_ntop(AF_INET, &l->ip4.ip.ip4, ip4str, INET6_ADDRSTRLEN),
	      l->ip4.cidr,
	      inet_ntop(AF_INET6, &l->ip6.ip.ip6, ip6str, INET6_ADDRSTRLEN),
	      l->ip6.cidr);
}
#endif

static int do_connect(int *fd)
{
	int res;
	struct sockaddr_in6 our_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = our_lladdr,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_scope_id = device->ifindex,
	};
	struct sockaddr_in6 their_addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_scope_id = device->ifindex,
	};

	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (*fd < 0)
		fatal("Creating a socket failed");

	if (bind(*fd, (struct sockaddr *)&our_addr, sizeof(our_addr)))
		fatal("Binding socket failed");

	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &their_addr.sin6_addr) != 1)
		fatal("inet_pton()");
	if (connect(*fd, (struct sockaddr *)&their_addr,
		    sizeof(struct sockaddr_in6))) {
		char out[INET6_ADDRSTRLEN];
		if (!inet_ntop(their_addr.sin6_family, &their_addr.sin6_addr,
			       out, sizeof out))
			fatal("inet_ntop()");
		debug("Connecting to [%s]:%u failed: %s\n", out,
		      ntohs(their_addr.sin6_port), strerror(errno));
		if (close(*fd))
			debug("Closing socket failed: %s\n", strerror(errno));
		*fd = -1;
		return -1;
	}

	res = fcntl(*fd, F_GETFL, 0);
	if (res < 0 || fcntl(*fd, F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting socket to nonblocking failed");

	return 0;
}

static size_t connect_and_send(unsigned char *buf, size_t *len)
{
	size_t ret;
	if (pollfds[0].fd < 0)
		if (do_connect(&pollfds[0].fd))
			return 0;
	ret = send_message(pollfds[0].fd, buf, len);
	return ret;
}

static bool request_ip(struct wg_dynamic_request *req,
		       const struct wg_dynamic_lease *lease)
{
	unsigned char buf[MAX_RESPONSE_SIZE + 1];
	char addrstr[INET6_ADDRSTRLEN];
	size_t msglen;
	size_t written;

	msglen = 0;
	msglen += print_to_buf((char *)buf, sizeof buf, msglen, "%s=%d\n",
			       WG_DYNAMIC_KEY[WGKEY_REQUEST_IP], 1);

	if (lease && lease->ip4.ip.ip4.s_addr) {
		if (!inet_ntop(AF_INET, &lease->ip4.ip.ip4, addrstr,
			       sizeof addrstr))
			fatal("inet_ntop()");
		msglen += print_to_buf((char *)buf, sizeof buf, msglen,
				       "ipv4=%s/32\n", addrstr);
	}
	if (lease && !IN6_IS_ADDR_UNSPECIFIED(&lease->ip6.ip.ip6)) {
		if (!inet_ntop(AF_INET6, &lease->ip6.ip.ip6, addrstr,
			       sizeof addrstr))
			fatal("inet_ntop()");
		msglen += print_to_buf((char *)buf, sizeof buf, msglen,
				       "ipv6=%s/128\n", addrstr);
	}
	/* nmsglen += print_to_buf((char *)buf, sizeof buf, msglen,
	   "leasetime=%u\n", fixme); */

	msglen += print_to_buf((char *)buf, sizeof buf, msglen, "\n");

	written = connect_and_send(buf, &msglen);
	if (msglen == 0)
		return true;

	debug("Socket %d blocking with %lu bytes to write, postponing\n",
	      pollfds[0].fd, msglen);
	send_later(req, buf + written, msglen);
	return false;
}

static int maybe_refresh_lease(uint32_t now, struct wg_dynamic_lease *lease,
			       struct wg_dynamic_request *req)
{
	if (now > lease->start + (lease->leasetime * 2) / 3) {
		debug("Refreshing lease expiring on %u\n",
		      lease->start + lease->leasetime);
		request_ip(req, lease);
		return 0;
	}

	return 1;
}

static bool lease_is_valid(uint32_t now, struct wg_dynamic_lease *lease)
{
	return now < lease->start + lease->leasetime;
}

static void maybe_remove_lease(uint32_t now, struct wg_dynamic_lease *lease)
{
	if (!lease_is_valid(now, lease))
		memset(lease, 0, sizeof *lease);
}

static void check_leases(struct wg_dynamic_request *req)
{
	uint32_t now = current_time();

	if (!lease_is_valid(now, &our_lease))
		request_ip(req, NULL);
	else {
		maybe_remove_lease(now, &our_lease);
		maybe_refresh_lease(now, &our_lease, req);
	}
}

static int handle_received_lease(const struct wg_dynamic_request *req)
{
	uint32_t ret;
	struct wg_dynamic_attr *attr;
	struct wg_dynamic_lease *lease = &our_lease;
	uint32_t now = current_time();
	uint32_t lease_start = 0;
	uint32_t curleasetime = lease->start + lease->leasetime;

	attr = req->first;
	while (attr) {
		switch (attr->key) {
		case WGKEY_IPV4:
			memcpy(&lease->ip4, attr->value,
			       sizeof(struct wg_combined_ip));
			break;
		case WGKEY_IPV6:
			memcpy(&lease->ip6, attr->value,
			       sizeof(struct wg_combined_ip));
			break;
		case WGKEY_LEASESTART:
			memcpy(&lease_start, attr->value, sizeof(uint32_t));
			break;
		case WGKEY_LEASETIME:
			memcpy(&lease->leasetime, attr->value,
			       sizeof(uint32_t));
			break;
		case WGKEY_ERRNO:
			memcpy(&ret, attr->value, sizeof(uint32_t));
			if (ret) {
				debug("Request IP failed with %ud from server\n",
				      ret);
				return -ret;
			}
			break;
		case WGKEY_ERRMSG:
			/* TODO: do something with the error message */
			break;
		default:
			debug("Ignoring invalid attribute for request_ip: %d\n",
			      attr->key);
		}
		attr = attr->next;
	}

	if (lease->leasetime == 0 ||
	    (lease->ip4.ip.ip4.s_addr == 0 &&
	     IN6_IS_ADDR_UNSPECIFIED(&lease->ip6.ip.ip6)))
		return -EINVAL;

	if (abs(now - lease_start) < 15)
		lease->start = lease_start;
	else
		lease->start = now;

	debug("Replacing lease %u -> %u\n", curleasetime,
	      lease->start + lease->leasetime);

	return 0;
}

static void cleanup()
{
	wg_free_device(device);
	if (pollfds[0].fd >= 0)
		if (close(pollfds[0].fd))
			debug("Failed to close fd");
}

static bool handle_error(int fd, int ret)
{
	UNUSED(fd);
	UNUSED(ret);

	debug("Unable to parse response: %s\n", strerror(ret));

	return true;
}

static void maybe_update_iface()
{
	if (memcmp(&our_gaddr4.ip, &our_lease.ip4.ip, sizeof our_gaddr4.ip) ||
	    our_gaddr4.cidr != our_lease.ip4.cidr) {
		if (our_gaddr4.ip.ip4.s_addr)
			iface_remove_addr(device->ifindex, &our_gaddr4);
		iface_add_addr(device->ifindex, &our_lease.ip4);
		memcpy(&our_gaddr4, &our_lease.ip4, sizeof our_gaddr4);
	}
	if (memcmp(&our_gaddr6.ip, &our_lease.ip6.ip, sizeof our_gaddr6.ip) ||
	    our_gaddr6.cidr != our_lease.ip6.cidr) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&our_gaddr6.ip.ip6))
			iface_remove_addr(device->ifindex, &our_gaddr6);
		iface_add_addr(device->ifindex, &our_lease.ip6);
		memcpy(&our_gaddr6, &our_lease.ip6, sizeof our_gaddr6);
	}
}

static bool handle_response(int fd, struct wg_dynamic_request *req)
{
	UNUSED(fd);

#if 0
	printf("Recieved response of type %s.\n", WG_DYNAMIC_KEY[req->cmd]);
	struct wg_dynamic_attr *cur = req->first;
	while (cur) {
		printf("  with attr %s.\n", WG_DYNAMIC_KEY[cur->key]);
		cur = cur->next;
	}
#endif

	switch (req->cmd) {
	case WGKEY_REQUEST_IP:
		if (handle_received_lease(req) == 0)
			maybe_update_iface();
		break;
	default:
		debug("Unknown command: %d\n", req->cmd);
		return true;
	}

	return true;
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	struct wg_dynamic_request req = { 0 };
	uint32_t now = current_time();

	progname = argv[0];
	if (argc != 2)
		usage();

	wg_interface = argv[1];

	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	if (atexit(cleanup))
		die("Failed to set exit function\n");
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		fatal("Unable to ignore SIGPIPE");

	if (!get_and_validate_local_addrs(device->ifindex, &our_lladdr,
					  &our_gaddr4, &our_gaddr6))
		die("%s needs to have an IPv6 link local address with prefixlen 128 assigned\n",
		    wg_interface);
	// TODO: verify that we have a peer with an allowed-ips including fe80::/128

	char lladr_str[INET6_ADDRSTRLEN];
	debug("%s: %s\n", wg_interface,
	      inet_ntop(AF_INET6, &our_lladdr, lladr_str, sizeof lladr_str));

	if (our_gaddr4.ip.ip4.s_addr ||
	    !IN6_IS_ADDR_UNSPECIFIED(&our_gaddr6.ip.ip6)) {
		our_lease.start = now;
		our_lease.leasetime = 15;
		memcpy(&our_lease.ip4, &our_gaddr4,
		       sizeof(struct wg_combined_ip));
		memcpy(&our_lease.ip6, &our_gaddr6,
		       sizeof(struct wg_combined_ip));
	}

	/* TODO: use a blocking socket instead of the unnecessary
	 * complexity of nonblocking */

	pollfds[0] = (struct pollfd){ .fd = -1, .events = POLLIN };
	while (1) {
		size_t off;
		int nevents = poll(pollfds, 1, LEASE_CHECK_INTERVAL);

		if (nevents == -1)
			fatal("poll()");

		if (nevents == 0) {
			/* FIXME: if there's any risk for this path to
			 * be starving, maybe do this regardless of
			 * socket readiness? */
			check_leases(&req);
			continue;
		}

		if (pollfds[0].revents & POLLOUT) {
			pollfds[0].revents &= ~POLLOUT;
			debug("sending, trying again with %lu bytes\n",
			      req.buflen);
			off = send_message(pollfds[0].fd, req.buf, &req.buflen);
			if (req.buflen)
				memmove(req.buf, req.buf + off, req.buflen);
			else
				close_connection(&pollfds[0].fd, &req);
		}

		if (pollfds[0].revents & POLLIN) {
			pollfds[0].revents &= ~POLLIN;
			if (handle_request(pollfds[0].fd, &req, handle_response,
					   handle_error))
				close_connection(&pollfds[0].fd, &req);
			else if (req.buf)
				pollfds[0].events |= POLLOUT;
		}
	}

	return 0;
}
