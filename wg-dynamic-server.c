/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2019 WireGuard LLC. All Rights Reserved.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "dbg.h"
#include "netlink.h"

static const char *progname;
static struct in6_addr well_known;

static wg_device *device = NULL;
static struct pollfd pollfds[MAX_CONNECTIONS + 1];

struct mnl_cb_data {
	uint32_t ifindex;
	bool valid_ip_found;
};

static void usage()
{
	die("usage: %s <wg-interface>\n", progname);
}

static bool is_link_local(unsigned char *addr)
{
	/* TODO: check if the remaining 48 bits are 0 */
	return addr[0] == 0xFE && addr[1] == 0x80;
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
	unsigned char *addr;

	if (ifa->ifa_index != cb_data->ifindex)
		return MNL_CB_OK;

	if (ifa->ifa_scope != RT_SCOPE_LINK)
		return MNL_CB_OK;

	mnl_attr_parse(nlh, sizeof(*ifa), data_attr_cb, tb);

	if (!tb[IFA_ADDRESS])
		return MNL_CB_OK;

	addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
	char out[INET6_ADDRSTRLEN];
	inet_ntop(ifa->ifa_family, addr, out, sizeof(out));
	debug("index=%d, family=%d, addr=%s\n", ifa->ifa_index, ifa->ifa_family,
	      out);

	if (ifa->ifa_prefixlen != 64 || memcmp(addr, well_known.s6_addr, 16))
		return MNL_CB_OK;

	cb_data->valid_ip_found = true;

	return MNL_CB_OK;
}

static bool validate_link_local_ip(uint32_t ifindex)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	/* TODO: rtln-addr-dump from libmnl uses rtgenmsg here? */
	struct ifaddrmsg *ifaddr;
	int ret;
	unsigned int seq, portid;
	struct mnl_cb_data cb_data = {
		.ifindex = ifindex,
		.valid_ip_found = false,
	};

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL)
		fatal("mnl_socket_open");

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		fatal("mnl_socket_bind");

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
	ifaddr->ifa_family = AF_INET6;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		fatal("mnl_socket_sendto");

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, data_cb, &cb_data);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1)
		fatal("mnl_cb_run/mnl_socket_recvfrom");

	mnl_socket_close(nl);

	return cb_data.valid_ip_found;
}

static bool valid_peer_found(wg_device *device)
{
	wg_peer *peer;
	wg_key_b64_string key;
	wg_allowedip *allowedip;
	wg_for_each_peer (device, peer) {
		wg_key_to_base64(key, peer->public_key);
		debug("- peer %s\n", key);
		debug("  allowedips:\n");

		wg_for_each_allowedip (peer, allowedip) {
			char out[INET6_ADDRSTRLEN];
			inet_ntop(allowedip->family, &allowedip->ip6, out,
				  sizeof(out));
			debug("    %s\n", out);

			if (is_link_local(allowedip->ip6.s6_addr) &&
			    allowedip->cidr == 128)
				return true;
		}
	}

	return false;
}

static int get_avail_pollfds()
{
	for (int nfds = 1;; ++nfds) {
		if (nfds >= MAX_CONNECTIONS + 1)
			return -1;

		if (pollfds[nfds].fd < 0)
			return nfds;
	}
}

static void accept_connection(int fd, struct pollfd *pfd)
{
	// struct sockaddr_storage;

#ifdef __linux__
	pfd->fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
#else
	pfd->fd = accept(fd, NULL, NULL);
	int res = fcntl(pfd->fd, F_GETFL, 0);
	if (res < 0 || fcntl(pfd->fd, F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting socket to nonblocking failed");
#endif

	if (pfd->fd < 0)
		fatal("Failed to accept connection");
}

static int handle_request(int fd)
{
	ssize_t read;
	unsigned char buf[RECV_BUFSIZE + MAX_LINESIZE];
	struct wg_dynamic_request req = {
		.cmd = WGKEY_UNKNOWN,
		.version = 0,
		.first = NULL,
		.last = NULL,
	};

	while (1) {
		read = recv(fd, buf, RECV_BUFSIZE, 0);
		if (read >= 0) {
			parse_request(&req, buf, read);
		} else {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			fatal("recv()");
		}
	}

	if (close(fd))
		debug("failed to close accept() socket");

	return 1;
}

static void setup_socket(int *fd)
{
	int val = 1;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_addr = well_known,
		.sin6_scope_id = device->ifindex,
	};

	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (*fd < 0)
		fatal("Creating a socket failed");

	if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val) == -1)
		fatal("Setting socket option failed");

	if (bind(*fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		fatal("Binding socket failed");

	if (listen(*fd, SOMAXCONN) == -1)
		fatal("Listening to socket failed");
}

static void cleanup()
{
	wg_free_device(device);

	for (int i = 0; i < MAX_CONNECTIONS + 1; ++i) {
		if (pollfds[i].fd < 0)
			continue;

		if (close(pollfds[i].fd))
			debug("Failed to close fd %d\n", pollfds[i].fd);
	}
}

int main(int argc, char *argv[])
{
	const char *iface;
	int n;

	progname = argv[0];
	inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known);

	for (int i = 0; i < MAX_CONNECTIONS + 1; ++i) {
		pollfds[i] = (struct pollfd){
			.fd = -1,
			.events = POLLIN,
		};
	}

	if (argc != 2)
		usage();

	iface = argv[1];
	if (atexit(cleanup))
		die("Failed to set exit function\n");

	if (wg_get_device(&device, iface))
		fatal("Unable to access interface %s", iface);

	if (!validate_link_local_ip(device->ifindex))
		// TODO: assign IP instead?
		die("%s needs to have %s assigned\n", iface, WG_DYNAMIC_ADDR);

	if (!valid_peer_found(device))
		die("%s has no peers with link-local allowedips\n", iface);

	setup_socket(&pollfds[0].fd);

	while (1) {
		if (poll(pollfds, MAX_CONNECTIONS + 1, -1) == -1)
			fatal("Failed to poll() fds");

		if (pollfds[0].revents & POLLIN) {
			pollfds[0].revents = 0;
			n = get_avail_pollfds();
			if (n >= 0)
				accept_connection(pollfds[0].fd, &pollfds[n]);
		}

		for (int i = 1; i < MAX_CONNECTIONS + 1; ++i) {
			if (!(pollfds[i].revents & POLLIN))
				continue;

			pollfds[i].revents = 0;
			if (handle_request(pollfds[i].fd) > 0)
				pollfds[i].fd = -1;
		}
	}

	return 0;
}
