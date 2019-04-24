/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2019 WireGuard LLC. All Rights Reserved.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "dbg.h"
#include "netlink.h"
#include "radix-trie.h"

static const char *progname;
static const char *wg_interface;
static struct in6_addr well_known;

static wg_device *device = NULL;
static struct radix_trie allowedips_trie;
static struct pollfd pollfds[MAX_CONNECTIONS + 1];

struct mnl_cb_data {
	uint32_t ifindex;
	bool valid_ip_found;
};

static void usage()
{
	die("usage: %s <wg-interface>\n", progname);
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
	struct mnl_cb_data cb_data = {
		.ifindex = ifindex, .valid_ip_found = false,
	};

	iface_get_all_addrs(AF_INET6, data_cb, &cb_data);

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

static void rebuild_allowedips_trie()
{
	int ret;
	wg_peer *peer;
	wg_allowedip *allowedip;

	radix_free(&allowedips_trie);

	wg_free_device(device);
	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	wg_for_each_peer (device, peer) {
		wg_for_each_allowedip (peer, allowedip) {
			if (allowedip->family == AF_INET)
				ret = radix_insert_v4(&allowedips_trie,
						      &allowedip->ip4,
						      allowedip->cidr, peer);
			else
				ret = radix_insert_v6(&allowedips_trie,
						      &allowedip->ip6,
						      allowedip->cidr, peer);
			if (ret)
				die("Failed to rebuild allowedips trie\n");
		}
	}
}

static wg_key *addr_to_pubkey(struct sockaddr_storage *addr)
{
	wg_peer *peer;

	if (addr->ss_family == AF_INET)
		peer = radix_find_v4(&allowedips_trie, 32,
				     &((struct sockaddr_in *)addr)->sin_addr);
	else
		peer = radix_find_v6(&allowedips_trie, 128,
				     &((struct sockaddr_in6 *)addr)->sin6_addr);

	if (!peer)
		return NULL;

	return &peer->public_key;
}

static int accept_connection(int sockfd, wg_key *dest)
{
	int fd;
	wg_key *pubkey;
	struct sockaddr_storage addr;
	socklen_t size = sizeof addr;
#ifdef __linux__
	fd = accept4(sockfd, (struct sockaddr *)&addr, &size, SOCK_NONBLOCK);
	if (fd < 0)
		return -errno;
#else
	fd = accept(sockfd, (struct sockaddr *)&addr, &size);
	if (fd < 0)
		return -errno;

	int res = fcntl(fd, F_GETFL, 0);
	if (res < 0 || fcntl(fd, F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting socket to nonblocking failed");
#endif

	char addrstring[INET6_ADDRSTRLEN];
	char serv[10];
	if (getnameinfo((struct sockaddr *)&addr, sizeof addr, addrstring,
			sizeof addrstring, serv, sizeof serv,
			NI_NUMERICHOST | NI_NUMERICSERV))
		fatal("getnameinfo");

	if (addr.ss_family != AF_INET6) {
		debug("%s: rejecting client for not using an IPv6 address\n",
		      addrstring);
		return -EINVAL;
	}
	unsigned long port = strtoul(serv, NULL, 10);
	if (port >= 1024) {
		debug("%s: rejecting client for not using a low port: %lu\n",
		      addrstring, port);
		return -EINVAL;
	}

	pubkey = addr_to_pubkey(&addr);
	if (!pubkey) {
		/* our copy of allowedips is outdated, refresh */
		rebuild_allowedips_trie();
		pubkey = addr_to_pubkey(&addr);
		if (!pubkey) {
			/* either we lost the race or something is very wrong */
			close(fd);
			return -ENOENT;
		}
	}
	memcpy(dest, pubkey, sizeof *dest);

	wg_key_b64_string key;
	wg_key_to_base64(key, *pubkey);
	debug("%s has pubkey: %s\n", addrstring, key);

	return fd;
}

static void accept_incoming(int sockfd, struct wg_dynamic_request *reqs)
{
	int n, fd;
	while ((n = get_avail_pollfds()) >= 0) {
		fd = accept_connection(sockfd, &reqs[n - 1].pubkey);
		if (fd < 0) {
			if (fd == -ENOENT)
				debug("Failed to match IP to pubkey\n");
			else if (fd != -EAGAIN && fd != -EWOULDBLOCK)
				debug("Failed to accept connection: %s\n",
				      strerror(-fd));
			break;
		}
		pollfds[n].fd = fd;
	}
}

static int allocate_from_pool(struct wg_dynamic_request *const req,
			      struct wg_dynamic_lease *lease)
{
	struct wg_dynamic_attr *attr;
	struct wg_combined_ip default_v4 = {.family = AF_INET, .cidr = 32 },
			      default_v6 = {.family = AF_INET6, .cidr = 128 };

	/* NOTE: handing out whatever the client asks for */
	/* TODO: choose an ip address from pool of available
	 * addresses, together with an appropriate lease time */
	/* NOTE: the pool is to be drawn from what routes are pointing
	 * to the wg interface, and kept up to date as the routing
	 * table changes */

	if (inet_pton(AF_INET, "192.168.47.11", &default_v4.ip.ip4) != 1)
		fatal("inet_pton()");
	memcpy(&lease->ip4, &default_v4, sizeof(struct wg_combined_ip));

	if (inet_pton(AF_INET6, "fd00::4711", &default_v6.ip.ip6) != 1)
		fatal("inet_pton()");
	memcpy(&lease->ip6, &default_v6, sizeof(struct wg_combined_ip));

	lease->start = current_time();
	lease->leasetime = WG_DYNAMIC_LEASETIME;

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
		case WGKEY_LEASETIME:
			memcpy(&lease->leasetime, attr->value,
			       sizeof(uint32_t));
			break;
		default:
			debug("Ignoring invalid attribute for request_ip: %d\n",
			      attr->key);
		}

		attr = attr->next;
	}

	return 0;
}

static bool send_error(int fd, int ret)
{
	UNUSED(fd);
	debug("Error: %s\n", strerror(ret));
	return true;
}

static bool serialise_lease(char *buf, size_t bufsize, size_t *offset,
			    const struct wg_dynamic_lease *lease)
{
	char addrbuf[INET6_ADDRSTRLEN];
	bool ret = false;

	if (lease->ip4.ip.ip4.s_addr) {
		if (!inet_ntop(AF_INET, &lease->ip4.ip.ip4, addrbuf,
			       sizeof addrbuf))
			fatal("inet_ntop()");
		*offset += print_to_buf(buf, bufsize, *offset, "ipv4=%s/%d\n",
					addrbuf, lease->ip4.cidr);
		ret = true;
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ip6.ip.ip6)) {
		if (!inet_ntop(AF_INET6, &lease->ip6.ip.ip6, addrbuf,
			       sizeof addrbuf))
			fatal("inet_ntop()");
		*offset += print_to_buf(buf, bufsize, *offset, "ipv6=%s/%d\n",
					addrbuf, lease->ip6.cidr);
		ret = true;
	}

	if (ret) {
		*offset += print_to_buf(buf, bufsize, *offset,
					"leasestart=%u\n", lease->start);
		*offset += print_to_buf(buf, bufsize, *offset, "leasetime=%u\n",
					lease->leasetime);
	}

	return ret;
}

static struct wg_peer *current_peer(struct wg_dynamic_request *req)
{
	struct wg_peer *peer;

	wg_for_each_peer (device, peer) {
		if (!memcmp(peer->public_key, req->pubkey, sizeof(wg_key)))
			return peer;
	}

	return NULL;
}

static void insert_allowed_ip(struct wg_peer *peer,
			      const struct wg_combined_ip *ip)
{
	struct wg_allowedip *newip;

	newip = calloc(1, sizeof(struct wg_allowedip));
	if (!newip)
		fatal("calloc()");

	newip->family = ip->family;
	switch (newip->family) {
	case AF_INET:
		memcpy(&newip->ip4, &ip->ip.ip4, sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(&newip->ip6, &ip->ip.ip6, sizeof(struct in6_addr));
		break;
	}
	newip->cidr = ip->cidr;

	if (!peer->first_allowedip)
		peer->first_allowedip = newip;
	else
		peer->last_allowedip->next_allowedip = newip;
	peer->last_allowedip = newip;
}

static int add_allowed_ips(struct wg_peer *peer,
			   const struct wg_dynamic_lease *lease)
{
	if (lease->ip4.ip.ip4.s_addr)
		insert_allowed_ip(peer, &lease->ip4);
	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ip6.ip.ip6))
		insert_allowed_ip(peer, &lease->ip6);

	return wg_set_device(device);
}

static bool send_response(int fd, struct wg_dynamic_request *req)
{
	int ret;
	char *errmsg = "OK";
	unsigned char buf[MAX_RESPONSE_SIZE + 1];
	size_t msglen;
	size_t written;
	struct wg_dynamic_lease lease = { 0 };
	struct wg_peer *peer;

#if 0
	printf("Recieved request of type %s.\n", WG_DYNAMIC_KEY[req->cmd]);
	struct wg_dynamic_attr *cur = req->first;
	while (cur) {
		printf("  with attr %s.\n", WG_DYNAMIC_KEY[cur->key]);
		cur = cur->next;
	}
#endif

	peer = current_peer(req);
	if (!peer)
		die("Unable to find peer\n");

	ret = 0;
	msglen = 0;
	switch (req->cmd) {
	case WGKEY_REQUEST_IP:
		msglen = print_to_buf((char *)buf, sizeof buf, 0, "%s=%d\n",
				      WG_DYNAMIC_KEY[req->cmd], 1);
		ret = allocate_from_pool(req, &lease);
		if (ret) {
			debug("IP address allocation failing with %d\n", ret);
			ret = 0x01;
			errmsg = "Out of IP addresses";
			break;
		}

		ret = add_allowed_ips(peer, &lease);
		if (ret) {
			debug("Unable to add address(es) to peer: %s\n",
			      strerror(-ret));
			ret = 0x2;
			errmsg = "Internal error";
			break;
		}

		if (!serialise_lease((char *)buf, sizeof buf, &msglen,
				     &lease)) {
			die("Nothing to hand out, despite succeeding allocate_from_pool()\n");
			ret = 0x3;
			errmsg = "Internal error";
			break;
		}

		break;

	default:
		debug("Unknown command: %d\n", req->cmd);
		return true;
	}

	msglen += print_to_buf((char *)buf, sizeof buf, msglen, "errno=%d\n",
			       ret);
	if (ret)
		msglen += print_to_buf((char *)buf, sizeof buf, msglen,
				       "errmsg=%s\n", errmsg);
	if (msglen == sizeof buf)
		fatal("Outbuffer too small");
	buf[msglen++] = '\n';

	written = send_message(fd, buf, &msglen);
	if (msglen == 0)
		return true;

	debug("Socket %d blocking on write with %lu bytes left, postponing\n",
	      fd, msglen);
	send_later(req, buf + written, msglen);
	return false;
}

static void setup_socket(int *fd)
{
	int val = 1, res;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_addr = well_known,
		.sin6_scope_id = device->ifindex,
	};

	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (*fd < 0)
		fatal("Creating a socket failed");

	res = fcntl(*fd, F_GETFL, 0);
	if (res < 0 || fcntl(*fd, F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting socket to nonblocking failed");

	if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val) == -1)
		fatal("Setting socket option failed");

	if (bind(*fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		fatal("Binding socket failed");

	if (listen(*fd, SOMAXCONN) == -1)
		fatal("Listening to socket failed");
}

static void cleanup()
{
	radix_free(&allowedips_trie);
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
	struct wg_dynamic_request reqs[MAX_CONNECTIONS] = { 0 };
	int *sockfd = &pollfds[0].fd;

	progname = argv[0];
	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

	for (int i = 0; i < MAX_CONNECTIONS + 1; ++i) {
		pollfds[i] = (struct pollfd){
			.fd = -1, .events = POLLIN,
		};
	}

	if (argc != 2)
		usage();

	radix_init(&allowedips_trie);

	wg_interface = argv[1];
	if (atexit(cleanup))
		die("Failed to set exit function\n");

	rebuild_allowedips_trie();

	if (!validate_link_local_ip(device->ifindex))
		// TODO: assign IP instead?
		die("%s needs to have %s assigned\n", wg_interface,
		    WG_DYNAMIC_ADDR);

	if (!valid_peer_found(device))
		die("%s has no peers with link-local allowedips\n",
		    wg_interface);

	setup_socket(sockfd);

	while (1) {
		if (poll(pollfds, MAX_CONNECTIONS + 1, -1) == -1)
			fatal("Failed to poll() fds");

		if (pollfds[0].revents & POLLIN) {
			pollfds[0].revents = 0;
			accept_incoming(*sockfd, reqs);
		}

		for (int i = 1; i < MAX_CONNECTIONS + 1; ++i) {
			size_t off;

			if (!(pollfds[i].revents & POLLOUT))
				continue;

			off = send_message(pollfds[i].fd, reqs[i - 1].buf,
					   &reqs[i - 1].buflen);
			if (reqs[i - 1].buflen)
				memmove(reqs[i - 1].buf, reqs[i - 1].buf + off,
					reqs[i - 1].buflen);
			else
				close_connection(&pollfds[i].fd, &reqs[i - 1]);
		}

		for (int i = 1; i < MAX_CONNECTIONS + 1; ++i) {
			if (pollfds[i].fd < 0 || !pollfds[i].revents & POLLIN)
				continue;

			if (handle_request(pollfds[i].fd, &reqs[i - 1],
					   send_response, send_error))
				close_connection(&pollfds[i].fd, &reqs[i - 1]);
			else if (reqs[i - 1].buf)
				pollfds[i].events |= POLLOUT;
		}
	}

	return 0;
}
