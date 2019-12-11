/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2019 WireGuard LLC. All Rights Reserved.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "dbg.h"
#include "ipm.h"
#include "khash.h"
#include "lease.h"
#include "netlink.h"

static const char *progname;
static const char *wg_interface = NULL;
static struct in6_addr well_known;

static wg_device *device = NULL;
static uint32_t leasetime = 3600;

static int sockfd = -1;
static int epollfd = -1;
static struct mnl_socket *nlsock = NULL;

KHASH_MAP_INIT_INT64(allowedht, wg_key *)
khash_t(allowedht) * allowedips_ht;

struct wg_dynamic_connection {
	struct wg_dynamic_request req;
	int fd;
	wg_key pubkey;
	struct in6_addr lladdr;
	unsigned char *outbuf;
	size_t buflen;
};

static struct wg_dynamic_connection connections[MAX_CONNECTIONS] = { 0 };

static void usage()
{
	fprintf(stderr, "usage: %s [--leasetime <leasetime>] <wg-interface>\n",
		progname);
	exit(EXIT_FAILURE);
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

static void rebuild_allowedips_ht()
{
	wg_peer *peer;
	wg_allowedip *allowedip;
	khiter_t k;
	uint64_t lh;
	int ret;

	kh_clear(allowedht, allowedips_ht);

	wg_free_device(device);
	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	wg_for_each_peer (device, peer) {
		wg_for_each_allowedip (peer, allowedip) {
			if (allowedip->family == AF_INET6 &&
			    is_link_local(allowedip->ip6.s6_addr) &&
			    allowedip->cidr == 128) {
				memcpy(&lh, allowedip->ip6.s6_addr + 8, 8);
				k = kh_put(allowedht, allowedips_ht, lh, &ret);
				if (ret <= 0)
					die("Failed to rebuild allowedips hashtable\n");

				kh_value(allowedips_ht, k) = &peer->public_key;
			}
		}
	}
}

static wg_key *addr_to_pubkey(struct sockaddr_storage *addr)
{
	khiter_t k;
	uint64_t lh;

	if (addr->ss_family == AF_INET6) {
		lh = *(uint64_t *)&((struct sockaddr_in6 *)addr)
			      ->sin6_addr.s6_addr[8];
		k = kh_get(allowedht, allowedips_ht, lh);
		if (k != kh_end(allowedips_ht))
			return kh_val(allowedips_ht, k);
	}

	return NULL;
}

static int accept_connection(wg_key *dest_pubkey, struct in6_addr *dest_lladdr)
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

	if (addr.ss_family != AF_INET6) {
		debug("Rejecting client for not using an IPv6 address\n");
		return -EINVAL;
	}

	if (((struct sockaddr_in6 *)&addr)->sin6_port !=
	    htons(WG_DYNAMIC_PORT)) {
		debug("Rejecting client for using port %u != %u\n",
		      htons(((struct sockaddr_in6 *)&addr)->sin6_port),
		      WG_DYNAMIC_PORT);
		return -EINVAL;
	}

	pubkey = addr_to_pubkey(&addr);
	if (!pubkey) {
		/* our copy of allowedips is outdated, refresh */
		rebuild_allowedips_ht();
		pubkey = addr_to_pubkey(&addr);
		if (!pubkey) {
			/* either we lost the race or something is very wrong */
			close(fd);
			return -ENOENT;
		}
	}
	memcpy(dest_pubkey, pubkey, sizeof *dest_pubkey);

	memcpy(dest_lladdr, &((struct sockaddr_in6 *)&addr)->sin6_addr,
	       sizeof *dest_lladdr);

	wg_key_b64_string key;
	char out[INET6_ADDRSTRLEN];
	wg_key_to_base64(key, *pubkey);
	inet_ntop(addr.ss_family, &((struct sockaddr_in6 *)&addr)->sin6_addr,
		  out, sizeof(out));
	debug("%s has pubkey: %s\n", out, key);

	return fd;
}

static bool send_message(struct wg_dynamic_connection *con,
			 const unsigned char *buf, size_t len)
{
	size_t offset = 0;

	while (1) {
		ssize_t written = write(con->fd, buf + offset, len - offset);
		if (written < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			if (errno == EINTR)
				continue;

			debug("Writing to socket %d failed: %s\n", con->fd,
			      strerror(errno));
			return false;
		}

		offset += written;
		if (offset == len)
			return true;
	}

	debug("Socket %d blocking on write with %lu bytes left, postponing\n",
	      con->fd, len - offset);

	if (!con->outbuf) {
		con->buflen = len - offset;
		con->outbuf = malloc(con->buflen);
		if (!con->outbuf)
			fatal("malloc()");

		memcpy(con->outbuf, buf + offset, con->buflen);
	} else {
		con->buflen = len - offset;
		memmove(con->outbuf, buf + offset, con->buflen);
	}

	return true;
}

void close_connection(struct wg_dynamic_connection *con)
{
	free_wg_dynamic_request(&con->req);

	if (close(con->fd))
		debug("Failed to close socket\n");

	con->fd = -1;
	memset(con->pubkey, 0, sizeof con->pubkey);
	free(con->outbuf);
	con->outbuf = NULL;
	con->buflen = 0;
}

static bool send_response(struct wg_dynamic_connection *con)
{
	char buf[MAX_RESPONSE_SIZE];
	size_t msglen;

	switch (con->req.cmd) {
	case WGKEY_REQUEST_IP:;
		struct wg_dynamic_request_ip *rip = con->req.result;
		struct in_addr *ip4 = rip->has_ipv4 ? &rip->ipv4 : NULL;
		struct in6_addr *ip6 = rip->has_ipv6 ? &rip->ipv6 : NULL;
		struct wg_dynamic_lease *lease;
		struct wg_dynamic_request_ip ans = { 0 };

		lease = set_lease(con->pubkey, leasetime, &con->lladdr, ip4,
				  ip6);

		if (lease->ipv4.s_addr) {
			ans.has_ipv4 = true;
			memcpy(&ans.ipv4, &lease->ipv4, sizeof ans.ipv4);
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6)) {
			ans.has_ipv6 = true;
			memcpy(&ans.ipv6, &lease->ipv6, sizeof ans.ipv6);
		}

		if ((!ans.has_ipv4 && rip->has_ipv4) ||
		    (!ans.has_ipv6 && rip->has_ipv6))
			ans.wg_errno = E_IP_UNAVAIL;

		ans.start = lease->start_real;
		ans.leasetime = lease->leasetime;

		msglen = serialize_request_ip(false, buf, sizeof buf, &ans);
		break;
	default:
		debug("Unknown command: %d\n", con->req.cmd);
		BUG();
	}

	return send_message(con, (unsigned char *)buf, msglen);
}

static void handle_client(struct wg_dynamic_connection *con)
{
	unsigned char buf[RECV_BUFSIZE + MAX_LINESIZE];
	size_t rem = 0;
	ssize_t ret;

	while ((ret = handle_request(con->fd, &con->req, buf, &rem)) > 0) {
		if (!send_response(con)) {
			close_connection(con);
			break;
		}

		free_wg_dynamic_request(&con->req);
	}

	if (ret < 0) {
		size_t len = 0;
		uint32_t err = E_INVALID_REQ;
		if (-ret == EPROTONOSUPPORT)
			err = E_UNSUPP_PROTO;

		print_to_buf((char *)buf, sizeof buf, &len,
			     "errno=%u\nerrmsg=%s\n\n", err,
			     WG_DYNAMIC_ERR[err]);
		send_message(con, buf, len);
		close_connection(con);
	}
}

static void setup_sockets()
{
	int val = 1, res;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_addr = well_known,
		.sin6_scope_id = device->ifindex,
	};

	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
		fatal("Creating a socket failed");

	res = fcntl(sockfd, F_GETFL, 0);
	if (res < 0 || fcntl(sockfd, F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting socket to nonblocking failed");

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val))
		fatal("Setting socket option failed");

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		fatal("Binding socket failed");

	if (listen(sockfd, SOMAXCONN) == -1)
		fatal("Listening to socket failed");

	/* netlink route socket */
	nlsock = mnl_socket_open(NETLINK_ROUTE);
	if (!nlsock)
		fatal("mnl_socket_open(NETLINK_ROUTE)");

	res = fcntl(mnl_socket_get_fd(nlsock), F_GETFL, 0);
	if (res < 0 ||
	    fcntl(mnl_socket_get_fd(nlsock), F_SETFL, res | O_NONBLOCK) < 0)
		fatal("Setting netlink socket to nonblocking failed");

	if (mnl_socket_bind(nlsock, 0, MNL_SOCKET_AUTOPID) < 0)
		fatal("mnl_socket_bind()");

	val = RTNLGRP_IPV4_ROUTE;
	if (mnl_socket_setsockopt(nlsock, NETLINK_ADD_MEMBERSHIP, &val,
				  sizeof val) < 0)
		fatal("mnl_socket_setsockopt()");

	val = RTNLGRP_IPV6_ROUTE;
	if (mnl_socket_setsockopt(nlsock, NETLINK_ADD_MEMBERSHIP, &val,
				  sizeof val) < 0)
		fatal("mnl_socket_setsockopt()");
}

static void cleanup()
{
	leases_free();
	kh_destroy(allowedht, allowedips_ht);
	wg_free_device(device);

	if (nlsock)
		mnl_socket_close(nlsock);

	if (sockfd >= 0)
		close(sockfd);

	if (epollfd >= 0)
		close(epollfd);

	for (int i = 0; i < MAX_CONNECTIONS; ++i) {
		if (connections[i].fd < 0)
			continue;

		close_connection(&connections[i]);
	}
}

static void init_leases_from_peers()
{
	wg_peer *peer;

	wg_for_each_peer (device, peer) {
		wg_allowedip *allowedip;
		struct in6_addr *lladdr = NULL;
		struct in_addr *ipv4 = NULL;
		struct in6_addr *ipv6 = NULL;
		wg_for_each_allowedip (peer, allowedip) {
			if (allowedip->family == AF_INET6 &&
			    IN6_IS_ADDR_LINKLOCAL(&allowedip->ip6))
				lladdr = &allowedip->ip6;
			else if (allowedip->family == AF_INET && !ipv4)
				ipv4 = &allowedip->ip4;
			else if (allowedip->family == AF_INET6 && !ipv6)
				ipv6 = &allowedip->ip6;
		}

		if (!ipv4 && !ipv6)
			continue;

		set_lease(peer->public_key, leasetime, lladdr, ipv4, ipv6);
	}
}

static void setup()
{
	struct wg_combined_ip ip;
	int ret;

	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

	allowedips_ht = kh_init(allowedht);

	for (int i = 0; i < MAX_CONNECTIONS; ++i)
		connections[i].fd = -1;

	if (atexit(cleanup))
		die("Failed to set exit function\n");

	rebuild_allowedips_ht();

	ipm_init();
	ret = ipm_getlladdr(device->ifindex, &ip);
	if (ret == -1)
		fatal("ipm_getlladdr()");
	if (ret == -2)
		die("Interface must not have multiple link-local addresses assigned\n");
	ipm_free();

	if (ret == -1 || ip.family != AF_INET6 ||
	    memcmp(&ip.ip6, well_known.s6_addr, 16))
		/* TODO: assign IP instead? */
		die("%s needs to have %s assigned\n", wg_interface,
		    WG_DYNAMIC_ADDR);

	if (ip.cidr != 64)
		die("Link-local address must have a CIDR of 64\n");

	if (!valid_peer_found(device))
		die("%s has no peers with link-local allowedips\n",
		    wg_interface);

	setup_sockets();
	leases_init(wg_interface, device->ifindex, NULL, nlsock);
	init_leases_from_peers();
}

static int get_avail_request()
{
	for (int nfds = 0;; ++nfds) {
		if (nfds >= MAX_CONNECTIONS)
			return -1;

		if (connections[nfds].fd < 0)
			return nfds;
	}
}

static void accept_incoming()
{
	int n, fd;
	struct epoll_event ev;

	while ((n = get_avail_request()) >= 0) {
		fd = accept_connection(&connections[n].pubkey,
				       &connections[n].lladdr);
		if (fd < 0) {
			if (fd == -ENOENT) {
				debug("Failed to match IP to pubkey\n");
				continue;
			} else if (fd == -EAGAIN || fd == -EWOULDBLOCK) {
				return;
			}

			debug("Failed to accept connection: %s\n",
			      strerror(-fd));
			continue;
		}

		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = &connections[n];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
			fatal("epoll_ctl()");

		connections[n].fd = fd;
	}
}

static void handle_event(void *ptr, uint32_t events)
{
	struct wg_dynamic_connection *con;

	if (ptr == &sockfd) {
		accept_incoming();
		return;
	}

	if (ptr == nlsock) {
		leases_update_pools(nlsock);
		return;
	}

	con = (struct wg_dynamic_connection *)ptr;
	if (events & EPOLLIN) {
		handle_client(con);
	}

	if (events & EPOLLOUT) {
		if (!send_message(con, con->outbuf, con->buflen))
			close_connection(con);
	}
}

static void poll_loop()
{
	struct epoll_event ev, events[MAX_CONNECTIONS];
	epollfd = epoll_create1(0);
	if (epollfd == -1)
		fatal("epoll_create1()");

	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = &sockfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev))
		fatal("epoll_ctl()");

	ev.events = EPOLLIN;
	ev.data.ptr = nlsock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, mnl_socket_get_fd(nlsock), &ev))
		fatal("epoll_ctl()");

	while (1) {
		time_t next = leases_refresh() * 1000;
		int nfds = epoll_wait(epollfd, events, MAX_CONNECTIONS, next);
		if (nfds == -1) {
			if (errno == EINTR)
				continue;

			fatal("epoll_wait()");
		}

		for (int i = 0; i < nfds; ++i)
			handle_event(events[i].data.ptr, events[i].events);
	}
}

int main(int argc, char *argv[])
{
	progname = argv[0];

	while (1) {
		int ret, index;
		char *endptr = NULL;
		const struct option options[] = {
			{ "leasetime", required_argument, NULL, 0 },
			{ 0, 0, 0, 0 }
		};

		ret = getopt_long(argc, argv, "", options, &index);
		if (ret == -1)
			break;

		switch (ret) {
		case 0:
			if (index != 0)
				usage();
			leasetime = (uint32_t)strtoul(optarg, &endptr, 10);
			if (*endptr)
				usage();
			break;
		default:
			usage();
		}
	}

	if (optind < argc)
		wg_interface = argv[optind++];

	if (!wg_interface || optind < argc)
		usage();

	setup();

	poll_loop();

	return 0;
}
