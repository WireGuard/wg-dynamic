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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "dbg.h"
#include "khash.h"
#include "lease.h"
#include "netlink.h"

static const char *progname;
static const char *wg_interface;
static struct in6_addr well_known;

static wg_device *device = NULL;
static struct wg_dynamic_request requests[MAX_CONNECTIONS] = { 0 };

static int sockfd = -1;
static int epollfd = -1;

KHASH_MAP_INIT_INT64(allowedht, wg_key *)
khash_t(allowedht) * allowedips_ht;

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
		.ifindex = ifindex,
		.valid_ip_found = false,
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
	memcpy(dest, pubkey, sizeof *dest);

	wg_key_b64_string key;
	char out[INET6_ADDRSTRLEN];
	wg_key_to_base64(key, *pubkey);
	inet_ntop(addr.ss_family, &((struct sockaddr_in6 *)&addr)->sin6_addr,
		  out, sizeof(out));
	debug("%s has pubkey: %s\n", out, key);

	return fd;
}

static bool send_error(int fd, int ret)
{
	UNUSED(fd);
	debug("Error: %s\n", strerror(ret));
	return true;
}

static void serialise_lease(char *buf, size_t bufsize, size_t *offset,
			    const struct wg_dynamic_lease *lease)
{
	char addrbuf[INET6_ADDRSTRLEN];

	if (lease->ipv4.s_addr) {
		if (!inet_ntop(AF_INET, &lease->ipv4, addrbuf, sizeof addrbuf))
			fatal("inet_ntop()");
		*offset += print_to_buf(buf, bufsize, *offset, "ipv4=%s/%d\n",
					addrbuf, 32);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6)) {
		if (!inet_ntop(AF_INET6, &lease->ipv6, addrbuf, sizeof addrbuf))
			fatal("inet_ntop()");
		*offset += print_to_buf(buf, bufsize, *offset, "ipv6=%s/%d\n",
					addrbuf, 128);
	}

	*offset += print_to_buf(buf, bufsize, *offset, "leasestart=%u\n",
				lease->start_real);
	*offset += print_to_buf(buf, bufsize, *offset, "leasetime=%u\n",
				lease->leasetime);
}

static void add_allowed_ips(wg_key pubkey, struct in_addr *ipv4,
			    struct in6_addr *ipv6)
{
	wg_allowedip allowed_v4, allowed_v6;
	wg_peer peer = { 0 };
	wg_device dev = { .first_peer = &peer };

	strcpy(dev.name, wg_interface);
	memcpy(peer.public_key, pubkey, sizeof peer.public_key);
	wg_allowedip **cur = &peer.first_allowedip;

	if (ipv4) {
		allowed_v4 = (wg_allowedip){
			.family = AF_INET,
			.cidr = 32,
			.ip4 = *ipv4,
		};
		*cur = &allowed_v4;
		cur = &allowed_v4.next_allowedip;
	}

	if (ipv6) {
		allowed_v6 = (wg_allowedip){
			.family = AF_INET6,
			.cidr = 128,
			.ip6 = *ipv6,
		};
		*cur = &allowed_v6;
	}

	if (wg_set_device(&dev))
		fatal("wg_set_device()");
}

static int response_request_ip(struct wg_dynamic_attr *cur, wg_key pubkey,
			       struct wg_dynamic_lease **lease)
{
	time_t expires;
	struct in_addr *ipv4 = NULL;
	struct in6_addr *ipv6 = NULL;
	uint32_t leasetime = WG_DYNAMIC_LEASETIME;

	*lease = get_leases(pubkey);

	while (cur) {
		switch (cur->key) {
		case WGKEY_IPV4:
			ipv4 = &((struct wg_combined_ip *)cur->value)->ip4;
			break;
		case WGKEY_IPV6:
			ipv6 = &((struct wg_combined_ip *)cur->value)->ip6;
			break;
		case WGKEY_LEASETIME:
			leasetime = *(uint32_t *)cur->value;
			break;
		default:
			debug("Ignoring invalid attribute for request_ip: %d\n",
			      cur->key);
		}
		cur = cur->next;
	}

	if (ipv4 && ipv6 && !ipv4->s_addr && IN6_IS_ADDR_UNSPECIFIED(ipv6))
		return 2; /* TODO: invalid request */

	*lease = new_lease(pubkey, leasetime, ipv4, ipv6, &expires);
	if (!*lease)
		return 1; /* TODO: either out of IPs or IP unavailable */

	return 0;
}

static bool send_response(int fd, struct wg_dynamic_request *req)
{
	char *errmsg = "OK";
	struct wg_dynamic_attr *cur = req->first;
	struct wg_dynamic_lease *lease;
	unsigned char buf[MAX_RESPONSE_SIZE + 1];
	size_t msglen;
	size_t written;
	int ret = 0;

	switch (req->cmd) {
	case WGKEY_REQUEST_IP:
		msglen = print_to_buf((char *)buf, sizeof buf, 0, "%s=%d\n",
				      WG_DYNAMIC_KEY[req->cmd], 1);
		ret = response_request_ip(cur, req->pubkey, &lease);
		if (ret) {
			errmsg = "Out of IP addresses"; /* TODO: distinguish */
			break;
		}

		add_allowed_ips(req->pubkey, &lease->ipv4, &lease->ipv6);
		serialise_lease((char *)buf, sizeof buf, &msglen, lease);
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

static void setup_socket()
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
}

static void cleanup()
{
	leases_free();
	kh_destroy(allowedht, allowedips_ht);
	wg_free_device(device);

	if (sockfd >= 0)
		close(sockfd);

	if (epollfd >= 0)
		close(epollfd);

	for (int i = 0; i < MAX_CONNECTIONS; ++i) {
		if (requests[i].fd < 0)
			continue;

		close_connection(&requests[i]);
	}
}

static void setup()
{
	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

	leases_init("leases_file");
	allowedips_ht = kh_init(allowedht);

	for (int i = 0; i < MAX_CONNECTIONS; ++i)
		requests[i].fd = -1;

	if (atexit(cleanup))
		die("Failed to set exit function\n");

	rebuild_allowedips_ht();

	if (!validate_link_local_ip(device->ifindex))
		// TODO: assign IP instead?
		die("%s needs to have %s assigned\n", wg_interface,
		    WG_DYNAMIC_ADDR);

	if (!valid_peer_found(device))
		die("%s has no peers with link-local allowedips\n",
		    wg_interface);

	setup_socket(&sockfd);
}

static int get_avail_request()
{
	for (int nfds = 0;; ++nfds) {
		if (nfds >= MAX_CONNECTIONS)
			return -1;

		if (requests[nfds].fd < 0)
			return nfds;
	}
}

static void accept_incoming(int sockfd, int epollfd,
			    struct wg_dynamic_request *requests)
{
	int n, fd;
	struct epoll_event ev;

	while ((n = get_avail_request()) >= 0) {
		fd = accept_connection(sockfd, &requests[n].pubkey);
		if (fd < 0) {
			if (fd == -ENOENT) {
				debug("Failed to match IP to pubkey\n");
				continue;
			} else if (fd != -EAGAIN && fd != -EWOULDBLOCK) {
				debug("Failed to accept connection: %s\n",
				      strerror(-fd));
				continue;
			}

			break;
		}

		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = &requests[n];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
			fatal("epoll_ctl()");

		requests[n].fd = fd;
	}
}

static void handle_event(struct wg_dynamic_request *req, uint32_t events)
{
	if (!req) {
		accept_incoming(sockfd, epollfd, requests);
		return;
	}

	if (events & EPOLLIN) {
		if (handle_request(req, send_response, send_error))
			close_connection(req);
	}

	if (events & EPOLLOUT) {
		size_t off = send_message(req->fd, req->buf, &req->buflen);
		if (req->buflen)
			memmove(req->buf, req->buf + off, req->buflen);
		else
			close_connection(req);
	}
}

static void poll_loop()
{
	struct epoll_event ev, events[MAX_CONNECTIONS];
	epollfd = epoll_create1(0);
	if (epollfd == -1)
		fatal("epoll_create1()");

	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = NULL;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1)
		fatal("epoll_ctl()");

	while (1) {
		int nfds = epoll_wait(epollfd, events, MAX_CONNECTIONS, -1);
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
	if (argc != 2)
		usage();

	wg_interface = argv[1];
	setup();

	poll_loop();

	return 0;
}
