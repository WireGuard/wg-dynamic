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
static uint32_t leasetime = WG_DYNAMIC_DEFAULT_LEASETIME;

static int sockfd = -1;
static int epollfd = -1;
static struct mnl_socket *nlsock = NULL;

KHASH_MAP_INIT_INT64(allowedht, wg_key *)
khash_t(allowedht) * allowedips_ht;

struct mnl_cb_data {
	uint32_t ifindex;
	bool valid_ip_found;
};

static void usage()
{
	die("usage: %s <wg-interface> [<leasetime>]\n", progname);
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

static bool send_error(struct wg_dynamic_request *req, int error)
{
	char buf[MAX_RESPONSE_SIZE];
	size_t msglen = 0;

	debug("Parse error, errno=%d\n", error);

	print_to_buf(buf, sizeof buf, &msglen, "errno=%d\nerrmsg=%s\n\n",
		     E_INVALID_REQ, WG_DYNAMIC_ERR[E_INVALID_REQ]);

	return send_message(req, buf, msglen);
}

static size_t serialize_request_ip(char *buf, size_t len,
				   const struct wg_dynamic_lease *lease)
{
	char addrbuf[INET6_ADDRSTRLEN];
	size_t off = 0;

	print_to_buf(buf, len, &off, "request_ip=1\n");

	if (lease->ipv4.s_addr) {
		if (!inet_ntop(AF_INET, &lease->ipv4, addrbuf, sizeof addrbuf))
			fatal("inet_ntop()");

		print_to_buf(buf, len, &off, "ipv4=%s/%d\n", addrbuf, 32);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&lease->ipv6)) {
		if (!inet_ntop(AF_INET6, &lease->ipv6, addrbuf, sizeof addrbuf))
			fatal("inet_ntop()");

		print_to_buf(buf, len, &off, "ipv6=%s/%d\n", addrbuf, 128);
	}

	print_to_buf(buf, len, &off, "leasestart=%u\nleasetime=%u\n",
		     lease->start_real, lease->leasetime);

	return off;
}

static void adjust_allowed_ips(wg_key pubkey, struct in_addr *ipv4,
			       struct in6_addr *ipv6)
{
	wg_allowedip lladdr, allowed_v4, allowed_v6;
	wg_peer peer = { 0 };
	wg_device dev = {.first_peer = &peer };

	strcpy(dev.name, wg_interface);
	memcpy(peer.public_key, pubkey, sizeof peer.public_key);
	wg_allowedip **cur = &peer.first_allowedip;

	wg_peer *ourpeer;
	wg_for_each_peer (device, ourpeer) {
		if (!memcmp(ourpeer->public_key, pubkey, sizeof(wg_key))) {
			peer.flags |= WGPEER_REPLACE_ALLOWEDIPS;
			memcpy(peer.public_key, pubkey, sizeof(wg_key));

			wg_allowedip *allowedip;
			wg_for_each_allowedip (ourpeer, allowedip) {
				if (allowedip->family == AF_INET6 &&
				    allowedip->cidr == 128 &&
				    IN6_IS_ADDR_LINKLOCAL(&allowedip->ip6)) {
					lladdr.family = AF_INET6;
					memcpy(&lladdr.ip6, &allowedip->ip6,
					       sizeof(struct in6_addr));
					lladdr.cidr = 128;
					*cur = &lladdr;
					cur = &lladdr.next_allowedip;
					break;
				}
			}
			break;
		}
	}

	if (ipv4 && ipv4->s_addr) {
		allowed_v4 = (wg_allowedip){
			.family = AF_INET, .cidr = 32, .ip4 = *ipv4,
		};
		*cur = &allowed_v4;
		cur = &allowed_v4.next_allowedip;
	}

	if (ipv6 && !IN6_IS_ADDR_UNSPECIFIED(ipv6)) {
		allowed_v6 = (wg_allowedip){
			.family = AF_INET6, .cidr = 128, .ip6 = *ipv6,
		};
		*cur = &allowed_v6;
	}

	if ((ipv4 && ipv4->s_addr) || (ipv6 && !IN6_IS_ADDR_UNSPECIFIED(ipv6)))
		if (wg_set_device(&dev))
			fatal("wg_set_device()");
}

/* TODO: have UPDATES contain {wg_key, ip4, ip6} and remove only matching addrs */
/* FIXME: rename to remove_allowed_ips() */
static void update_allowed_ips(wg_key *updates, int nupdates)
{
	wg_device newdev = { 0 };
	wg_peer newpeers[WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 },
		**nextpp = &newdev.first_peer;
	wg_allowedip newallowedips[WG_DYNAMIC_LEASE_CHUNKSIZE] = { 0 };

	int newpeers_idx = 0;
	wg_peer *peer;
	wg_for_each_peer (device, peer) {
		for (int i = 0; i < nupdates; i++) {
			if (!memcmp(peer->public_key, updates[i],
				    sizeof(wg_key))) {
				wg_peer *pp = &newpeers[newpeers_idx];
				pp->flags |= WGPEER_REPLACE_ALLOWEDIPS;
				memcpy(pp->public_key, peer->public_key,
				       sizeof(wg_key));

				/* Whacking all addrs except the first (!) link-local /128 . */
				wg_allowedip *allowedip;
				wg_for_each_allowedip (peer, allowedip) {
					if (allowedip->family == AF_INET6 &&
					    allowedip->cidr == 128 &&
					    IN6_IS_ADDR_LINKLOCAL(
						    &allowedip->ip6)) {
						wg_allowedip *aip =
							&newallowedips
								[newpeers_idx];
						aip->family = AF_INET6;
						memcpy(&aip->ip6,
						       &allowedip->ip6,
						       sizeof(struct in6_addr));
						aip->cidr = 128;
						pp->first_allowedip = aip;
						break;
					}
				}
				newpeers_idx++;
				*nextpp = pp;
				nextpp = &pp->next_peer;
				break; /* Assuming no duplicated pubkeys in updates. */
			}
		}
	}

	if (newpeers_idx) {
		strcpy(newdev.name, wg_interface);
		if (wg_set_device(&newdev))
			fatal("wg_set_device()");
	}
}

static int response_request_ip(struct wg_dynamic_attr *cur, wg_key pubkey,
			       struct wg_dynamic_lease **lease_out)
{
	struct in_addr *ipv4 = NULL;
	struct in6_addr *ipv6 = NULL;
	struct wg_dynamic_lease *current = NULL;

	while (cur) {
		switch (cur->key) {
		case WGKEY_IPV4:
			ipv4 = &((struct wg_combined_ip *)cur->value)->ip4;
			break;
		case WGKEY_IPV6:
			ipv6 = &((struct wg_combined_ip *)cur->value)->ip6;
			break;
		default:
			debug("Ignoring invalid attribute for request_ip: %d\n",
			      cur->key);
		}
		cur = cur->next;
	}

	current = get_leases(pubkey);
	debug("current lease: %s\n", lease_to_str(current));

	*lease_out = new_lease(pubkey, leasetime, ipv4, ipv6, current);

	release_lease(current, pubkey);

	return E_NO_ERROR;
}

static bool send_response(struct wg_dynamic_request *req)
{
	char buf[MAX_RESPONSE_SIZE];
	struct wg_dynamic_attr *cur = req->first;
	size_t msglen = 0;
	int ret = 0;

	switch (req->cmd) {
	case WGKEY_REQUEST_IP: {
		struct wg_dynamic_lease *lease = NULL;
		ret = response_request_ip(cur, req->pubkey, &lease);
		if (ret)
			break;

		if (lease) {
			adjust_allowed_ips(req->pubkey, &lease->ipv4,
					   &lease->ipv6);
			msglen = serialize_request_ip(buf, sizeof buf, lease);
		}
		break;
	}
	default:
		debug("Unknown command: %d\n", req->cmd);
		BUG();
	}

	if (ret) {
		print_to_buf(buf, sizeof buf, &msglen,
			     "request_ip=1\nerrno=%d\nerrmsg=%s\n\n", ret,
			     WG_DYNAMIC_ERR[ret]);

		return send_message(req, buf, msglen);
	}

	print_to_buf(buf, sizeof buf, &msglen, "errno=0\n\n");
	return send_message(req, buf, msglen);
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
		if (requests[i].fd < 0)
			continue;

		close_connection(&requests[i]);
	}
}

static void setup()
{
	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

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

	setup_sockets();
	leases_init("leases_file", nlsock);
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

static void handle_event(void *ptr, uint32_t events)
{
	struct wg_dynamic_request *req;

	if (ptr == &sockfd) {
		accept_incoming(sockfd, epollfd, requests);
		return;
	}

	if (ptr == nlsock) {
		leases_update_pools(nlsock);
		return;
	}

	req = (struct wg_dynamic_request *)ptr;
	if (events & EPOLLIN) {
		if (handle_request(req, send_response, send_error))
			close_connection(req);
	}

	if (events & EPOLLOUT) {
		if (send_message(req, req->buf, req->buflen))
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
	ev.data.ptr = &sockfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev))
		fatal("epoll_ctl()");

	ev.events = EPOLLIN;
	ev.data.ptr = nlsock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, mnl_socket_get_fd(nlsock), &ev))
		fatal("epoll_ctl()");

	while (1) {
		time_t next = leases_refresh(update_allowed_ips) * 1000;
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
	if (argc < 2 || argc > 3)
		usage();

	wg_interface = argv[1];
	if (argc == 3) {
		char *endptr;
		leasetime = (uint32_t) strtoul(argv[2], &endptr, 10);
		if (*endptr)
			usage();
	}

	setup();

	poll_loop();

	return 0;
}
