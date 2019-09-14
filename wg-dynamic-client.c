/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */
#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "dbg.h"
#include "ipm.h"
#include "netlink.h"

static const char *progname;
static const char *wg_interface;
static struct in6_addr well_known;
static struct in6_addr lladdr;

static struct wg_combined_ip ipv4, ipv6; // TODO:
static bool ipv4_assign = false, ipv6_assign = false;

static wg_device *device = NULL;

static void usage()
{
	die("usage: %s <wg-interface>\n", progname);
}

static void cleanup()
{
	if (ipv4_assign)
		ipm_deladdr(device->ifindex, &ipv4);
	if (ipv6_assign)
		ipm_deladdr(device->ifindex, &ipv6);

	ipm_free();
	wg_free_device(device);
}

#include "ip_util.h"
static int sockfd = -1;

static void preamble()
{
	struct sockaddr_in6 dstaddr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_addr = well_known,
		.sin6_scope_id = device->ifindex,
	};
	struct sockaddr_in6 srcaddr = {
		.sin6_family = AF_INET6,
		.sin6_addr = lladdr,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_scope_id = device->ifindex,
	};

	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
		fatal("Creating a socket failed");
	if (bind(sockfd, (struct sockaddr *)&srcaddr, sizeof(srcaddr)))
		fatal("Binding socket failed");

	if (connect(sockfd, (struct sockaddr *)&dstaddr, sizeof(dstaddr)))
		fatal("connect()");
}

static void postamble()
{
	close(sockfd); // TODO:
}

static int request_ip()
{
	char buf[4096];
	struct wg_dynamic_request req = {
		.cmd = WGKEY_REQUEST_IP
	}; // TODO: version
	struct wg_combined_ip new_ipv4, new_ipv6;
	struct wg_dynamic_attr *attr = req.first;
	size_t msglen = 0, off = 0;
	char ip4str[INET_ADDRSTRLEN], ip6str[INET6_ADDRSTRLEN];
	uint32_t err;
	int ret;

	strcpy(buf, "request_ip=1\n");
	msglen = strlen(buf);

	if (ipv4_assign) {
		if (!inet_ntop(AF_INET, &ipv4.ip4, ip4str, sizeof ip4str))
			fatal("inet_ntop()");

		print_to_buf(buf, sizeof buf, &msglen, "ipv4=%s/32\n", ip4str);
	}

	if (ipv6_assign) {
		if (!inet_ntop(AF_INET6, &ipv6.ip6, ip6str, sizeof ip6str))
			fatal("inet_ntop()");

		print_to_buf(buf, sizeof buf, &msglen, "ipv6=%s/128\n", ip6str);
	}

	buf[msglen++] = '\n';

	do {
		ssize_t written = write(sockfd, buf + off, msglen - off);
		if (written == -1) {
			if (errno == EINTR)
				continue;

			fatal("write()");
		}

		off += written;
	} while (off < msglen);

	ret = handle_request(sockfd, &req);
	if (ret != 0) {
		free_wg_dynamic_request(&req);
		return ret;
	}

	while (attr) {
		switch (attr->key) {
		case WGKEY_IPV4:
			memcpy(&new_ipv4, attr->value, sizeof new_ipv4);
			ipv4.cidr = 32;
			debug("Recieved addr: %y/%d\n", &new_ipv4.ip4,
			      new_ipv4.cidr);
			break;
		case WGKEY_IPV6:
			memcpy(&new_ipv6, attr->value, sizeof new_ipv6);
			ipv6.cidr = 128;
			break;
		case WGKEY_ERRNO:
			err = *attr->value;
			break;
		case WGKEY_ERRMSG:
			break;
		default:
			debug("Ignoring unknown attribute for request_ip: %d\n",
			      attr->key);
		}

		attr = attr->next;
	}

	if (err != 0) {
		free_wg_dynamic_request(&req);
		return -err;
	}

	if (ipv4_assign)
		ipm_deladdr(device->ifindex, &ipv4);

	if (ipv6_assign)
		ipm_deladdr(device->ifindex, &ipv6);

	memcpy(&ipv4, &new_ipv4, sizeof ipv4);
	memcpy(&ipv6, &new_ipv6, sizeof ipv6);

	ipm_newaddr(device->ifindex, &ipv4);
	ipm_newaddr(device->ifindex, &ipv6);
	ipv4_assign = ipv6_assign = true;

	free_wg_dynamic_request(&req);
}

static void setup()
{
	struct wg_combined_ip ip;
	int ret;

	if (atexit(cleanup))
		die("Failed to set exit function\n");

	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

	ipm_init();

	ret = ipm_getlladdr(device->ifindex, &ip);
	if (ret == -1 || ip.family != AF_INET6)
		die("%s needs to be assigned an IPv6 link local address\n",
		    wg_interface);

	if (ret == -2)
		die("Interface must not have multiple link-local addresses assigned\n");

	if (ip.cidr != 128)
		die("Link-local address must have a CIDR of 128\n");

	memcpy(&lladdr, &ip, 16);
}

static void loop()
{
	int ret;

	preamble();
	ret = request_ip();
	if (ret < 0) {
		/* TODO: differentiate between errors */
		die("Server error: %d\n", -ret);
	} else if (ret == 1) {
		/* TODO: network error, retry later */
		die("Network error");
	} else if (ret == 2) {
		die("Invalid server response");
	}

	postamble();

	// figure out last handshake time
	// sleep until then
	wg_free_device(device);
	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
		fatal("clock_gettime(CLOCK_REALTIME)");

	debug("Last handshake: %zu (%zu)\n",
	      device->first_peer->last_handshake_time.tv_sec,
	      ts.tv_sec - device->first_peer->last_handshake_time.tv_sec);

	time_t test = 180 + device->first_peer->last_handshake_time.tv_sec;

	if (test > ts.tv_sec) {
		struct timespec timeout = {
			.tv_sec = test - ts.tv_sec,
		}, remain;
		debug("Sleeping for %zus\n", timeout.tv_sec);

		if (clock_nanosleep(CLOCK_BOOTTIME, 0, &timeout, &remain))
			fatal("clock_nanosleep()"); // TODO: does not set errno
	}
}

int main(int argc, char *argv[])
{
	progname = argv[0];
	if (argc != 2)
		usage();

	wg_interface = argv[1];
	setup();

	while (1)
		loop();

	return 0;
}
