/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */
#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
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

static struct in_addr ipv4;
static struct in6_addr ipv6;
static bool ipv4_assigned = false, ipv6_assigned = false;

static wg_device *device = NULL;
static int sockfd = -1;

static volatile sig_atomic_t should_exit = 0;

static void usage()
{
	die("usage: %s <wg-interface>\n", progname);
}

/* NOTE: do NOT call exit() in here */
static void cleanup()
{
	if (ipv4_assigned && ipm_deladdr_v4(device->ifindex, &ipv4))
		debug("Failed to cleanup ipv4 address\n");
	if (ipv6_assigned && ipm_deladdr_v6(device->ifindex, &ipv6))
		debug("Failed to cleanup ipv6 address\n");

	if (sockfd >= 0)
		close(sockfd);

	ipm_free();
	wg_free_device(device);
}

static void handler(int signum)
{
	UNUSED(signum);
	should_exit = 1;
}

static void check_signal()
{
	if (should_exit)
		exit(EXIT_FAILURE);
}

static int request_ip(struct wg_dynamic_request_ip *rip)
{
	unsigned char buf[RECV_BUFSIZE + MAX_LINESIZE];
	size_t msglen, remaining = 0, off = 0;
	struct sockaddr_in6 dstaddr = {
		.sin6_family = AF_INET6,
		.sin6_addr = well_known,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_scope_id = device->ifindex,
	};
	struct sockaddr_in6 srcaddr = {
		.sin6_family = AF_INET6,
		.sin6_addr = lladdr,
		.sin6_port = htons(WG_DYNAMIC_PORT),
		.sin6_scope_id = device->ifindex,
	};
	struct wg_dynamic_request req = {
		.cmd = WGKEY_REQUEST_IP,
		.version = 1,
		.result = rip,
	};
	struct timeval timeout = { .tv_sec = 30 };
	ssize_t ret;
	int val = 1;

	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
		fatal("Creating a socket failed");

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val))
		fatal("setsockopt(SO_REUSEADDR)");

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
		       sizeof timeout))
		fatal("setsockopt(SO_RCVTIMEO)");

	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
		       sizeof timeout))
		fatal("setsockopt(SO_SNDTIMEO)");

	if (bind(sockfd, (struct sockaddr *)&srcaddr, sizeof(srcaddr)))
		fatal("Binding socket failed");

	if (connect(sockfd, (struct sockaddr *)&dstaddr, sizeof(dstaddr)))
		fatal("connect()");

	rip->has_ipv4 = rip->has_ipv6 = true;
	if (ipv4_assigned)
		memcpy(&rip->ipv4, &ipv4, sizeof rip->ipv4);

	if (ipv6_assigned)
		memcpy(&rip->ipv6, &ipv6, sizeof rip->ipv6);

	msglen = serialize_request_ip(true, (char *)buf, RECV_BUFSIZE, rip);
	do {
		ssize_t written = write(sockfd, buf + off, msglen - off);
		if (written == -1) {
			if (errno == EINTR) {
				check_signal();
				continue;
			}

			fatal("write()");
		}

		off += written;
	} while (off < msglen);

	memset(rip, 0, sizeof *rip);

	while ((ret = handle_request(sockfd, &req, buf, &remaining)) <= 0) {
		if (ret == 0) {
			check_signal();
			continue;
		}

		if (close(sockfd))
			debug("Failed to close socket: %s\n", strerror(errno));

		log_err("Server communication error.\n");
		return -1;
	}

	if (remaining > 0)
		log_err("Warning: discarding %zu extra bytes sent by the server\n",
			remaining);

	if (rip->wg_errno && !rip->has_ipv4 && !rip->has_ipv6) {
		if (rip->errmsg) {
			log_err("Server refused request: %s\n", rip->errmsg);
			return -1;
		} else if (rip->wg_errno <= ARRAY_SIZE(WG_DYNAMIC_ERR) - 1) {
			log_err("Server refused request: %s\n",
				WG_DYNAMIC_ERR[rip->wg_errno]);
		} else {
			log_err("Server refused request: unknown error code %u\n",
				rip->wg_errno);
		}

		free(rip->errmsg); /* TODO: this could be done cleaner */
		return -1;
	}
	free(rip->errmsg);

	if (!ipv4_assigned || memcmp(&ipv4, &rip->ipv4, sizeof ipv4)) {
		if (ipv4_assigned && ipm_deladdr_v4(device->ifindex, &ipv4))
			fatal("ipm_deladdr_v4()");

		if (rip->has_ipv4) {
			memcpy(&ipv4, &rip->ipv4, sizeof ipv4);
			if (ipm_newaddr_v4(device->ifindex, &ipv4))
				fatal("ipm_newaddr_v4()");
			ipv4_assigned = true;
		} else {
			memset(&ipv4, 0, sizeof ipv4);
			ipv4_assigned = false;
		}
	}

	if (!ipv6_assigned || memcmp(&ipv6, &rip->ipv6, sizeof ipv6)) {
		if (ipv6_assigned && ipm_deladdr_v6(device->ifindex, &ipv6))
			fatal("ipm_deladdr_v6()");

		if (rip->has_ipv6) {
			memcpy(&ipv6, &rip->ipv6, sizeof ipv6);
			if (ipm_newaddr_v6(device->ifindex, &ipv6))
				fatal("ipm_newaddr_v6()");
			ipv6_assigned = true;
		} else {
			memset(&ipv6, 0, sizeof ipv6);
			ipv6_assigned = false;
		}
	}

	if (close(sockfd))
		debug("Failed to close socket: %s\n", strerror(errno));

	return 0;
}

static void setup()
{
	struct sigaction sa = { .sa_handler = handler, .sa_flags = 0 };
	struct wg_combined_ip ip;
	int ret;

	if (atexit(cleanup))
		die("Failed to set exit function\n");

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1)
		fatal("sigaction()");

	if (wg_get_device(&device, wg_interface))
		fatal("Unable to access interface %s", wg_interface);

	if (inet_pton(AF_INET6, WG_DYNAMIC_ADDR, &well_known) != 1)
		fatal("inet_pton()");

	ipm_init();

	ret = ipm_getlladdr(device->ifindex, &ip);
	if (ret == -1)
		fatal("ipm_getlladdr()");

	if (ret == -2 || ip.family != AF_INET6)
		die("%s needs to be assigned an IPv6 link local address\n",
		    wg_interface);

	if (ret == -3)
		die("Interface must not have multiple link-local addresses assigned\n");

	if (ip.cidr != 128)
		die("Link-local address must have a CIDR of 128\n");

	memcpy(&lladdr, &ip, 16);
}

static void xnanosleep(time_t duration)
{
	struct timespec rem, timeout = { .tv_sec = duration };
	int ret;

	while ((ret = clock_nanosleep(CLOCK_BOOTTIME, 0, &timeout, &rem))) {
		if (ret == EINTR) {
			check_signal();
			memcpy(&timeout, &rem, sizeof timeout);
			continue;
		}

		die("clock_nanosleep(): %s\n", strerror(ret));
	}
}

static void loop()
{
	struct wg_dynamic_request_ip rip = { 0 };
	struct timespec tsend, trecv;
	time_t expires, timeout;

	if (clock_gettime(CLOCK_REALTIME, &tsend))
		fatal("clock_gettime(CLOCK_REALTIME)");

	if (request_ip(&rip)) {
		/* TODO: implement some sort of exponential backoff */
		log_err("Trying again in 30s.\n");
		xnanosleep(30);
		return;
	}

	if (clock_gettime(CLOCK_REALTIME, &trecv))
		fatal("clock_gettime(CLOCK_REALTIME)");

	if (tsend.tv_sec < rip.start + 5 || rip.start > trecv.tv_sec + 5)
		expires = tsend.tv_sec + rip.leasetime;
	else
		expires = MIN(rip.leasetime, trecv.tv_sec) + rip.leasetime;

	if (expires <= trecv.tv_sec) {
		log_err("Warning: lease we tried to aquire already expired\n");
		return;
	}

	/* TODO: implement random jitter */
	timeout = (expires - trecv.tv_sec);
	timeout -= MIN(30, timeout * 0.5);

	debug("Sleeping for %zus\n", timeout);
	xnanosleep(timeout);
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
