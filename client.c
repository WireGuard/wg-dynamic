/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "wireguard.h"
#include "protocol.h"
#include "client.h"

bool is_server_in_allowed_ips(const char iface[])
{
	unsigned __int128 server_addr;
	unsigned __int128 subnet_mask;
	unsigned __int128 allowed_ip6;
	wg_device *device;
	wg_allowedip *allowedip;
	int ret;

	inet_pton(AF_INET6, WG_DYNAMIC_SERVER_IP, &server_addr);

	ret = wg_get_device(&device, iface);
	if (ret < 0) {
		goto nodevice;
	}

	wg_for_each_allowedip(device->first_peer, allowedip)
	{
		if (allowedip->family == AF_INET6) {
			allowed_ip6 = *(unsigned __int128 *)(&allowedip->ip6);
			subnet_mask = ~0 << allowedip->cidr;
			server_addr &= subnet_mask;
			allowed_ip6 &= subnet_mask;
			if (server_addr == allowed_ip6) {
				return true;
			}
		}
	}
	return false;

nodevice:
	wg_free_device(device);
	return false;
}

int connect_to_server()
{
	int sock = -1;
	int ret;
	struct sockaddr_in6 addr;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		return -errno;
	}
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(WG_DYNAMIC_SERVER_PORT);
	inet_pton(AF_INET6, WG_DYNAMIC_SERVER_IP, &addr.sin6_addr);
	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		return -errno;
	}

	return sock;
}

int close_connection(int sock)
{
	int ret;
	ret = close(sock);
	if (ret < 0) {
		return -errno;
	}
	return 0;
}
