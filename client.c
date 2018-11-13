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
#include "protocol.h"
#include "client.h"

bool is_server_in_allowed_ips(const char iface[])
{
	/* TODO: check if IP is in wg allowed ips, etc */
	return true;
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
