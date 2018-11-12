/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "server.h"

bool is_wg_up_on_iface(const char iface[])
{
	/* TODO */
	return true;
}

int setup_server()
{
	int sock = -1;
	int reuseaddr = 1;
	int ret;
	struct sockaddr_in6 addr;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		return -errno;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
		   sizeof(reuseaddr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(WG_DYNAMIC_SERVER_PORT);
	inet_pton(AF_INET6, WG_DYNAMIC_SERVER_IP, &addr.sin6_addr);
	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		return -errno;
	}
	ret = listen(sock, 5);
	if (ret < 0) {
		return -errno;
	}
	return sock;
}

static void handle_connection(int conn, struct sockaddr_in6 addr)
{
	/* TODO */
}

int handle_connections(int sock)
{
	int conn = -1;
	pid_t pid = -1;
	struct sockaddr_in6 addr;
	socklen_t addr_size = sizeof(addr);
	;
	while (1) {
		conn = accept(sock, (struct sockaddr *)&addr, &addr_size);
		if (conn < 0) {
			return -errno;
		}
		pid = fork();
		if (pid < 0) {
			return -errno;
		} else if (pid == 0) {
			close(sock);
			handle_connection(conn, addr);
			close(conn);
			exit(EXIT_SUCCESS);
		} else {
			close(conn);
		}
	}
	return 0;
}
