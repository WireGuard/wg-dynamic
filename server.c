/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "wireguard.h"
#include "protocol.h"
#include "protocol.capnp.h"
#include "server.h"

bool is_wg_up_on_iface(const char iface[])
{
	wg_device *device;
	int ret = wg_get_device(&device, iface);
	wg_free_device(device);
	if (ret < 0) {
		return false;
	} else {
		return true;
	}
}

int setup_server(void)
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

static void handle_simpleipv4_request(int conn, struct sockaddr_in6 addr)
{
	printf("Entering simple ipv4 request handler!\n");
}

static void handle_connection(int conn, struct sockaddr_in6 addr)
{
	/* get client message */
	unsigned char client_buf[WgClientMsg_struct_bytes_count];
	if (recv(conn, client_buf, WgClientMsg_struct_bytes_count, 0) < 0) {
		perror("recv failed");
		return;
	}

	/* init capnproto */
	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, client_buf,
					 WgClientMsg_struct_bytes_count, 0);
	if (init_mem_ret != 0) {
		fprintf(stderr, "error initializing capnproto memory\n");
		return;
	}

	/* deserialize client message */
	WgClientMsg_ptr client_root;
	struct WgClientMsg client_msg;
	client_root.p = capn_getp(capn_root(&rc), 0, 1);
	read_WgClientMsg(&client_msg, client_root);

	/* free capnproto */
	capn_free(&rc);

	/* handle client request */
	switch (client_msg.request) {
	case WgClientMsg_WgClientRequestType_simpleIpv4:
		handle_simpleipv4_request(conn, addr);
		break;
	}
}

static void catch_sigchld(int signo)
{
	if (signo == SIGCHLD) {
		wait(NULL);
	}
}

int handle_connections(int sock)
{
	int conn = -1;
	pid_t pid = -1;
	struct sockaddr_in6 addr;
	socklen_t addr_size = sizeof(addr);

	if (signal(SIGCHLD, catch_sigchld) == SIG_ERR) {
		return -errno;
	}

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
