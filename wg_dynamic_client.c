/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include "client.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char *PROG_NAME;

static void show_usage()
{
	fprintf(stderr, "Usage: %s <interface>\n\n", PROG_NAME);
}

int main(int argc, char *argv[])
{
	const char *iface;
	int sock;

	PROG_NAME = argv[0];

	if (argc == 1) {
		show_usage();
		return EXIT_FAILURE;
	}

	iface = argv[1];

	/*if (!is_server_in_allowed_ips(iface)) {
		fprintf(stderr, "server is not in allowed IPs for tunnel %s\n",
			iface);
		return EXIT_FAILURE;
        }*/

	if ((sock = connect_to_server(argv[1])) < 0) {
		fprintf(stderr, "error connecting to server: %s\n",
			strerror(-sock));
		return EXIT_FAILURE;
	}

	if ((sock = close_connection(sock)) < 0) {
		fprintf(stderr, "error closing socket: %s\n", strerror(-sock));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
