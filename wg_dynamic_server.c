/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include "server.h"

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
	int ret;

	PROG_NAME = argv[0];

	if (argc == 1) {
		show_usage();
		return EXIT_FAILURE;
	}

	iface = argv[1];

	if (!is_wg_up_on_iface(iface)) {
		fprintf(stderr, "no such wireguard iface %s\n", iface);
		return EXIT_FAILURE;
	}

	if ((sock = setup_server(argv[1])) < 0) {
		fprintf(stderr, "error setting up server: %s\n",
			strerror(-sock));
		return EXIT_FAILURE;
	}

	if ((ret = handle_connections(sock)) < 0) {
		fprintf(stderr, "error while handling connections: %s\n",
			strerror(-ret));
		return EXIT_FAILURE;
	}

	/* unreachable */
	return EXIT_FAILURE;
}
