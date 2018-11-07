/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include <stdlib.h>
#include <stdio.h>

const char *PROG_NAME;

/* TODO: break this function out into another file when it gets big */
static void setup_server(char *interface)
{
}

static void show_usage()
{
	fprintf(stderr, "Usage: %s <interface>\n\n", PROG_NAME);
}

int main(int argc, char *argv[])
{
	PROG_NAME = argv[0];

	if (argc == 1) {
		show_usage();
		return EXIT_FAILURE;
	}

	setup_server(argv[1]);

	return EXIT_SUCCESS;
}
