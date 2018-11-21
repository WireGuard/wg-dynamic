/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#ifndef SERVER_H
#define SERVER_H

#include <stdbool.h>

#define BASE_DYN_IP 0xc0a80100

bool is_wg_up_on_iface(const char iface[]);
int setup_server();
int handle_connections(int sock);

#endif
