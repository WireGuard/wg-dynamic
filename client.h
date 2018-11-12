/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>

bool is_server_in_allowed_ips(const char iface[]);
int connect_to_server();
int close_connection(int sock);

#endif
