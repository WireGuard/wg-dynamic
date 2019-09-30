/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __IPM_H__
#define __IPM_H__

#include <stdint.h>

#include "common.h"

void ipm_init();
void ipm_free();
int ipm_newaddr_v4(uint32_t ifindex, const struct in_addr *ip);
int ipm_newaddr_v6(uint32_t ifindex, const struct in6_addr *ip);
int ipm_deladdr_v4(uint32_t ifindex, const struct in_addr *ip);
int ipm_deladdr_v6(uint32_t ifindex, const struct in6_addr *ip);
int ipm_getlladdr(uint32_t ifindex, struct wg_combined_ip *addr);

#endif
