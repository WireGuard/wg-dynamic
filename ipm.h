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
void ipm_newaddr(uint32_t ifindex, const struct wg_combined_ip *addr);
void ipm_deladdr(uint32_t ifindex, const struct wg_combined_ip *addr);
int ipm_getlladdr(uint32_t ifindex, struct wg_combined_ip *addr);

#endif
