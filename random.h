/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool get_random_bytes(uint8_t *out, size_t len);
uint64_t random_u64();
uint64_t random_bounded(uint64_t bound);

#endif
