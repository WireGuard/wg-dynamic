/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <stdint.h>

uint64_t random_bounded(uint64_t bound);

#endif
