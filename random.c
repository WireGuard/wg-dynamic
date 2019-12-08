/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dbg.h"

#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_12
#define MAC_OS_X_VERSION_10_12 101200
#endif
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
#include <sys/random.h>
#endif
#endif

bool __attribute__((__warn_unused_result__))
get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret = 0;
	size_t i;
	int fd;

	if (len > 256) {
		errno = EOVERFLOW;
		return false;
	}

#if defined(__OpenBSD__) ||                                                    \
	(defined(__APPLE__) &&                                                 \
	 MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) ||           \
	(defined(__GLIBC__) &&                                                 \
	 (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	if (!getentropy(out, len))
		return true;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	if (syscall(__NR_getrandom, out, len, 0) == (ssize_t)len)
		return true;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return false;
	for (errno = 0, i = 0; i < len; i += ret, ret = 0) {
		ret = read(fd, out + i, len - i);
		if (ret <= 0) {
			ret = errno ? -errno : -EIO;
			break;
		}
	}
	close(fd);
	errno = -ret;
	return i == len;
}

uint64_t random_u64()
{
	uint64_t ret;
	if (!get_random_bytes((uint8_t *)&ret, sizeof(ret)))
		fatal("get_random_bytes()");

	return ret;
}

/* Returns a random number [0, bound) (exclusive) */
uint64_t random_bounded(uint64_t bound)
{
	uint64_t ret, max_mod_bound;

	if (bound < 2)
		return 0;

	max_mod_bound = (1 + ~bound) % bound;

	do {
		ret = random_u64();
	} while (ret < max_mod_bound);

	return ret % bound;
}
