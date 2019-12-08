/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016-2019 WireGuard LLC. All Rights Reserved.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 */

#ifndef _LINUX_SIPHASH_H
#define _LINUX_SIPHASH_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint64_t key[2];
} siphash_key_t;

static inline bool siphash_key_is_zero(const siphash_key_t *key)
{
	return !(key->key[0] | key->key[1]);
}

uint64_t __siphash_aligned(const void *data, size_t len,
			   const siphash_key_t *key);

uint64_t siphash_1u64(const uint64_t a, const siphash_key_t *key);
uint64_t siphash_2u64(const uint64_t a, const uint64_t b,
		      const siphash_key_t *key);
uint64_t siphash_3u64(const uint64_t a, const uint64_t b, const uint64_t c,
		      const siphash_key_t *key);
uint64_t siphash_4u64(const uint64_t a, const uint64_t b, const uint64_t c,
		      const uint64_t d, const siphash_key_t *key);
uint64_t siphash_1u32(const uint32_t a, const siphash_key_t *key);
uint64_t siphash_3u32(const uint32_t a, const uint32_t b, const uint32_t c,
		      const siphash_key_t *key);

static inline uint64_t siphash_2u32(const uint32_t a, const uint32_t b,
				    const siphash_key_t *key)
{
	return siphash_1u64((uint64_t)b << 32 | a, key);
}
static inline uint64_t siphash_4u32(const uint32_t a, const uint32_t b,
				    const uint32_t c, const uint32_t d,
				    const siphash_key_t *key)
{
	return siphash_2u64((uint64_t)b << 32 | a, (uint64_t)d << 32 | c, key);
}

static inline uint64_t ___siphash_aligned(const uint64_t *data, size_t len,
					  const siphash_key_t *key)
{
	if (__builtin_constant_p(len) && len == 4)
		return siphash_1u32(le32toh(*((const uint32_t *)data)), key);
	if (__builtin_constant_p(len) && len == 8)
		return siphash_1u64(le64toh(data[0]), key);
	if (__builtin_constant_p(len) && len == 16)
		return siphash_2u64(le64toh(data[0]), le64toh(data[1]), key);
	if (__builtin_constant_p(len) && len == 24)
		return siphash_3u64(le64toh(data[0]), le64toh(data[1]),
				    le64toh(data[2]), key);
	if (__builtin_constant_p(len) && len == 32)
		return siphash_4u64(le64toh(data[0]), le64toh(data[1]),
				    le64toh(data[2]), le64toh(data[3]), key);
	return __siphash_aligned(data, len, key);
}

/**
 * siphash - compute 64-bit siphash PRF value
 * @data: buffer to hash
 * @size: size of @data
 * @key: the siphash key
 */
static inline uint64_t siphash(const void *data, size_t len,
			       const siphash_key_t *key)
{
	return ___siphash_aligned(data, len, key);
}

#endif /* _LINUX_SIPHASH_H */
