/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016-2019 WireGuard LLC. All Rights Reserved.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 */

#include "siphash.h"

static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
	return (word << shift) | (word >> (64 - shift));
}

#define SIPROUND                                                               \
	do {                                                                   \
		v0 += v1;                                                      \
		v1 = rol64(v1, 13);                                            \
		v1 ^= v0;                                                      \
		v0 = rol64(v0, 32);                                            \
		v2 += v3;                                                      \
		v3 = rol64(v3, 16);                                            \
		v3 ^= v2;                                                      \
		v0 += v3;                                                      \
		v3 = rol64(v3, 21);                                            \
		v3 ^= v0;                                                      \
		v2 += v1;                                                      \
		v1 = rol64(v1, 17);                                            \
		v1 ^= v2;                                                      \
		v2 = rol64(v2, 32);                                            \
	} while (0)

#define PREAMBLE(len)                                                          \
	uint64_t v0 = 0x736f6d6570736575ULL;                                   \
	uint64_t v1 = 0x646f72616e646f6dULL;                                   \
	uint64_t v2 = 0x6c7967656e657261ULL;                                   \
	uint64_t v3 = 0x7465646279746573ULL;                                   \
	uint64_t b = ((uint64_t)(len)) << 56;                                  \
	v3 ^= key->key[1];                                                     \
	v2 ^= key->key[0];                                                     \
	v1 ^= key->key[1];                                                     \
	v0 ^= key->key[0];

#define POSTAMBLE                                                              \
	v3 ^= b;                                                               \
	SIPROUND;                                                              \
	SIPROUND;                                                              \
	v0 ^= b;                                                               \
	v2 ^= 0xff;                                                            \
	SIPROUND;                                                              \
	SIPROUND;                                                              \
	SIPROUND;                                                              \
	SIPROUND;                                                              \
	return (v0 ^ v1) ^ (v2 ^ v3);

uint64_t __siphash_aligned(const void *data, size_t len,
			   const siphash_key_t *key)
{
	const uint8_t *end = data + len - (len % sizeof(uint64_t));
	const uint8_t left = len & (sizeof(uint64_t) - 1);
	uint64_t m;
	PREAMBLE(len)
	for (; data != end; data += sizeof(uint64_t)) {
		m = le64toh(*((uint64_t *)data));
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
	switch (left) {
	case 7:
		b |= ((uint64_t)end[6]) << 48; /* fall through */
	case 6:
		b |= ((uint64_t)end[5]) << 40; /* fall through */
	case 5:
		b |= ((uint64_t)end[4]) << 32; /* fall through */
	case 4:
		b |= le32toh(*((uint32_t *)data));
		break;
	case 3:
		b |= ((uint64_t)end[2]) << 16; /* fall through */
	case 2:
		b |= le16toh(*((uint16_t *)data));
		break;
	case 1:
		b |= end[0];
	}
	POSTAMBLE
}

/**
 * siphash_1u64 - compute 64-bit siphash PRF value of a u64
 * @first: first u64
 * @key: the siphash key
 */
uint64_t siphash_1u64(const uint64_t first, const siphash_key_t *key)
{
	PREAMBLE(8)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	POSTAMBLE
}

/**
 * siphash_2u64 - compute 64-bit siphash PRF value of 2 u64
 * @first: first u64
 * @second: second u64
 * @key: the siphash key
 */
uint64_t siphash_2u64(const uint64_t first, const uint64_t second,
		      const siphash_key_t *key)
{
	PREAMBLE(16)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	POSTAMBLE
}

/**
 * siphash_3u64 - compute 64-bit siphash PRF value of 3 u64
 * @first: first u64
 * @second: second u64
 * @third: third u64
 * @key: the siphash key
 */
uint64_t siphash_3u64(const uint64_t first, const uint64_t second,
		      const uint64_t third, const siphash_key_t *key)
{
	PREAMBLE(24)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	v3 ^= third;
	SIPROUND;
	SIPROUND;
	v0 ^= third;
	POSTAMBLE
}

/**
 * siphash_4u64 - compute 64-bit siphash PRF value of 4 u64
 * @first: first u64
 * @second: second u64
 * @third: third u64
 * @forth: forth u64
 * @key: the siphash key
 */
uint64_t siphash_4u64(const uint64_t first, const uint64_t second,
		      const uint64_t third, const uint64_t forth,
		      const siphash_key_t *key)
{
	PREAMBLE(32)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	v3 ^= third;
	SIPROUND;
	SIPROUND;
	v0 ^= third;
	v3 ^= forth;
	SIPROUND;
	SIPROUND;
	v0 ^= forth;
	POSTAMBLE
}

uint64_t siphash_1u32(const uint32_t first, const siphash_key_t *key)
{
	PREAMBLE(4)
	b |= first;
	POSTAMBLE
}

uint64_t siphash_3u32(const uint32_t first, const uint32_t second,
		      const uint32_t third, const siphash_key_t *key)
{
	uint64_t combined = (uint64_t)second << 32 | first;
	PREAMBLE(12)
	v3 ^= combined;
	SIPROUND;
	SIPROUND;
	v0 ^= combined;
	b |= third;
	POSTAMBLE
}
