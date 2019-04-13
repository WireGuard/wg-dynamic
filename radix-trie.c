/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#define _DEFAULT_SOURCE
#include <endian.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dbg.h"
#include "radix-trie.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

struct radix_node {
	struct radix_node *bit[2];
	void *data;
	struct {
		uint64_t left;
		uint64_t right;
	} count;
	uint8_t bits[16];
	uint8_t cidr, bit_at_a, bit_at_b;
};

struct radix_pool {
	struct radix_node *node;
	struct radix_pool *next;
};

static struct radix_pool *pool_start = NULL;

static unsigned int fls64(uint64_t x)
{
	return x ? sizeof(unsigned long long) * 8 - __builtin_clzll(x) : 0;
}

static unsigned int fls(uint32_t x)
{
	return x ? sizeof(unsigned long) * 8 - __builtin_clzl(x) : 0;
}

static unsigned int fls128(uint64_t a, uint64_t b)
{
	return a ? fls64(a) + 64U : fls64(b);
}

/* TODO: portable implementations */
static void swap_endian(uint8_t *dst, const uint8_t *src, uint8_t bits)
{
	if (bits == 32) {
		*(uint32_t *)dst = be32toh(*(const uint32_t *)src);
	} else if (bits == 128) {
		((uint64_t *)dst)[0] = be64toh(((const uint64_t *)src)[0]);
		((uint64_t *)dst)[1] = be64toh(((const uint64_t *)src)[1]);
	}
}

static uint8_t common_bits(const struct radix_node *node, const uint8_t *key,
			   uint8_t bits)
{
	if (bits == 32)
		return 32U - fls(*(const uint32_t *)node->bits ^
				 *(const uint32_t *)key);
	else if (bits == 128)
		return 128U - fls128(*(const uint64_t *)&node->bits[0] ^
					     *(const uint64_t *)&key[0],
				     *(const uint64_t *)&node->bits[8] ^
					     *(const uint64_t *)&key[8]);
	return 0;
}

static struct radix_node *new_node(const uint8_t *key, uint8_t cidr,
				   uint8_t bits)
{
	struct radix_node *node;
	uint64_t mask;

	node = malloc(sizeof *node);
	if (!node)
		fatal("malloc()");

	node->bit[0] = node->bit[1] = node->data = NULL;
	node->cidr = cidr;
	node->bit_at_a = cidr / 8U;
#ifdef __LITTLE_ENDIAN
	node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
	node->bit_at_b = 7U - (cidr % 8U);
	if (bits - cidr > 0 && bits - cidr - 1 < 64)
		node->count.left = node->count.right = 1ULL
						       << (bits - cidr - 1);
	else
		node->count.left = node->count.right = 0;

	memcpy(node->bits, key, bits / 8U);
	mask = (bits - cidr) >= 64 ? 0 : 0xFFFFFFFFFFFFFFFF << (bits - cidr);
	if (bits == 32)
		*(uint32_t *)node->bits &= mask;
	else
		*(uint64_t *)&node->bits[8] &= mask;

	return node;
}

static bool prefix_matches(const struct radix_node *node, const uint8_t *key,
			   uint8_t bits)
{
	return common_bits(node, key, bits) >= node->cidr;
}

#define CHOOSE_NODE(parent, key)                                               \
	parent->bit[(key[parent->bit_at_a] >> parent->bit_at_b) & 1]

static bool node_placement(struct radix_node *trie, const uint8_t *key,
			   uint8_t cidr, uint8_t bits,
			   struct radix_node **rnode)
{
	struct radix_node *node = trie, *parent = NULL;
	bool exact = false;

	while (node && node->cidr <= cidr && prefix_matches(node, key, bits)) {
		parent = node;
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}

		node = CHOOSE_NODE(parent, key);
	}
	*rnode = parent;
	return exact;
}

static void decrement_radix(struct radix_node *trie, uint8_t bits,
			    const uint8_t *key)
{
	struct radix_node *node = trie;

	while (node && prefix_matches(node, key, bits)) {
		if (node->cidr == bits)
			break;

		/* TODO: distinguish left/right */
		--(node->count.left);
		node = CHOOSE_NODE(node, key);
	}
}

static uint64_t subnet_diff(uint8_t *ip1, uint8_t *ip2, uint8_t bits)
{
	if (bits == 32)
		return *(const uint32_t *)ip1 - *(const uint32_t *)ip2;
	else
		return *(const uint64_t *)&ip1[8] - *(const uint64_t *)&ip2[8];
}

static void add_nth_pool(struct radix_node *start, uint8_t bits, uint64_t n,
			 uint64_t total, void *data, uint8_t *dest)
{
	struct radix_node *target = start, *parent, *newnode, *between;
	uint8_t ip[16] __aligned(__alignof(uint64_t));
	uint8_t cidr = bits;
	uint64_t result, free_ips, diff;

	do {
		parent = target;

		if (n >= parent->count.left) {
			target = parent->bit[1];
			--(parent->count.right);

			n += (1ULL << (bits - parent->cidr - 1)) -
			     parent->count.left;
		} else {
			target = parent->bit[0];
			--(parent->count.left);
		}

		if (!target)
			break;

		/* check if target has a suitable ip range */
		free_ips = target->count.left + target->count.right;
		diff = subnet_diff(target->bits, parent->bits, bits);
		debug("n: %zu, difference: %zu, free_ips: %zu\n", n, diff,
		      free_ips);
		if (n < diff) {
			/* can't go down, or we'd skip too many ips */
			break;
		} else if (n >= diff + free_ips) {
			/* can't go down, we want a higher ip */
			n += (1ULL << (bits - target->cidr)) - free_ips;
			break;
		} else {
			/* match; subtract skipped ips */
			n -= diff;
		}
	} while (1);

	if (bits == 32) {
		result = *(const uint32_t *)parent->bits + n;
		if (result > UINT32_MAX)
			abort();

		memcpy(ip, &result, 4);
	} else {
		result = *(const uint64_t *)&parent->bits[8] + n;
		memcpy(ip, &result, 8);
	}

	newnode = new_node(ip, cidr, bits);
	newnode->data = data;
	swap_endian(dest, (const uint8_t *)ip, bits);

	if (!target) {
		CHOOSE_NODE(parent, newnode->bits) = newnode;
	} else {
		cidr = MIN(cidr, common_bits(target, ip, bits));
		between = new_node(newnode->bits, cidr, bits);

		CHOOSE_NODE(between, target->bits) = target;
		CHOOSE_NODE(between, newnode->bits) = newnode;
		CHOOSE_NODE(parent, between->bits) = between;

		between->count.left -=
			(1ULL << (bits - between->bit[0]->cidr)) -
			(between->bit[0]->count.left +
			 between->bit[0]->count.right);
		between->count.right -=
			(1ULL << (bits - between->bit[1]->cidr)) -
			(between->bit[1]->count.left +
			 between->bit[1]->count.right);
	}
}

static void add_nth(uint8_t bits, uint64_t n, void *data, uint8_t *dest)
{
	struct radix_pool *current = pool_start;
	uint64_t total;

	while (current) {
		total = current->node->count.left + current->node->count.right;
		if (n < total)
			break;

		n -= total;
		current = current->next;
	}

	if (!current)
		abort();

	add_nth_pool(current->node, bits, n, total, data, dest);
}

static int add(struct radix_node **trie, uint8_t bits, const uint8_t *key,
	       uint8_t cidr, void *data, bool overwrite)
{
	struct radix_node *node, *newnode, *down, *parent;

	if (cidr > bits)
		return -EINVAL;

	if (!*trie) {
		*trie = new_node(key, cidr, bits);
		(*trie)->data = data;
		return 0;
	}

	if (node_placement(*trie, key, cidr, bits, &node)) {
		// exact match, so use the existing node
		if (!overwrite && node->data)
			return 1;

		node->data = data;
		return 0;
	}

	if (!overwrite && node && node->data)
		return 1;

	newnode = new_node(key, cidr, bits);
	newnode->data = data;

	if (!node) {
		down = *trie;
	} else {
		down = CHOOSE_NODE(node, key);

		if (!down) {
			CHOOSE_NODE(node, key) = newnode;
			return 0;
		}
	}
	cidr = MIN(cidr, common_bits(down, key, bits));
	parent = node;

	if (newnode->cidr == cidr) {
		CHOOSE_NODE(newnode, down->bits) = down;
		if (!parent)
			*trie = newnode;
		else
			CHOOSE_NODE(parent, newnode->bits) = newnode;
	} else {
		node = new_node(newnode->bits, cidr, bits);

		CHOOSE_NODE(node, down->bits) = down;
		CHOOSE_NODE(node, newnode->bits) = newnode;
		if (!parent)
			*trie = node;
		else
			CHOOSE_NODE(parent, node->bits) = node;
	}

	return 0;
}

static void radix_free_nodes(struct radix_node *node)
{
	struct radix_node *old, *bottom = node;

	while (node) {
		while (bottom->bit[0])
			bottom = bottom->bit[0];
		bottom->bit[0] = node->bit[1];

		old = node;
		node = node->bit[0];
		free(old);
	}
}

static int insert_v4(struct radix_node **root, const struct in_addr *ip,
		     uint8_t cidr, void *data, bool overwrite)
{
	/* Aligned so it can be passed to fls */
	uint8_t key[4] __aligned(__alignof(uint32_t));
	int ret;

	if (!data)
		return -EINVAL;

	swap_endian(key, (const uint8_t *)ip, 32);

	ret = add(root, 32, key, cidr, data, overwrite);
	if (!ret)
		decrement_radix(*root, 32, (uint8_t *)key);

	return ret;
}

static int insert_v6(struct radix_node **root, const struct in6_addr *ip,
		     uint8_t cidr, void *data, bool overwrite)
{
	/* Aligned so it can be passed to fls64 */
	uint8_t key[16] __aligned(__alignof(uint64_t));

	if (!data)
		return -EINVAL;

	swap_endian(key, (const uint8_t *)ip, 128);
	return add(root, 128, key, cidr, data, overwrite);
}

static struct radix_node *find_node(struct radix_node *trie, uint8_t bits,
				    const uint8_t *key)
{
	struct radix_node *node = trie, *found = NULL;

	while (node && prefix_matches(node, key, bits)) {
		if (node->data)
			found = node;
		if (node->cidr == bits)
			break;
		node = CHOOSE_NODE(node, key);
	}
	return found;
}

static struct radix_node *lookup(struct radix_node *root, uint8_t bits,
				 const void *be_ip)
{
	/* Aligned so it can be passed to fls/fls64 */
	uint8_t ip[16] __aligned(__alignof(uint64_t));
	struct radix_node *node;

	swap_endian(ip, be_ip, bits);
	node = find_node(root, bits, ip);
	return node;
}

static int radix_addpool(struct radix_trie *root, uint8_t bits,
			 const uint8_t *key, uint8_t cidr)
{
	struct radix_pool *newpool, *lastpool, *current = pool_start;

	while (current) {
		if (common_bits(current->node, key, bits) >= cidr)
			return -2;

		lastpool = current;
		current = current->next;
	}

	if (add(&root->ip4_root, bits, key, cidr, NULL, false))
		abort();

	if (bits == 32) {
		/* TODO: insert network address (0) and broadcast address (255)
		 * into the pool, so they can't be used */
		/* TODO: special case /31 ?, see RFC 3021 */
	}

	if (malloc(sizeof *newpool))
		fatal("malloc()");

	newpool->node = find_node(root->ip4_root, bits, key);
	newpool->next = NULL;
	lastpool->next = newpool;

	return 0;
}

#ifdef DEBUG
#include <stdio.h>
void node_to_str(struct radix_node *node, char *buf, uint8_t bits)
{
	char out[INET6_ADDRSTRLEN];
	char cidr[5];
	struct in_addr v4addr;
	struct in6_addr v6addr;

	if (!node) {
		strcpy(buf, "-");
		return;
	}

	if (bits == 32) {
		swap_endian((uint8_t *)&v4addr.s_addr, node->bits, bits);
		inet_ntop(AF_INET, &v4addr, out, sizeof out);
	} else {
		swap_endian(v6addr.s6_addr, node->bits, bits);
		inet_ntop(AF_INET6, &v6addr, out, sizeof out);
	}

	snprintf(cidr, sizeof cidr, "/%u", node->cidr);
	strcpy(buf, out);
	strcat(buf, cidr);
}

static void debug_print_trie(struct radix_node *root, uint8_t bits)
{
	char parent[INET6_ADDRSTRLEN + 4], child1[INET6_ADDRSTRLEN + 4],
		child2[INET6_ADDRSTRLEN + 4];

	if (!root)
		return;

	node_to_str(root, parent, bits);
	node_to_str(root->bit[0], child1, bits);
	node_to_str(root->bit[1], child2, bits);

	debug("%s (%zu, %zu) -> %s, %s\n", parent, root->count.left,
	      root->count.right, child1, child2);

	debug_print_trie(root->bit[0], bits);
	debug_print_trie(root->bit[1], bits);
}

void debug_print_trie_v4(struct radix_trie *trie)
{
	debug_print_trie(trie->ip4_root, 32);
}

void debug_print_trie_v6(struct radix_trie *trie)
{
	debug_print_trie(trie->ip6_root, 128);
}
#endif

void radix_init(struct radix_trie *trie)
{
	debug("sizeof(struct radix_node): %zu\n", sizeof(struct radix_node));
	trie->ip4_root = trie->ip6_root = NULL;
}

void radix_free(struct radix_trie *trie)
{
	radix_free_nodes(trie->ip4_root);
	radix_free_nodes(trie->ip6_root);
}

void *radix_find_v4(struct radix_trie *trie, uint8_t bits, const void *be_ip)
{
	struct radix_node *found = lookup(trie->ip4_root, bits, be_ip);
	return found ? found->data : NULL;
}

void *radix_find_v6(struct radix_trie *trie, uint8_t bits, const void *be_ip)
{
	struct radix_node *found = lookup(trie->ip6_root, bits, be_ip);
	return found ? found->data : NULL;
}

int radix_insert_v4(struct radix_trie *root, const struct in_addr *ip,
		    uint8_t cidr, void *data)
{
	return insert_v4(&root->ip4_root, ip, cidr, data, true);
}

int radix_insert_v6(struct radix_trie *root, const struct in6_addr *ip,
		    uint8_t cidr, void *data)
{
	return insert_v6(&root->ip6_root, ip, cidr, data, true);
}

int radix_tryinsert_v4(struct radix_trie *root, const struct in_addr *ip,
		       uint8_t cidr, void *data)
{
	return insert_v4(&root->ip4_root, ip, cidr, data, false);
}

int radix_tryinsert_v6(struct radix_trie *root, const struct in6_addr *ip,
		       uint8_t cidr, void *data)
{
	return insert_v6(&root->ip6_root, ip, cidr, data, false);
}

int radix_addpool_v4(struct radix_trie *root, const struct in_addr *ip,
		     uint8_t cidr)
{
	uint8_t key[4] __aligned(__alignof(uint32_t));

	if (cidr <= 0 || cidr > 32)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 32);
	return radix_addpool(root, 32, key, cidr);
}

int radix_addpool_v6(struct radix_trie *root, const struct in6_addr *ip,
		     uint8_t cidr)
{
	uint8_t key[16] __aligned(__alignof(uint64_t));

	if (cidr <= 0 || cidr > 64)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 128);
	return radix_addpool(root, 128, key, cidr);
}

void radix_addnth_v4(uint64_t n, void *data, struct in_addr *dest)
{
	add_nth(32, n, data, (uint8_t *)&dest->s_addr);
}

void radix_addnth_v6(uint64_t n, void *data, struct in6_addr *dest)
{
	add_nth(128, n, data, (uint8_t *)dest->s6_addr);
}
