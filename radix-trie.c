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

struct radix_node {
	struct radix_node *bit[2];
	void *data;
	uint8_t bits[16];
	uint8_t cidr, bit_at_a, bit_at_b;
};

// TODO: sort out #ifdef business to make this portable
static unsigned int fls64(uint64_t a)
{
	return __builtin_ctzl(a) + 1;
}

static unsigned int fls(uint32_t a)
{
	return __builtin_ctz(a) + 1;
}

static unsigned int fls128(uint64_t a, uint64_t b)
{
	return a ? fls64(a) + 64U : (b ? fls64(b) : 0);
}

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
	memcpy(node->bits, key, bits / 8U);

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

static int add(struct radix_node **trie, uint8_t bits, const uint8_t *key,
	       uint8_t cidr, void *data, bool overwrite)
{
	struct radix_node *node, *newnode, *down, *parent;

	if (cidr > bits || !data)
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

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

static int insert_v4(struct radix_node **root, const struct in_addr *ip,
		     uint8_t cidr, void *data, bool overwrite)
{
	/* Aligned so it can be passed to fls */
	uint8_t key[4] __aligned(__alignof(uint32_t));

	swap_endian(key, (const uint8_t *)ip, 32);
	return add(root, 32, key, cidr, data, overwrite);
}

static int insert_v6(struct radix_node **root, const struct in6_addr *ip,
		     uint8_t cidr, void *data, bool overwrite)
{
	/* Aligned so it can be passed to fls64 */
	uint8_t key[16] __aligned(__alignof(uint64_t));

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

#ifdef DEBUG
#include <stdio.h>
void node_to_str(struct radix_node *node, char *buf)
{
	struct in6_addr addr;
	char out[INET6_ADDRSTRLEN];
	char cidr[5];

	if (!node) {
		strcpy(buf, "-");
		return;
	}

	swap_endian(addr.s6_addr, node->bits, 128);
	inet_ntop(AF_INET6, &addr, out, sizeof out);
	snprintf(cidr, sizeof cidr, "/%u", node->cidr);
	strcpy(buf, out);
	strcat(buf, cidr);
}

void debug_print_trie(struct radix_node *root)
{
	char parent[INET6_ADDRSTRLEN + 4], child1[INET6_ADDRSTRLEN + 4],
		child2[INET6_ADDRSTRLEN + 4];

	if (!root)
		return;

	node_to_str(root, parent);
	node_to_str(root->bit[0], child1);
	node_to_str(root->bit[1], child2);

	debug("%s -> %s, %s\n", parent, child1, child2);

	debug_print_trie(root->bit[0]);
	debug_print_trie(root->bit[1]);
}
#endif

void radix_init(struct radix_trie *trie)
{
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
