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

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

struct radix_node {
	struct radix_node *bit[2];
	uint64_t left;
	uint64_t right;
	uint8_t bits[16];
	uint8_t cidr, bit_at_a, bit_at_b;
	bool is_leaf;
};

struct radix_pool {
	struct radix_node *node;
	struct radix_pool *next;
	bool shadowed;
};

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

	node->bit[0] = node->bit[1] = NULL;
	node->cidr = cidr;
	node->bit_at_a = cidr / 8U;
#ifdef __LITTLE_ENDIAN
	node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
	node->bit_at_b = 7U - (cidr % 8U);
	node->is_leaf = false;
	if (bits - cidr > 0 && bits - cidr - 1 < 64)
		node->left = node->right = 1ULL << (bits - cidr - 1);
	else
		node->left = node->right = 0;

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
	(parent)->bit[(key[(parent)->bit_at_a] >> (parent)->bit_at_b) & 1]

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

static uint64_t subnet_diff(uint8_t *ip1, uint8_t *ip2, uint8_t bits)
{
	if (bits == 32)
		return *(const uint32_t *)ip1 - *(const uint32_t *)ip2;
	else
		return *(const uint64_t *)&ip1[8] - *(const uint64_t *)&ip2[8];
}

static void add_nth(struct radix_node *start, uint8_t bits, uint64_t n,
		    uint8_t *dest)
{
	struct radix_node *target = start, *parent, *newnode, *between;
	uint8_t ip[16] __aligned(__alignof(uint64_t));
	uint8_t cidr = bits;
	uint64_t result, free_ips, diff;

	BUG_ON(n > target->left + target->right - 1);

	do {
		parent = target;

		if (n >= parent->left) {
			target = parent->bit[1];
			BUG_ON(!parent->right);
			--(parent->right);

			n += (1ULL << (bits - parent->cidr - 1)) - parent->left;
		} else {
			target = parent->bit[0];
			BUG_ON(!parent->left);
			--(parent->left);
		}

		if (!target)
			break;

		/* check if target has a suitable ip range */
		free_ips = target->left + target->right;
		diff = subnet_diff(target->bits, parent->bits, bits);
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
		BUG_ON(result > UINT32_MAX);

		memcpy(ip, &result, 4);
	} else {
		result = *(const uint64_t *)&parent->bits[8] + n;
		memcpy(ip, &parent->bits, 8);
		memcpy(ip + 8, &result, 8);
	}

	newnode = new_node(ip, cidr, bits);
	newnode->is_leaf = true;
	swap_endian(dest, (const uint8_t *)ip, bits);

	if (!target) {
		CHOOSE_NODE(parent, newnode->bits) = newnode;
	} else {
		cidr = MIN(cidr, common_bits(target, ip, bits));
		between = new_node(newnode->bits, cidr, bits);

		CHOOSE_NODE(between, target->bits) = target;
		CHOOSE_NODE(between, newnode->bits) = newnode;
		CHOOSE_NODE(parent, between->bits) = between;

		between->left -=
			(1ULL << (bits - between->bit[0]->cidr)) -
			(between->bit[0]->left + between->bit[0]->right);
		between->right -=
			(1ULL << (bits - between->bit[1]->cidr)) -
			(between->bit[1]->left + between->bit[1]->right);
	}
}

static int add(struct radix_node **trie, uint8_t bits, const uint8_t *key,
	       uint8_t cidr, bool is_leaf)
{
	struct radix_node *node, *newnode, *down, *parent;

	if (cidr > bits)
		return -EINVAL;

	if (!*trie) {
		*trie = new_node(key, cidr, bits);
		(*trie)->is_leaf = is_leaf;
		return 0;
	}

	if (node_placement(*trie, key, cidr, bits, &node)) {
		/* exact match, so use the existing node */
		if (node->is_leaf)
			return 1;

		node->is_leaf = is_leaf;
		return 0;
	}

	if (node && node->is_leaf)
		return 1;

	newnode = new_node(key, cidr, bits);
	newnode->is_leaf = is_leaf;

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
	for (struct radix_node *next; node; node = next) {
		next = node->bit[0];
		if (next) {
			node->bit[0] = next->bit[1];
			next->bit[1] = node;
		} else {
			next = node->bit[1];
			free(node);
		}
	}
}

static void decrement_radix(struct radix_node *trie, uint8_t bits,
			    const uint8_t *key)
{
	struct radix_node *node = trie;

	while (node && prefix_matches(node, key, bits)) {
		if (node->cidr == bits)
			break;

		if (CHOOSE_NODE(node, key) == node->bit[0])
			--(node->left);
		else
			--(node->right);

		node = CHOOSE_NODE(node, key);
	}
}

static int insert_v4(struct radix_node **root, const struct in_addr *ip,
		     uint8_t cidr)
{
	/* Aligned so it can be passed to fls */
	uint8_t key[4] __aligned(__alignof(uint32_t));
	int ret;

	swap_endian(key, (const uint8_t *)ip, 32);

	ret = add(root, 32, key, cidr, true);
	if (!ret)
		decrement_radix(*root, 32, (uint8_t *)key);

	return ret;
}

static int insert_v6(struct radix_node **root, const struct in6_addr *ip,
		     uint8_t cidr)
{
	/* Aligned so it can be passed to fls64 */
	uint8_t key[16] __aligned(__alignof(uint64_t));
	int ret;

	swap_endian(key, (const uint8_t *)ip, 128);

	ret = add(root, 128, key, cidr, true);
	if (!ret)
		decrement_radix(*root, 128, (uint8_t *)key);

	return ret;
}

static int remove_node(struct radix_node *trie, const uint8_t *key,
		       uint8_t bits)
{
	struct radix_node **node = &trie, **target = NULL;

	while (*node && prefix_matches(*node, key, bits)) {
		if ((*node)->is_leaf) {
			target = node;
			break;
		}

		if (CHOOSE_NODE(*node, key) == (*node)->bit[0])
			++((*node)->left);
		else
			++((*node)->right);

		node = &CHOOSE_NODE(*node, key);
	}

	if (!target)
		return 1; /* key not found in trie */

	*target = NULL;
	radix_free_nodes(*node);

	return 0;
}

static void totalip_inc(struct ipns *ns, uint8_t bits, uint8_t val)
{
	if (bits == 32) {
		BUG_ON(val > 32);
		ns->total_ipv4 += 1ULL << val;
	} else if (bits == 128) {
		uint64_t tmp = ns->totall_ipv6;
		BUG_ON(val > 64);
		ns->totall_ipv6 += (val == 64) ? 0 : 1ULL << val;
		if (ns->totall_ipv6 <= tmp)
			++ns->totalh_ipv6;
	}
}

static void totalip_dec(struct ipns *ns, uint8_t bits, uint8_t val)
{
	if (bits == 32) {
		BUG_ON(val > 32);
		ns->total_ipv4 -= 1ULL << val;
	} else if (bits == 128) {
		uint64_t tmp = ns->totall_ipv6;
		BUG_ON(val > 64);
		ns->totall_ipv6 -= (val == 64) ? 0 : 1ULL << val;
		if (ns->totall_ipv6 >= tmp)
			--ns->totalh_ipv6;
	}
}

static int ipp_addpool(struct ipns *ns, struct radix_pool **pool,
		       struct radix_node **root, uint8_t bits,
		       const uint8_t *key, uint8_t cidr)
{
	struct radix_pool *newpool;
	struct radix_node *node;
	bool shadowed = false;

	while (*pool) {
		node = (*pool)->node;

		if (common_bits(node, key, bits) >= MIN(cidr, node->cidr)) {
			if (cidr > node->cidr) {
				shadowed = true;
			} else if (cidr < node->cidr && !(*pool)->shadowed) {
				(*pool)->shadowed = true;
				totalip_dec(ns, bits, bits - cidr);
			} else {
				return -1;
			}
		}

		pool = &(*pool)->next;
	}

	BUG_ON(add(root, bits, key, cidr, false));

	if (bits == 32) {
		/* TODO: insert network address (0) and broadcast address (255)
		 * into the pool, so they can't be used */
		/* TODO: special case /31 ?, see RFC 3021 */
	}

	if (!shadowed)
		totalip_inc(ns, bits, bits - cidr);

	newpool = malloc(sizeof *newpool);
	if (!newpool)
		fatal("malloc()");

	node = *root;
	while (node->cidr != cidr) {
		node = CHOOSE_NODE(node, key);

		BUG_ON(!node || !prefix_matches(node, key, bits));
	}
	newpool->node = node;
	newpool->shadowed = shadowed;
	newpool->next = NULL;
	*pool = newpool;

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

	debug("%s (%zu, %zu) -> %s, %s\n", parent, root->left, root->right,
	      child1, child2);

	debug_print_trie(root->bit[0], bits);
	debug_print_trie(root->bit[1], bits);
}

void debug_print_trie_v4(struct ipns *ns)
{
	debug_print_trie(ns->ip4_root, 32);
}

void debug_print_trie_v6(struct ipns *ns)
{
	debug_print_trie(ns->ip6_root, 128);
}
#endif

void ipp_init(struct ipns *ns)
{
	ns->ip4_root = ns->ip6_root = NULL;
	ns->ip4_pools = ns->ip6_pools = NULL;
	ns->totall_ipv6 = ns->totalh_ipv6 = ns->total_ipv4 = 0;
}

void ipp_free(struct ipns *ns)
{
	struct radix_pool *next;

	radix_free_nodes(ns->ip4_root);
	radix_free_nodes(ns->ip6_root);

	for (struct radix_pool *cur = ns->ip4_pools; cur; cur = next) {
		next = cur->next;
		free(cur);
	}

	for (struct radix_pool *cur = ns->ip6_pools; cur; cur = next) {
		next = cur->next;
		free(cur);
	}
}

int ipp_add_v4(struct ipns *ns, const struct in_addr *ip, uint8_t cidr)
{
	int ret = insert_v4(&ns->ip4_root, ip, cidr);
	if (!ret)
		--ns->total_ipv4;

	return ret;
}

int ipp_add_v6(struct ipns *ns, const struct in6_addr *ip, uint8_t cidr)
{
	int ret = insert_v6(&ns->ip6_root, ip, cidr);
	if (!ret) {
		if (ns->totall_ipv6 == 0)
			--ns->totalh_ipv6;

		--ns->totall_ipv6;
	}

	return ret;
}

int ipp_del_v4(struct ipns *ns, const struct in_addr *ip, uint8_t cidr)
{
	uint8_t key[4] __aligned(__alignof(uint32_t));
	int ret;

	swap_endian(key, (const uint8_t *)ip, 32);
	ret = remove_node(ns->ip4_root, key, cidr);
	if (!ret)
		++ns->total_ipv4;

	return ret;
}

int ipp_del_v6(struct ipns *ns, const struct in6_addr *ip, uint8_t cidr)
{
	uint8_t key[16] __aligned(__alignof(uint64_t));
	int ret;

	swap_endian(key, (const uint8_t *)ip, 128);
	ret = remove_node(ns->ip6_root, key, cidr);
	if (!ret) {
		++ns->totall_ipv6;
		if (ns->totall_ipv6 == 0)
			++ns->totalh_ipv6;
	}

	return ret;
}

int ipp_addpool_v4(struct ipns *ns, const struct in_addr *ip, uint8_t cidr)
{
	uint8_t key[4] __aligned(__alignof(uint32_t));

	if (cidr <= 0 || cidr >= 32)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 32);
	return ipp_addpool(ns, &ns->ip4_pools, &ns->ip4_root, 32, key, cidr);
}

int ipp_addpool_v6(struct ipns *ns, const struct in6_addr *ip, uint8_t cidr)
{
	uint8_t key[16] __aligned(__alignof(uint64_t));

	if (cidr < 64 || cidr >= 128)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 128);
	return ipp_addpool(ns, &ns->ip6_pools, &ns->ip6_root, 128, key, cidr);
}

/* TODO: implement */
int ipp_removepool_v4(struct ipns *ns, const struct in_addr *ip)
{
	return 0;
}

/* TODO: implement */
int ipp_removepool_v6(struct ipns *ns, const struct in6_addr *ip)
{
	return 0;
}

void ipp_addnth_v4(struct ipns *ns, struct in_addr *dest, uint32_t index)
{
	struct radix_pool *current = ns->ip4_pools;

	for (current = ns->ip4_pools; current; current = current->next) {
		if (current->shadowed)
			continue;

		if (index < current->node->left + current->node->right)
			break;

		index -= current->node->left + current->node->right;
	}

	BUG_ON(!current);

	add_nth(current->node, 32, index, (uint8_t *)&dest->s_addr);
	--ns->total_ipv4;
}

void ipp_addnth_v6(struct ipns *ns, struct in6_addr *dest, uint32_t index_low,
		   uint64_t index_high)
{
	struct radix_pool *current = ns->ip6_pools;
	uint64_t tmp;

	while (current) {
		if (current->shadowed ||
		    (current->node->left == 0 && current->node->right == 0)) {
			current = current->next;
			continue;
		}

		if (index_high == 0 &&
		    index_low < (current->node->left + current->node->right))
			break;

		tmp = index_low - (current->node->left + current->node->right);
		if (tmp >= index_low) {
			BUG_ON(index_high == 0);
			--index_high;
		}
		index_low = tmp;

		current = current->next;
	}

	BUG_ON(!current || index_high);

	add_nth(current->node, 128, index_low, (uint8_t *)&dest->s6_addr);
	if (ns->totall_ipv6 == 0)
		--ns->totalh_ipv6;

	--ns->totall_ipv6;
}
