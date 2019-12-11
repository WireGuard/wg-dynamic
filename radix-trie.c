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

enum radix_node_flags {
	RNODE_IS_LEAF = 1U << 0,
	RNODE_IS_POOLNODE = 1U << 1,
	RNODE_IS_SHADOWED = 1U << 2,
};

struct radix_node {
	struct radix_node *bit[2];
	uint64_t left;
	uint64_t right;
	uint8_t bits[16];
	uint8_t cidr, bit_at_a, bit_at_b, flags;
};

struct radix_pool {
	struct radix_node *node;
	struct radix_pool *next;
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
	node->flags = 0;
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

static uint64_t subnet_diff(uint8_t *ip1, uint8_t *ip2, uint8_t bits)
{
	if (bits == 32)
		return *(const uint32_t *)ip1 - *(const uint32_t *)ip2;
	else
		return *(const uint64_t *)&ip1[8] - *(const uint64_t *)&ip2[8];
}

static uint64_t taken_ips(struct radix_node *node, uint8_t bits)
{
	if ((bits - node->cidr) >= 64)
		return 0;

	return (1ULL << (bits - node->cidr)) - (node->left + node->right);
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
	newnode->flags |= RNODE_IS_LEAF;
	swap_endian(dest, (const uint8_t *)ip, bits);

	if (!target) {
		CHOOSE_NODE(parent, newnode->bits) = newnode;
	} else {
		cidr = MIN(cidr, common_bits(target, ip, bits));
		between = new_node(newnode->bits, cidr, bits);

		CHOOSE_NODE(between, target->bits) = target;
		CHOOSE_NODE(between, newnode->bits) = newnode;
		CHOOSE_NODE(parent, between->bits) = between;

		between->left -= taken_ips(between->bit[0], bits);
		between->right -= taken_ips(between->bit[1], bits);
	}
}

static struct radix_node *add(struct radix_node **trie, uint8_t bits,
			      const uint8_t *key, uint8_t cidr, uint8_t type)
{
	struct radix_node *node = NULL, *newnode, *down, *parent, *tmp = *trie;
	bool exact = false, in_pool = false;

	if (cidr > bits) {
		errno = EINVAL;
		return NULL;
	}

	if (!*trie) {
		if (type & RNODE_IS_LEAF) {
			errno = ENOENT;
			return NULL;
		}

		*trie = new_node(key, cidr, bits);
		(*trie)->flags = type;
		return *trie;
	}

	while (tmp && tmp->cidr <= cidr && prefix_matches(tmp, key, bits)) {
		node = tmp;
		if (tmp->flags & RNODE_IS_POOLNODE)
			in_pool = true;

		if (node->cidr == cidr) {
			exact = true;
			break;
		}

		tmp = CHOOSE_NODE(node, key);
	}

	if (!in_pool && (type & RNODE_IS_LEAF)) {
		errno = ENOENT;
		return NULL;
	}

	if (exact) {
		/* exact match, so use the existing node */
		if (node->flags & type) {
			errno = EEXIST;
			return NULL;
		}

		node->flags = type;
		return node;
	}

	newnode = new_node(key, cidr, bits);
	newnode->flags = type;

	if (!node) {
		down = *trie;
	} else {
		down = CHOOSE_NODE(node, key);

		if (!down) {
			CHOOSE_NODE(node, key) = newnode;
			return newnode;
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

		if (CHOOSE_NODE(node, down->bits) == node->bit[0])
			node->left -= taken_ips(down, bits);
		else
			node->right -= taken_ips(down, bits);

		if (!parent)
			*trie = node;
		else
			CHOOSE_NODE(parent, node->bits) = node;
	}

	return newnode;
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

	swap_endian(key, (const uint8_t *)ip, 32);

	if (add(root, 32, key, cidr, RNODE_IS_LEAF)) {
		decrement_radix(*root, 32, (uint8_t *)key);
		return 0;
	}

	return -1;
}

static int insert_v6(struct radix_node **root, const struct in6_addr *ip,
		     uint8_t cidr)
{
	/* Aligned so it can be passed to fls64 */
	uint8_t key[16] __aligned(__alignof(uint64_t));

	swap_endian(key, (const uint8_t *)ip, 128);

	if (add(root, 128, key, cidr, RNODE_IS_LEAF)) {
		decrement_radix(*root, 128, (uint8_t *)key);
		return 0;
	}

	return -1;
}

static int remove_node(struct radix_node **trie, const uint8_t *key,
		       uint8_t bits)
{
	struct radix_node **node = trie, **target = NULL;
	uint64_t *pnodes[127];
	int i = 0;

	while (*node && prefix_matches(*node, key, bits)) {
		if ((*node)->flags & RNODE_IS_LEAF) {
			target = node;
			break;
		}

		if (CHOOSE_NODE(*node, key) == (*node)->bit[0])
			pnodes[i++] = &((*node)->left);
		else
			pnodes[i++] = &((*node)->right);

		BUG_ON(i >= 127);
		node = &CHOOSE_NODE(*node, key);
	}

	if (!target)
		return 1; /* key not found in trie */

	for (int j = 0; j < i; ++j)
		++(*(pnodes[j]));

	free(*node);
	*target = NULL;

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

static void shadow_nodes(struct radix_node *node)
{
	if (!node)
		return;

	if (node->flags & RNODE_IS_POOLNODE) {
		BUG_ON(node->flags & RNODE_IS_SHADOWED);
		node->flags |= RNODE_IS_SHADOWED;
		return;
	}

	if (node->flags & RNODE_IS_LEAF)
		return;

	shadow_nodes(node->bit[0]);
	shadow_nodes(node->bit[1]);
}

static int ipp_addpool(struct ipns *ns, struct radix_pool **pool,
		       struct radix_node **root, uint8_t bits,
		       const uint8_t *key, uint8_t cidr)
{
	struct radix_node **node = root, *newnode;
	struct radix_pool *newpool;
	bool shadow = false, good_match = false;
	uint8_t flags;

	while (*node && (*node)->cidr <= cidr &&
	       prefix_matches(*node, key, bits)) {
		if ((*node)->cidr == cidr) {
			good_match = true;
			break;
		}

		if ((*node)->flags & RNODE_IS_POOLNODE)
			shadow = true;

		node = &CHOOSE_NODE(*node, key);
	}

	flags = RNODE_IS_POOLNODE | (shadow ? RNODE_IS_SHADOWED : 0);

	if (good_match) {
		if ((*node)->flags & RNODE_IS_POOLNODE)
			return -1; /* already exists */

		BUG_ON((*node)->flags & RNODE_IS_SHADOWED);
		(*node)->flags |= flags;

		newnode = *node;
	} else {
		newnode = add(node, bits, key, cidr, flags);
		if (newnode->bit[0])
			newnode->left -= taken_ips(newnode->bit[0], bits);

		if (newnode->bit[1])
			newnode->right -= taken_ips(newnode->bit[1], bits);
	}

	if (!shadow) {
		shadow_nodes(newnode->bit[0]);
		shadow_nodes(newnode->bit[1]);
	}

	if (bits == 32) {
		/* TODO: insert network address (0) and broadcast address (255)
		 * into the pool, so they can't be used */
		/* TODO: special case /31 ?, see RFC 3021 */
	}

	if (!shadow)
		totalip_inc(ns, bits, bits - cidr);

	newpool = malloc(sizeof *newpool);
	if (!newpool)
		fatal("malloc()");

	newpool->node = newnode;
	newpool->next = *pool;
	*pool = newpool;

	return 0;
}

static int orphan_nodes(struct radix_node *node, uint64_t *val)
{
	uint64_t v1 = 0, v2 = 0;

	if (!node)
		return 0;

	if (node->flags & RNODE_IS_POOLNODE) {
		BUG_ON(!(node->flags & RNODE_IS_SHADOWED));
		node->flags &= ~RNODE_IS_SHADOWED;
		return 0;
	}

	if (node->flags & RNODE_IS_LEAF) {
		BUG_ON(node->bit[0] || node->bit[1]);
		*val = 1;
		free(node);
		return 1;
	}

	if (orphan_nodes(node->bit[0], &v1))
		node->bit[0] = NULL;

	if (orphan_nodes(node->bit[1], &v2))
		node->bit[1] = NULL;

	node->left += v1;
	node->right += v2;
	*val = v1 + v2;

	if (node->bit[0] || node->bit[1])
		return 0; /* still need this node */

	free(node);
	return 1;
}

static int ipp_removepool(struct ipns *ns, uint8_t bits, const uint8_t *key,
			  uint8_t cidr)
{
	struct radix_pool **current, *next;
	struct radix_node *node;

	for (current = &ns->ip4_pools; *current; current = &(*current)->next) {
		struct radix_node *node = (*current)->node;
		if (node->cidr == cidr && common_bits(node, key, bits) >= cidr)
			break;
	}

	if (!*current)
		return -1;

	node = (*current)->node;

	if (node->flags & RNODE_IS_SHADOWED) {
		node->flags &= ~RNODE_IS_SHADOWED;
	} else {
		struct radix_node *n = ns->ip4_root;
		uint64_t v1 = 0, v2 = 0;

		if (orphan_nodes(node->bit[0], &v1))
			node->bit[0] = NULL;

		if (orphan_nodes(node->bit[1], &v2))
			node->bit[1] = NULL;

		node->left += v1;
		node->right += v2;

		while (n && n->cidr < cidr && prefix_matches(n, key, bits)) {
			if (n->bit[0] == CHOOSE_NODE(n, key))
				n->left += v1 + v2;
			else
				n->right += v1 + v2;

			n = CHOOSE_NODE(n, key);
		}
	}

	node->flags &= ~RNODE_IS_POOLNODE;
	next = (*current)->next;
	free(*current);
	*current = next;

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

	debug("%s (%zu, %zu, %c%c%c) -> %s, %s\n", parent, root->left,
	      root->right, root->flags & RNODE_IS_LEAF ? 'l' : '-',
	      root->flags & RNODE_IS_POOLNODE ? 'p' : '-',
	      root->flags & RNODE_IS_SHADOWED ? 's' : '-', child1, child2);

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
	ret = remove_node(&ns->ip4_root, key, cidr);
	if (!ret)
		++ns->total_ipv4;

	return ret;
}

int ipp_del_v6(struct ipns *ns, const struct in6_addr *ip, uint8_t cidr)
{
	uint8_t key[16] __aligned(__alignof(uint64_t));
	int ret;

	swap_endian(key, (const uint8_t *)ip, 128);
	ret = remove_node(&ns->ip6_root, key, cidr);
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

int ipp_removepool_v4(struct ipns *ns, const struct in_addr *ip, uint8_t cidr)
{
	uint8_t key[4] __aligned(__alignof(uint32_t));

	if (cidr <= 0 || cidr >= 32)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 32);
	return ipp_removepool(ns, 32, key, cidr);
}

int ipp_removepool_v6(struct ipns *ns, const struct in6_addr *ip, uint8_t cidr)
{
	uint8_t key[16] __aligned(__alignof(uint64_t));

	if (cidr < 64 || cidr >= 128)
		return -1;

	swap_endian(key, (const uint8_t *)ip, 128);
	return ipp_removepool(ns, 128, key, cidr);
}

void ipp_addnth_v4(struct ipns *ns, struct in_addr *dest, uint32_t index)
{
	struct radix_pool *current;

	for (current = ns->ip4_pools; current; current = current->next) {
		if (current->node->flags & RNODE_IS_SHADOWED)
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
	struct radix_pool *current;
	uint64_t tmp;

	for (current = ns->ip6_pools; current; current = current->next) {
		if (current->node->flags & RNODE_IS_SHADOWED ||
		    (current->node->left == 0 && current->node->right == 0))
			continue;

		/* left + right may overflow, so we substract 1 which is safe
		 * since we ensured it's > 0 except when the total is 2^64 */
		if (index_high == 0 && index_low <= (current->node->left +
						     current->node->right - 1))
			break;

		tmp = index_low - (current->node->left + current->node->right);
		if (tmp >= index_low) {
			BUG_ON(index_high == 0);
			--index_high;
		}
		index_low = tmp;
	}

	BUG_ON(!current || index_high);

	add_nth(current->node, 128, index_low, (uint8_t *)&dest->s6_addr);
	if (ns->totall_ipv6 == 0)
		--ns->totalh_ipv6;

	--ns->totall_ipv6;
}
