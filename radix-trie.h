/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __RADIX_TRIE_H__
#define __RADIX_TRIE_H__

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

struct radix_trie {
	struct radix_node *ip4_root, *ip6_root;
};

void radix_init(struct radix_trie *trie);
void radix_free(struct radix_trie *trie);
void *radix_find_v4(struct radix_trie *trie, uint8_t bits, const void *be_ip);
void *radix_find_v6(struct radix_trie *trie, uint8_t bits, const void *be_ip);
int radix_insert_v4(struct radix_trie *root, const struct in_addr *ip,
		    uint8_t cidr, void *data);
int radix_insert_v6(struct radix_trie *root, const struct in6_addr *ip,
		    uint8_t cidr, void *data);
int radix_tryinsert_v4(struct radix_trie *root, const struct in_addr *ip,
		       uint8_t cidr, void *data);
int radix_tryinsert_v6(struct radix_trie *root, const struct in6_addr *ip,
		       uint8_t cidr, void *data);
int radix_addpool_v4(struct radix_trie *root, const struct in_addr *ip,
		     uint8_t cidr);
int radix_addpool_v6(struct radix_trie *root, const struct in6_addr *ip,
		     uint8_t cidr);
void radix_addnth_v4(uint64_t n, void *data, struct in_addr *dest);
void radix_addnth_v6(uint64_t n, void *data, struct in6_addr *dest);

#ifdef DEBUG
void node_to_str(struct radix_node *node, char *buf, uint8_t bits);
void debug_print_trie_v4(struct radix_trie *trie);
void debug_print_trie_v6(struct radix_trie *trie);
#endif

#endif
