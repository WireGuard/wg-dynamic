/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __RADIX_TRIE_H__
#define __RADIX_TRIE_H__

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

struct ip_pool {
	uint64_t totall_ipv6;
	uint32_t totalh_ipv6, total_ipv4;
	struct radix_node *ip4_root, *ip6_root;
	struct radix_pool *ip4_pool, *ip6_pool;
};

void ipp_init(struct ip_pool *pool);
void ipp_free(struct ip_pool *pool);

int ipp_add_v4(struct ip_pool *pool, const struct in_addr *ip, uint8_t cidr);
int ipp_add_v6(struct ip_pool *pool, const struct in6_addr *ip, uint8_t cidr);

int ipp_del_v4(struct ip_pool *pool, const struct in_addr *ip, uint8_t cidr);
int ipp_del_v6(struct ip_pool *pool, const struct in6_addr *ip, uint8_t cidr);

void ipp_addnth_v4(struct ip_pool *pool, struct in_addr *dest, uint32_t index);
void ipp_addnth_v6(struct ip_pool *pool, struct in6_addr *dest,
		   uint32_t index_low, uint64_t index_high);

int ipp_addpool_v4(struct ip_pool *ipp, const struct in_addr *ip, uint8_t cidr);
int ipp_addpool_v6(struct ip_pool *ipp, const struct in6_addr *ip,
		   uint8_t cidr);

int ipp_removepool_v4(struct ip_pool *pool, const struct in_addr *ip);
int ipp_removepool_v6(struct ip_pool *pool, const struct in6_addr *ip);

#ifdef DEBUG
void node_to_str(struct radix_node *node, char *buf, uint8_t bits);
void debug_print_trie_v4(struct ip_pool *pool);
void debug_print_trie_v6(struct ip_pool *pool);
#endif

#endif
