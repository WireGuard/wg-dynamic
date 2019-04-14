#ifndef __IP_UTIL_H__
#define __IP_UTIL_H__

#include <arpa/inet.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

static int __printf_arginfo(const struct printf_info *info, size_t n,
			    int *argtypes, int *sz)
{
	if (n > 0)
		argtypes[0] = PA_POINTER;

	return 1;
}

static int __printf_output_b(FILE *stream, const struct printf_info *info,
			     const void *const *args)
{
	uint64_t value = 0;
	char buf[8 * sizeof(uintmax_t) + 1] = { 0 };

	if (info->width == 0 || info->width % 8 != 0)
		return -1;

	memcpy(&value, *(unsigned char **)(args[0]), info->width / 8);

	for (int i = 0; i < info->width; ++i)
		buf[info->width - 1 - i] = '0' + ((value >> i) & 0x1);

	return fprintf(stream, "%s", buf);
}

static int __printf_output_y(FILE *stream, const struct printf_info *info,
			     const void *const *args)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr ip;

	if (!*(unsigned char **)(args[0]))
		return fprintf(stream, "(nil)", buf);

	memcpy(&ip, *(unsigned char **)(args[0]), sizeof ip);

	inet_ntop(AF_INET, &ip.s_addr, buf, sizeof buf);

	return fprintf(stream, "%s", buf);
}

static int __printf_output_Y(FILE *stream, const struct printf_info *info,
			     const void *const *args)
{
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr ip;

	if (!*(unsigned char **)(args[0]))
		return fprintf(stream, "(nil)", buf);

	memcpy(&ip, *(unsigned char **)(args[0]), sizeof ip);

	inet_ntop(AF_INET6, &ip.s6_addr, buf, sizeof buf);

	return fprintf(stream, "%s", buf);
}

static void __attribute__((constructor)) __custom_printf_init()
{
	register_printf_specifier('b', __printf_output_b, __printf_arginfo);
	register_printf_specifier('y', __printf_output_y, __printf_arginfo);
	register_printf_specifier('Y', __printf_output_Y, __printf_arginfo);
}

struct ip_from {
	unsigned char ip[16];
	struct ip_from *next;
};

static struct ip_from *start = NULL;
static struct ip_from *end = NULL;

static unsigned char *ip_from(uint8_t bits, char *ip_str)
{
	struct ip_from *res = malloc(sizeof *res);

	inet_pton(bits == 32 ? AF_INET : AF_INET6, ip_str, &res->ip);

	if (!end)
		start = end = res;
	else
		end->next = res;

	end = res;
	res->next = NULL;

	return res->ip;
}

static struct in_addr *ip4_from(char *ip_str)
{
	return (struct in_addr *)ip_from(32, ip_str);
}

static struct in6_addr *ip6_from(char *ip_str)
{
	return (struct in6_addr *)ip_from(128, ip_str);
}

static void __attribute__((destructor)) __free_ip_froms()
{
	struct ip_from *cur = start, *next;
	while (cur) {
		next = cur->next;
		free(cur);
		cur = next;
	}
}

#endif
