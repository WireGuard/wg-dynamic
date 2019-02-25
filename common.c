/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#define _DEFAULT_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "common.h"
#include "dbg.h"

static bool parse_ip_cidr(struct wg_combined_ip *ip, char *value)
{
	uintmax_t res;
	char *endptr;
	char *sep = strchr(value, '/');
	if (!sep)
		return false;

	*sep = '\0';
	if (inet_pton(ip->family, value, &ip->ip) != 1)
		return false;

	res = strtoumax(sep + 1, &endptr, 10);
	if (res > UINT8_MAX || *endptr != '\0' || sep + 1 == endptr)
		return false;

	// TODO: validate cidr range depending on ip->family
	ip->cidr = (uint8_t)res;

	return true;
}

static struct wg_dynamic_attr *parse_value(enum wg_dynamic_key key, char *value)
{
	struct wg_dynamic_attr *attr;
	size_t len;
	char *endptr;
	uintmax_t uresult;
	union {
		uint32_t leasetime;
		struct wg_combined_ip ip;
	} data = { 0 };

	switch (key) {
	case WGKEY_IPV4:
		len = sizeof data.ip;
		data.ip.family = AF_INET;
		if (!parse_ip_cidr(&data.ip, value))
			return NULL;

		break;
	case WGKEY_IPV6:
		len = sizeof data.ip;
		data.ip.family = AF_INET6;
		if (!parse_ip_cidr(&data.ip, value))
			return NULL;

		break;
	case WGKEY_LEASETIME:
		len = sizeof data.leasetime;
		uresult = strtoumax(value, &endptr, 10);
		if (uresult > UINT32_MAX || *endptr != '\0')
			return NULL;

		data.leasetime = (uint32_t)uresult;
		break;
	default:
		debug("Invalid key %d, aborting\n", key);
		abort();
	}

	attr = malloc(sizeof(struct wg_dynamic_attr) + len);
	if (!attr)
		fatal("malloc()");

	attr->len = len;
	attr->key = key;
	attr->next = NULL;
	memcpy(&attr->value, &data, len);

	return attr;
}

static enum wg_dynamic_key parse_key(char *key)
{
	for (enum wg_dynamic_key e = 1; e < ARRAY_SIZE(WG_DYNAMIC_KEY); ++e)
		if (!strcmp(key, WG_DYNAMIC_KEY[e]))
			return e;

	return WGKEY_UNKNOWN;
}

/* Consumes one full line from buf, or up to MAX_LINESIZE-1 bytes if no newline
 * character was found.
 * If req != NULL then we expect to parse a command and will set cmd and version
 * of req accordingly, while *attr will be set to NULL.
 * Otherwise we expect to parse a normal key=value pair, that will be stored
 * in a newly allocated wg_dynamic_attr, pointed to by *attr.
 *
 * Return values:
 *   > 0 : Amount of bytes consumed (<= MAX_LINESIZE)
 *   < 0 : Error
 *   = 0 : End of message
 */
static ssize_t parse_line(unsigned char *buf, size_t len,
			  struct wg_dynamic_attr **attr,
			  struct wg_dynamic_request *req)
{
	unsigned char *line_end, *key_end;
	enum wg_dynamic_key key;
	ssize_t line_len;
	char *endptr;
	uintmax_t res;

	line_end = memchr(buf, '\n', len > MAX_LINESIZE ? MAX_LINESIZE : len);
	if (!line_end) {
		if (len >= MAX_LINESIZE)
			return -E2BIG;

		*attr = malloc(sizeof(struct wg_dynamic_attr) + len);
		if (!*attr)
			fatal("malloc()");

		(*attr)->key = WGKEY_INCOMPLETE;
		(*attr)->len = len;
		(*attr)->next = NULL;
		memcpy((*attr)->value, buf, len);

		return len;
	}

	if (line_end == buf)
		return 0; /* \n\n - end of message */

	*line_end = '\0';
	line_len = line_end - buf + 1;

	key_end = memchr(buf, '=', line_len - 1);
	if (!key_end)
		return -EINVAL;

	*key_end = '\0';
	key = parse_key((char *)buf);
	if (key == WGKEY_UNKNOWN)
		return -ENOENT;

	if (req) {
		if (key >= WGKEY_ENDCMD)
			return -ENOENT;

		*attr = NULL;
		res = strtoumax((char *)key_end + 1, &endptr, 10);

		if (res > UINT32_MAX || *endptr != '\0')
			return -EINVAL;

		req->cmd = key;
		req->version = (uint32_t)res;

		if (req->version != 1)
			return -EPROTONOSUPPORT;
	} else {
		if (key <= WGKEY_ENDCMD)
			return -ENOENT;

		*attr = parse_value(key, (char *)key_end + 1);
		if (!*attr)
			return -EINVAL;
	}

	return line_len;
}

void free_wg_dynamic_request(struct wg_dynamic_request *req)
{
	struct wg_dynamic_attr *prev, *cur = req->first;

	while (cur) {
		prev = cur;
		cur = cur->next;
		free(prev);
	}

	req->cmd = WGKEY_UNKNOWN;
	req->version = 0;
	free(req->buf);
	req->buf = NULL;
	req->buflen = 0;
	req->first = NULL;
	req->last = NULL;
}

static int parse_request(struct wg_dynamic_request *req, unsigned char *buf,
			 size_t len)
{
	struct wg_dynamic_attr *attr;
	size_t offset = 0;
	ssize_t ret;

	if (memchr(buf, '\0', len))
		return -EINVAL; /* don't allow null bytes */

	if (req->last && req->last->key == WGKEY_INCOMPLETE) {
		len += req->last->len;

		memmove(buf + req->last->len, buf, len);
		memcpy(buf, req->last->value, req->last->len);
		free(req->last);

		if (req->first == req->last) {
			req->first = NULL;
			req->last = NULL;
		} else {
			attr = req->first;
			while (attr->next != req->last)
				attr = attr->next;

			attr->next = NULL;
			req->last = attr;
		}
	}

	while (len > 0) {
		ret = parse_line(buf + offset, len, &attr,
				 req->cmd == WGKEY_UNKNOWN ? req : NULL);
		if (ret <= 0)
			return ret; /* either error or message complete */

		len -= ret;
		offset += ret;
		if (!attr)
			continue;

		if (!req->first)
			req->first = attr;
		else
			req->last->next = attr;

		req->last = attr;
	}

	return 1;
}

bool handle_request(int fd, struct wg_dynamic_request *req,
		    bool (*success)(int, struct wg_dynamic_request *),
		    bool (*error)(int, int))
{
	ssize_t bytes;
	int ret;
	unsigned char buf[RECV_BUFSIZE + MAX_LINESIZE];

	while (1) {
		bytes = read(fd, buf, RECV_BUFSIZE);
		if (bytes < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			// TODO: handle EINTR

			debug("Reading from socket %d failed: %s\n",
			      fd, strerror(errno));
			return true;
		} else if (bytes == 0) {
			debug("Client disconnected unexpectedly\n");
			return true;
		}

		ret = parse_request(req, buf, bytes);
		if (ret < 0)
			return error(fd, -ret);
		else if (ret == 0)
			return success(fd, req);
	}

	return false;
}

bool send_message(int fd, unsigned char *buf, size_t *len)
{
	ssize_t bytes;
	size_t offset = 0;

	while (*len) {
		bytes = write(fd, buf + offset, *len);
		if (bytes < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			// TODO: handle EINTR

			debug("Writing to socket %d failed: %s\n",
			      fd, strerror(errno));
			return true;
		}

		*len -= bytes;
		offset += bytes;
	}
	return *len == 0;
}
