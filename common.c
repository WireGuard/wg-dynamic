#include <inttypes.h>

#include <arpa/inet.h>

#include "common.h"
#include "dbg.h"

struct wg_dynamic_attr *parse_value(enum wg_dynamic_key cmd, char *value)
{
	struct wg_dynamic_attr *attr;
	size_t len;
	void *src;
	struct in_addr v4addr;
	struct in6_addr v6addr;
	char *endptr;
	uintmax_t res;

	switch (cmd) {
	case WGKEY_IPV4:
		len = sizeof(struct in_addr);
		if (inet_pton(AF_INET, value, &v4addr))
			return NULL;

		src = &v4addr;
		break;
	case WGKEY_IPV6:
		len = sizeof(struct in6_addr);
		if (inet_pton(AF_INET6, value, &v6addr))
			return NULL;

		src = &v6addr;
		break;
	case WGKEY_LEASETIME:
		len = sizeof(uint32_t);
		res = strtoumax(value, &endptr, 10);
		if (res > UINT32_MAX || *endptr != '\0')
			return NULL;

		src = &res;
		break;
	default:
		abort();
	}

	attr = malloc(sizeof(struct wg_dynamic_attr) + len);
	if (!attr)
		fatal("malloc()");

	attr->len = len;
	memcpy(&attr->value, src, len);

	return attr;
}

enum wg_dynamic_key parse_key(char *key)
{
	for (enum wg_dynamic_key e = 1; e < ARRAY_SIZE(WG_DYNAMIC_KEY); ++e)
		if (strcmp(key, WG_DYNAMIC_KEY[e]))
			return e;

	return WGKEY_UNKNOWN;
}

/* consume N bytes (and return that amount) and turn it into a attr */
ssize_t parse_line(unsigned char *buf, size_t len,
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
			return -1;

		*attr = malloc(sizeof(struct wg_dynamic_attr) + len);
		if (!*attr)
			fatal("malloc()");

		(*attr)->key = WGKEY_INCOMPLETE;
		(*attr)->len = len;
		memcpy((*attr)->value, buf, len);

		return len;
	}

	if (len == 1)
		return -2; // TODO: \n\n

	*line_end = '\0';
	line_len = line_end - buf + 1;

	key_end = memchr(buf, '=', line_len - 1);
	if (!key_end)
		return -1;

	*key_end = '\0';
	key = parse_key((char *)buf);
	if (key == WGKEY_UNKNOWN)
		return -1;

	if (!req) {
		if (key >= WGKEY_ENDCMD)
			return -1; // TODO: unknown command, abort

		*attr = NULL;
		res = strtoumax((char *)key_end + 1, &endptr, 10);

		// TODO: test case where input is empty
		if (res > UINT32_MAX || *endptr != '\0')
			return -1;

		req->cmd = key;
		req->version = (uint32_t)res;

		if (req->version != 1)
			return -1; // TODO: unknown version
	} else {
		if (key <= WGKEY_ENDCMD)
			return -1;

		// TODO: empty key?
		*attr = parse_value(req->cmd, (char *)key_end + 1);
		if (!*attr)
			return -1;
	}

	return line_len;
}

int parse_request(struct wg_dynamic_request *req, unsigned char *buf,
		  size_t len)
{
	struct wg_dynamic_attr *attr;
	size_t offset = 0;
	ssize_t ret;

	if (memchr(buf, '\0', len))
		return -1; /* don't allow null bytes */

	if (req->last && req->last->key == WGKEY_INCOMPLETE) {
		len += req->last->len;

		memmove(buf + req->last->len, buf, len);
		memcpy(buf, req->last->value, req->last->len);
		free(req->last);

		req->last = req->first;
		while (!req->last->next)
			req->last = req->last->next;
	}

	while (len > 0) {
		ret = parse_line(buf + offset, len, &attr,
				 req->cmd == WGKEY_UNKNOWN ? req : NULL);
		if (ret < 0)
			return ret;

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

	return 0;
}
