#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

#include "dbg.h"
#include "radix-trie.h"
#include "ip_util.h"

int main(int argc, char **argv)
{
	struct ip_pool pool;
	char *line = NULL;
	ssize_t len;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;

	ipp_init(&pool);

	while ((len = getline(&line, &(size_t){ 0 }, stdin)) > 0) {
		if (len != 20 || (line[1] != 0x01 && line[1] != 0x02)) {
			free(line);
			line = NULL;
			continue;
		}

		if (line[1] == 0x01)
			ipv4 = (struct in_addr *)&line[3];
		else if (line[1] == 0x02)
			ipv6 = (struct in6_addr *)&line[3];

		switch (line[0]) {
		case 'a':
			if (line[1] == 0x01) {
				debug("ipp_addpool_v4(%y, %u)\n", ipv4,
				      line[2]);
				ipp_addpool_v4(&pool, ipv4, line[2]);
			} else {
				debug("ipp_addpool_v6(%Y, %u)\n", ipv6,
				      line[2]);
				ipp_addpool_v6(&pool, ipv6, line[2]);
			}
			break;
		case 'b':
			if (line[1] == 0x01) {
				debug("ipp_removepool_v4(%y)\n", ipv4);
				ipp_removepool_v4(&pool, ipv4);
			} else {
				debug("ipp_removepool_v6(%Y)\n", ipv6);
				ipp_removepool_v6(&pool, ipv6);
			}
			break;
		}

		free(line);
		line = NULL;
	}

	free(line);
	ipp_free(&pool);

	if (len == -1 && errno)
		fatal("getline()");

	return 0;
}
