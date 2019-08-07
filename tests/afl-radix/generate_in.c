#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dbg.h"
#include "ip_util.h"

int main(void)
{
	char buf[4096];
	int fd = open("in/1", O_CREAT | O_WRONLY);
	int i = 0;

	buf[i++] = 'a';
	buf[i++] = 0x01;
	buf[i++] = 28;
	memcpy(buf + i, ip4_from("192.168.4.0"), 4);
	i += 4;
	memset(buf + i, 0x0, 12);
	i += 12;
	buf[i++] = '\n';

	buf[i++] = 'a';
	buf[i++] = 0x02;
	buf[i++] = 124;
	memcpy(buf + i, ip6_from("2001:db8:1234::"), 16);
	i += 16;
	buf[i++] = '\n';

	buf[i++] = 'b';
	buf[i++] = 0x01;
	buf[i++] = 0;
	memcpy(buf + i, ip4_from("192.168.4.0"), 4);
	i += 4;
	memset(buf + i, 0x0, 12);
	i += 12;
	buf[i++] = '\n';

	buf[i++] = 'b';
	buf[i++] = 0x02;
	buf[i++] = 0;
	memcpy(buf + i, ip6_from("2001:db8:1234::"), 16);
	i += 16;
	buf[i++] = '\n';

	if (write(fd, buf, i) < i)
		fatal("write()");

	return 0;
}
