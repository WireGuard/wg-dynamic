#include <stdio.h>
#include <string.h>

#include "netlink.h"
#include "ip_util.h"

static void add_allowed_ips(wg_key pubkey, struct in_addr *ipv4,
			    struct in6_addr *ipv6)
{
	wg_allowedip allowed_v4, allowed_v6;
	wg_peer peer = { .flags = WGPEER_NO_CREATE };
	wg_device dev = { .first_peer = &peer };

	strcpy(dev.name, "wg0");
	memcpy(peer.public_key, pubkey, sizeof peer.public_key);
	wg_allowedip **cur = &peer.first_allowedip;

	if (ipv4) {
		allowed_v4 = (wg_allowedip){
			.family = AF_INET,
			.cidr = 32,
			.ip4 = *ipv4,
		};
		*cur = &allowed_v4;
		cur = &allowed_v4.next_allowedip;
	}

	if (ipv6) {
		allowed_v6 = (wg_allowedip){
			.family = AF_INET6,
			.cidr = 128,
			.ip6 = *ipv6,
		};
		*cur = &allowed_v6;
	}

	if (wg_set_device(&dev))
		perror("wg_set_device()");
}

int main(void)
{
	struct wg_device *device;
	if (wg_get_device(&device, "wg0")) {
		perror("Unable to access interface wg0");
		return 1;
	}

	if (!device->first_peer) {
		wg_free_device(device);
		return 1;
	}

	wg_key_b64_string str;
	wg_key_to_base64(str, device->first_peer->public_key);
	printf("Public key: %s\n", str);

	char cmd[4096];
	sprintf(cmd, "wg set wg0 peer %s remove", str);
	system(cmd);

	add_allowed_ips(device->first_peer->public_key, ip4_from("192.168.1.1"),
			NULL);

	wg_free_device(device);
	return 0;
}
