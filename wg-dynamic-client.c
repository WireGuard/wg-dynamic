/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include "netlink.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	char *device_names, *device_name;
	size_t len;

	device_names = wg_list_device_names();
	if (!device_names) {
		perror("Unable to get device names");
		return 1;
	}
	wg_for_each_device_name(device_names, device_name, len) {
		wg_device *device;
		wg_peer *peer;
		wg_key_b64_string key;

		if (wg_get_device(&device, device_name) < 0) {
			perror("Unable to get device");
			continue;
		}
		wg_key_to_base64(key, device->public_key);
		printf("%s has public key %s\n", device_name, key);
		wg_for_each_peer(device, peer) {
			wg_key_to_base64(key, peer->public_key);
			printf(" - peer %s\n", key);
		}
		wg_free_device(device);
	}
	free(device_names);
	return 0;
}
