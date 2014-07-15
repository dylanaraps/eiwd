/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <glob.h>
#include <ell/ell.h>

#include "linux/kdbus.h"
#include "src/kdbus.h"

#define POOL_SIZE (16 * 1024LU * 1024LU)

static int kdbus_control = -1;

static int kdbus_conn = -1;
static uint8_t kdbus_id128[16];

bool kdbus_create_bus(void)
{
	struct {
		struct kdbus_cmd_make head;
		/* bloom size item */
		uint64_t bloom_size;
		uint64_t bloom_type;
		struct kdbus_bloom_parameter bloom_param;
		/* name item */
		uint64_t name_size;
		uint64_t name_type;
		char name_param[64];
	} bus_make;

	if (kdbus_control >= 0)
		return false;

	l_debug("Opening /dev/kdbus/control");

	kdbus_control = open("/dev/kdbus/control", O_RDWR | O_CLOEXEC);
	if (kdbus_control < 0) {
		l_error("Failed to open kdbus control interface: %m");
		return false;
	}

	memset(&bus_make, 0, sizeof(bus_make));
	/* bloom size item */
	bus_make.bloom_size = 16 + sizeof(bus_make.bloom_param);
	bus_make.bloom_type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bloom_param.size = 64;
	bus_make.bloom_param.n_hash = 1;
	/* name item */
	snprintf(bus_make.name_param, sizeof(bus_make.name_param),
							"%u-iwd", getuid());
	bus_make.name_size = 16 + strlen(bus_make.name_param) + 1;
	bus_make.name_type = KDBUS_ITEM_MAKE_NAME;
	/* bus make head */
	bus_make.head.size = sizeof(bus_make.head) +
				bus_make.bloom_size + bus_make.name_size;
	bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

	l_debug("Creating bus %s", bus_make.name_param);

	if (ioctl(kdbus_control, KDBUS_CMD_BUS_MAKE, &bus_make) < 0) {
		l_error("Failed to create bus: %m");
		close(kdbus_control);
		kdbus_control = -1;
		return false;
        }

	return true;
}

bool kdbus_destroy_bus(void)
{
	if (kdbus_control < 0)
		return false;

	if (kdbus_conn >= 0) {
		l_debug("Closing bus endpoint");

		close(kdbus_conn);
		kdbus_conn = -1;
	}

	l_debug("Closing kdbus control interface");

	close(kdbus_control);
	kdbus_control = -1;

	return true;
}

char *kdbus_lookup_bus(void)
{
	glob_t gl;
	char *path = NULL;

	if (glob("/dev/kdbus/*-iwd/bus", GLOB_ONLYDIR, NULL, &gl)) {
		l_error("Failed to lookup bus directory");
		return NULL;
	}

	if (gl.gl_pathc < 1) {
		l_error("Failed to lookup bus endpoint");
		return NULL;
	}

	path = l_strdup(gl.gl_pathv[0]);

	globfree(&gl);

	return path;
}

static bool name_acquire(const char *name)
{
	struct {
		struct kdbus_cmd_name head;
		char param[64];
	} cmd_name;

	if (!name)
		return true;

	memset(&cmd_name, 0, sizeof(cmd_name));
	/* cmd name head */
	snprintf(cmd_name.param, sizeof(cmd_name.param), "%s", name);
	cmd_name.head.size = sizeof(cmd_name.head) + strlen(cmd_name.param) + 1;

	l_debug("Acquiring name %s", cmd_name.param);

	if (ioctl(kdbus_conn, KDBUS_CMD_NAME_ACQUIRE, &cmd_name) < 0) {
		l_error("Failed to acquire name: %m");
		return false;
	}

	return true;
}

bool kdbus_open_bus(const char *path, const char *name, const char *conn_name)
{
	struct {
		struct kdbus_cmd_hello head;
		/* conn name item */
		uint64_t name_size;
		uint64_t name_type;
		char name_param[16];
	} cmd_hello;
	uint64_t id, size, n_hash;

	if (kdbus_conn >= 0)
		return false;

	l_debug("Opening %s", path);

	kdbus_conn = open(path, O_RDWR | O_CLOEXEC);
	if (kdbus_conn < 0) {
		l_error("Failed to open bus endpoint: %m");
		return false;
	}

	memset(&cmd_hello, 0, sizeof(cmd_hello));
	/* conn name item */
	snprintf(cmd_hello.name_param, sizeof(cmd_hello.name_param),
							"%s", conn_name);
	cmd_hello.name_size = 16 + strlen(cmd_hello.name_param) + 1;
	cmd_hello.name_type = KDBUS_ITEM_CONN_NAME;
	/* cmd hello head */
	cmd_hello.head.size = sizeof(cmd_hello.head) + cmd_hello.name_size;
	cmd_hello.head.conn_flags = KDBUS_HELLO_ACCEPT_FD;
	cmd_hello.head.attach_flags = KDBUS_ATTACH_TIMESTAMP |
					KDBUS_ATTACH_NAMES |
					KDBUS_ATTACH_CREDS |
					KDBUS_ATTACH_CAPS |
					KDBUS_ATTACH_CGROUP |
					KDBUS_ATTACH_CONN_NAME;
	cmd_hello.head.pool_size = POOL_SIZE;

	l_debug("Sending hello message for %s", cmd_hello.name_param);

	if (ioctl(kdbus_conn, KDBUS_CMD_HELLO, &cmd_hello) < 0) {
		l_error("Failed to send hello: %m");
		close(kdbus_conn);
		kdbus_conn = -1;
		return false;
        }

	id = cmd_hello.head.id;

	l_debug("Name: :1.%" PRIu64, id);

	memcpy(kdbus_id128, cmd_hello.head.id128, sizeof(kdbus_id128));

	l_debug("UUID: %02x%02x%02x%02x-%02x%02x%02x%02x-"
			"%02x%02x%02x%02x-%02x%02x%02x%02x",
				kdbus_id128[0],  kdbus_id128[1],
				kdbus_id128[2],  kdbus_id128[3],
				kdbus_id128[4],  kdbus_id128[5],
				kdbus_id128[6],  kdbus_id128[7],
				kdbus_id128[8],  kdbus_id128[9],
				kdbus_id128[10], kdbus_id128[11],
				kdbus_id128[12], kdbus_id128[13],
				kdbus_id128[14], kdbus_id128[15]);

	size = cmd_hello.head.bloom.size;
	n_hash = cmd_hello.head.bloom.n_hash;

	l_debug("Bloom size: %" PRIu64, size);
	l_debug("Bloom hashes: %" PRIu64, n_hash);

	if (!name_acquire(name)) {
		close(kdbus_conn);
		kdbus_conn = -1;
		return false;
	}

	return true;
};

bool kdbus_close_bus(void)
{
	if (kdbus_conn < 0)
		return false;

	l_debug("Closing bus endpoint");

	close(kdbus_conn);
	kdbus_conn = -1;

	return true;
}
