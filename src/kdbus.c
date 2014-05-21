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
#include <string.h>
#include <glob.h>
#include <ell/ell.h>

#include "linux/kdbus.h"
#include "src/kdbus.h"

static int kdbus_control = -1;

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

	l_debug("Closing kdbus control interface");

	close(kdbus_control);
	kdbus_control = -1;

	return true;
}

char *kdbus_lookup_bus(void)
{
	glob_t gl;
	size_t i;
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
