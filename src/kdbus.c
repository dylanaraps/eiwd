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

#include <glob.h>
#include <ell/ell.h>

#include "src/kdbus.h"

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
