/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <fnmatch.h>

#include <ell/ell.h>
#include <ell/plugin.h>

#include "src/builtin.h"
#include "src/plugin.h"

static bool check_plugin(struct l_plugin_desc *desc,
						char **include, char **exclude)
{
	char *pattern;
	unsigned int i;

	if (!include)
		goto check_blacklist;

	for (i = 0; (pattern = include[i]); i++) {
		if (fnmatch(pattern, desc->name, 0) != 0)
			continue;

		goto check_blacklist;
	}

	l_debug("whitelist filtered plugin: %s", desc->name);
	return false;

check_blacklist:
	if (!exclude)
		return true;

	for (i = 0; (pattern = exclude[i]); i++) {
		if (fnmatch(pattern, desc->name, 0) == 0) {
			l_debug("blacklist filtered plugin: %s", desc->name);
			return false;
		}
	}

	return true;
}

int plugin_init(const char *include, const char *exclude)
{
	char **inc = NULL;
	char **exc = NULL;
	int i;

	if (include)
		inc = l_strsplit_set(include, ",");

	if (exclude)
		exc = l_strsplit_set(exclude, ",");

	for (i = 0; __iwd_builtin[i]; i++) {
		if (check_plugin(__iwd_builtin[i], inc, exc))
			l_plugin_add(__iwd_builtin[i],
					__iwd_builtin[i]->version);
	}

	l_plugin_load(NULL, NULL, NULL);

	l_strfreev(inc);
	l_strfreev(exc);

	return 1;
}

void plugin_exit(void)
{
	l_plugin_unload();
}
