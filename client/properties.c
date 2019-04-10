/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "properties.h"

const char *properties_on_off_opts[3] = { "on", "off", NULL };
const char *properties_yes_no_opts[3] = { "yes", "no", NULL };

bool properties_builder_append_on_off_variant(
					struct l_dbus_message_builder *builder,
					const char *value_str)
{
	bool value;

	if (!builder || !value_str)
		return false;

	if (!strcmp(value_str, "on"))
		value = true;
	else if (!strcmp(value_str, "off"))
		value = false;
	else
		return false;

	return l_dbus_message_builder_append_basic(builder, 'b', &value);
}

bool properties_builder_append_yes_no_variant(
					struct l_dbus_message_builder *builder,
					const char *value_str)
{
	bool value;

	if (!builder || !value_str)
		return false;

	if (!strcmp(value_str, "yes"))
		value = true;
	else if (!strcmp(value_str, "no"))
		value = false;
	else
		return false;

	return l_dbus_message_builder_append_basic(builder, 'b', &value);
}
