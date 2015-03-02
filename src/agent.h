/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

#include <stdbool.h>

enum agent_result {
	AGENT_RESULT_OK,
	AGENT_RESULT_FAILED,
};

typedef void (*agent_request_passphrase_func_t) (enum agent_result result,
					const char *passphrase,
					void *user_data);

bool agent_init(void);
void agent_exit(void);
bool agent_setup(struct l_dbus_interface *interface);

unsigned int agent_request_passphrase(const char *path,
				agent_request_passphrase_func_t callback,
				void *user_data);
