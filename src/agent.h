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
					struct l_dbus_message *message,
					void *user_data);
typedef void (*agent_request_user_name_passwd_func_t) (enum agent_result result,
					const char *user, const char *password,
					struct l_dbus_message *message,
					void *user_data);
typedef void (*agent_request_destroy_func_t)(void *user_data);

bool agent_init(struct l_dbus *dbus);
bool agent_exit(struct l_dbus *dbus);
void agent_shutdown(void);

unsigned int agent_request_passphrase(const char *path,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *message,
				void *user_data,
				agent_request_destroy_func_t destroy);
unsigned int agent_request_pkey_passphrase(const char *path,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *trigger,
				void *user_data,
				agent_request_destroy_func_t destroy);
unsigned int agent_request_user_name_password(const char *path,
				agent_request_user_name_passwd_func_t callback,
				struct l_dbus_message *trigger,
				void *user_data,
				agent_request_destroy_func_t destroy);
unsigned int agent_request_user_password(const char *path, const char *user,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *trigger, void *user_data,
				agent_request_destroy_func_t destroy);
bool agent_request_cancel(unsigned int req_id, int reason);
