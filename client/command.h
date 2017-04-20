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

typedef char *(*command_completion_func_t) (const char *text, int state);

struct command {
	const char *entity;
	const char *cmd;
	const char *arg;
	void (*function)(const char *entity, char *arg);
	const char *desc;
	const bool refreshable;
};

struct command_family {
	const char *caption;
	const char *name;
	const struct command *command_list;
};

char **command_completion(const char *text, int start, int end);

void command_process_prompt(char *prompt);

void command_family_register(const struct command_family *family);
void command_family_unregister(const struct command_family *family);

struct command_family_desc {
	const char *name;
	int (*init)(void);
	void (*exit)(void);
} __attribute__((aligned(8)));

#define COMMAND_FAMILY(name, init, exit)				\
	static struct command_family_desc __command_family_ ## name	\
		__attribute__((used, section("__command"), aligned(8))) = {\
			#name, init, exit				\
		};							\

void command_init(void);
void command_exit(void);
