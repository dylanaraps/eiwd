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

struct command;
struct command_family;

#define COLOR_BOLDGRAY	"\x1B[1;30m"
#define COLOR_GRAY	"\x1b[37m"
#define COLOR_GREEN	"\x1b[32m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_OFF	"\x1B[0m"
#define CHECK		"\u2714"
#define CLEAR_SCREEN	"\033[2J"
#define MARGIN		"  "

void display(const char *format, ...);
void display_table_header(const char *caption, const char *fmt, ...);
void display_table_footer(void);
void display_error(const char *error);
void display_command(const struct command_family *family, const char *cmd_name);
void display_command_line(const char *command_family,
						const struct command *cmd);

void display_enable_cmd_prompt(void);
void display_disable_cmd_prompt(void);

void display_quit(void);

void display_init(void);
void display_exit(void);
