/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2015  Intel Corporation. All rights reserved.
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

struct l_settings;

int create_dirs(const char *filename);

ssize_t read_file(void *buffer, size_t len, const char *path_fmt, ...)
	__attribute__((format(printf, 3, 4)));

ssize_t write_file(const void *buffer, size_t len, const char *path_fmt, ...)
	__attribute__((format(printf, 3, 4)));

struct l_settings *storage_network_open(const char *type, const char *ssid);
int storage_network_touch(const char *type, const char *ssid);
void storage_network_sync(const char *type, const char *ssid,
				struct l_settings *settings);
