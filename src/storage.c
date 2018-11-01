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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ell/ell.h>

#include "src/common.h"
#include "src/storage.h"

#ifdef TEMP_FAILURE_RETRY
#define TFR TEMP_FAILURE_RETRY
#else
#define TFR
#endif

#define STORAGE_DIR_MODE (S_IRUSR | S_IWUSR | S_IXUSR)
#define STORAGE_FILE_MODE (S_IRUSR | S_IWUSR)

int create_dirs(const char *filename)
{
	struct stat st;
	char *dir;
	const char *prev, *next;
	int err;

	if (filename[0] != '/')
		return -1;

	err = stat(filename, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	dir = l_malloc(strlen(filename) + 1);
	strcpy(dir, "/");

	for (prev = filename; (next = strchr(prev + 1, '/')); prev = next) {
		/* Skip consecutive '/' characters */
		if (next - prev == 1)
			continue;

		strncat(dir, prev + 1, next - prev);

		if (mkdir(dir, STORAGE_DIR_MODE) == -1 && errno != EEXIST) {
			l_free(dir);
			return -1;
		}
	}

	l_free(dir);
	return 0;
}

ssize_t read_file(void *buffer, size_t len, const char *path_fmt, ...)
{
	va_list ap;
	char *path;
	ssize_t r;
	int fd;

	va_start(ap, path_fmt);
	path = l_strdup_vprintf(path_fmt, ap);
	va_end(ap);

	fd = TFR(open(path, O_RDONLY));

	l_free(path);

	if (fd == -1)
		return -1;

	r = TFR(read(fd, buffer, len));

	TFR(close(fd));

	return r;
}

/*
 * Write a buffer to a file in a transactionally safe form
 *
 * Given a buffer, write it to a file named after
 * @path_fmt+args. However, to make sure the file contents are
 * consistent (ie: a crash right after opening or during write()
 * doesn't leave a file half baked), the contents are written to a
 * file with a temporary name and when closed, it is renamed to the
 * specified name (@path_fmt+args).
 */
ssize_t write_file(const void *buffer, size_t len,
			const char *path_fmt, ...)
{
	va_list ap;
	char *tmp_path, *path;
	ssize_t r;
	int fd;

	va_start(ap, path_fmt);
	path = l_strdup_vprintf(path_fmt, ap);
	va_end(ap);

	tmp_path = l_strdup_printf("%s.XXXXXX.tmp", path);

	r = -1;
	if (create_dirs(path) != 0)
		goto error_create_dirs;

	fd = TFR(mkostemps(tmp_path, 4, O_CLOEXEC));
	if (fd == -1)
		goto error_mkostemps;

	r = TFR(write(fd, buffer, len));
	TFR(close(fd));

	if (r != (ssize_t) len) {
		r = -1;
		goto error_write;
	}

	/*
	 * Now that the file contents are written, rename to the real
	 * file name; this way we are uniquely sure that the whole
	 * thing is there.
	 * conserve @r's value from 'write'
	 */

	if (rename(tmp_path, path) == -1)
		r = -1;

error_write:
	if (r < 0)
		unlink(tmp_path);
error_mkostemps:
error_create_dirs:
	l_free(tmp_path);
	l_free(path);
	return r;
}

char *storage_get_network_file_path(enum security type, const char *ssid)
{
	char *path;
	const char *c;
	char *hex = NULL;

	for (c = ssid; *c; c++)
		if (!isalnum(*c) && !strchr("-_ ", *c))
			break;

	if (*c) {
		hex = l_util_hexstring((const unsigned char *) ssid,
					strlen(ssid));

		path = l_strdup_printf(DAEMON_STORAGEDIR "/=%s.%s", hex,
					security_to_str(type));

		l_free(hex);
	} else
		path = l_strdup_printf(DAEMON_STORAGEDIR "/%s.%s", ssid,
					security_to_str(type));

	return path;
}

const char *storage_network_ssid_from_path(const char *path,
							enum security *type)
{
	const char *filename = strrchr(path, '/');
	const char *c, *end;
	char *decoded;
	static char buf[67];

	if (filename)
		filename++;	/* Skip the / */
	else
		filename = path;

	end = strchr(filename, '.');

	if (!end || !security_from_str(end + 1, type))
		return NULL;

	if (filename[0] != '=') {
		if (end == filename || end - filename > 32)
			return NULL;

		for (c = filename; c < end; c++)
			if (!isalnum(*c) && !strchr("-_ ", *c))
				break;

		if (c < end)
			return NULL;

		memcpy(buf, filename, end - filename);
		buf[end - filename] = '\0';

		return buf;
	}

	if (end - filename <= 1 || end - filename > 65)
		return NULL;

	memcpy(buf, filename + 1, end - filename - 1);
	buf[end - filename - 1] = '0';
	buf[end - filename + 0] = '0';
	buf[end - filename + 1] = '\0';

	decoded = (char *) l_util_from_hexstring(buf, NULL);
	if (!decoded)
		return NULL;

	if (!l_utf8_validate(decoded, (end - filename) / 2, NULL)) {
		l_free(decoded);
		return NULL;
	}

	strcpy(buf, decoded);
	l_free(decoded);

	return buf;
}

struct l_settings *storage_network_open(enum security type, const char *ssid)
{
	struct l_settings *settings;
	char *path;

	if (ssid == NULL)
		return NULL;

	path = storage_get_network_file_path(type, ssid);
	settings = l_settings_new();

	if (!l_settings_load_from_file(settings, path)) {
		l_settings_free(settings);
		settings = NULL;
	}

	l_free(path);
	return settings;
}

int storage_network_touch(enum security type, const char *ssid)
{
	char *path;
	int ret;

	if (ssid == NULL)
		return -EINVAL;

	path = storage_get_network_file_path(type, ssid);
	ret = utimensat(0, path, NULL, 0);
	l_free(path);

	if (!ret)
		return 0;

	return -errno;
}

int storage_network_get_mtime(enum security type, const char *ssid,
				struct timespec *mtim)
{
	char *path;
	int ret;
	struct stat sb;

	if (ssid == NULL)
		return -EINVAL;

	path = storage_get_network_file_path(type, ssid);
	ret = stat(path, &sb);
	l_free(path);

	if (ret < 0)
		return -errno;

	if (!S_ISREG(sb.st_mode))
		return -EINVAL;

	if (mtim)
		memcpy(mtim, &sb.st_mtim, sizeof(struct timespec));

	return 0;
}

void storage_network_sync(enum security type, const char *ssid,
				struct l_settings *settings)
{
	char *data;
	size_t length = 0;
	char *path;

	path = storage_get_network_file_path(type, ssid);
	data = l_settings_to_data(settings, &length);
	write_file(data, length, "%s", path);
	l_free(data);
	l_free(path);
}

int storage_network_remove(enum security type, const char *ssid)
{
	char *path;
	int ret;

	path = storage_get_network_file_path(type, ssid);
	ret = unlink(path);
	l_free(path);

	return ret < 0 ? -errno : 0;
}
