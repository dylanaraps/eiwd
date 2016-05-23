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
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <ell/ell.h>

#include "storage.h"

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
	 */
	unlink(path);

	/* conserve @r's value from 'write' */
	if (link(tmp_path, path) == -1)
		r = -1;

error_write:
	unlink(tmp_path);
error_mkostemps:
error_create_dirs:
	l_free(tmp_path);
	l_free(path);
	return r;
}

static char *get_network_file_path(const char *type, const char *ssid)
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

		path = l_strdup_printf(STORAGEDIR "/=%s.%s", hex, type);

		l_free(hex);
	} else
		path = l_strdup_printf(STORAGEDIR "/%s.%s", ssid, type);

	return path;
}

struct l_settings *storage_network_open(const char *type, const char *ssid)
{
	struct l_settings *settings;
	char *path;

	if (ssid == NULL || type == NULL)
		return NULL;

	path = get_network_file_path(type, ssid);
	settings = l_settings_new();

	l_settings_load_from_file(settings, path);
	l_free(path);

	return settings;
}

int storage_network_touch(const char *type, const char *ssid)
{
	char *path;
	int ret;

	if (ssid == NULL || type == NULL)
		return -EINVAL;

	path = get_network_file_path(type, ssid);
	ret = utimensat(0, path, NULL, 0);
	l_free(path);

	if (!ret)
		return 0;

	return -errno;
}

int storage_network_get_mtime(const char *type, const char *ssid,
				struct timespec *mtim)
{
	char *path;
	int ret;
	struct stat sb;

	if (ssid == NULL || type == NULL)
		return -EINVAL;

	path = get_network_file_path(type, ssid);
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

void storage_network_sync(const char *type, const char *ssid,
				struct l_settings *settings)
{
	char *data;
	size_t length = 0;
	char *path;

	path = get_network_file_path(type, ssid);
	data = l_settings_to_data(settings, &length);
	write_file(data, length, "%s", path);
	l_free(data);
	l_free(path);
}
