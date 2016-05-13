/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <poll.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <glob.h>
#include <ell/ell.h>

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#define CMDLINE_MAX			2048

#define BIN_IW				"/usr/sbin/iw"
#define BIN_HWSIM			"./hwsim"

#define HWSIM_RADIOS_MAX		100
#define TEST_MAX_EXEC_TIME_SEC		20

static const char *own_binary;
static char **test_argv;
static int test_argc;
static bool verbose_out;
static const char *qemu_binary;
static const char *kernel_image;
static const char *exec_home;
static const char *test_dir_list = "";

static const char * const qemu_table[] = {
	"qemu-system-x86_64",
	"qemu-system-i386",
	"/usr/bin/qemu-system-x86_64",
	"/usr/bin/qemu-system-i386",
	NULL
};

static bool path_exist(const char *path_name)
{
	struct stat st;

	if (!stat(path_name, &st))
		return true;

	return false;
}

static const char *find_qemu(void)
{
	int i;

	for (i = 0; qemu_table[i]; i++)
		if (path_exist(qemu_table[i]))
			return qemu_table[i];

	return NULL;
}

static const char * const kernel_table[] = {
	"bzImage",
	"arch/x86/boot/bzImage",
	"vmlinux",
	"arch/x86/boot/vmlinux",
	NULL
};

static const char *find_kernel(void)
{
	int i;

	for (i = 0; kernel_table[i]; i++)
		if (path_exist(kernel_table[i]))
			return kernel_table[i];

	return NULL;
}

static const struct {
	const char *target;
	const char *linkpath;
} dev_table[] = {
	{ "/proc/self/fd",	"/dev/fd"	},
	{ "/proc/self/fd/0",	"/dev/stdin"	},
	{ "/proc/self/fd/1",	"/dev/stdout"	},
	{ "/proc/self/fd/2",	"/dev/stderr"	},
	{ }
};

static const struct {
	const char *fstype;
	const char *target;
	const char *options;
	unsigned long flags;
} mount_table[] = {
	{ "sysfs",    "/sys",     NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "proc",     "/proc",    NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "devpts",   "/dev/pts", "mode=0620", MS_NOSUID|MS_NOEXEC },
	{ "tmpfs",    "/dev/shm", "mode=1777",
					MS_NOSUID|MS_NODEV|MS_STRICTATIME },
	{ "tmpfs",    "/run",     "mode=0755",
					MS_NOSUID|MS_NODEV|MS_STRICTATIME },
	{ "tmpfs",    "/tmp",              NULL, 0 },
	{ "debugfs",  "/sys/kernel/debug", NULL, 0 },
	{ }
};

static const char * const config_table[] = {
	"/usr/share/dbus-1",
	NULL
};

static void prepare_sandbox(void)
{
	int i;

	for (i = 0; mount_table[i].fstype; i++) {
		struct stat st;

		if (lstat(mount_table[i].target, &st) < 0) {
			l_debug("Creating %s\n", mount_table[i].target);
			mkdir(mount_table[i].target, 0755);
		}

		l_debug("Mounting %s to %s\n", mount_table[i].fstype,
							mount_table[i].target);

		if (mount(mount_table[i].fstype,
				mount_table[i].target,
				mount_table[i].fstype,
				mount_table[i].flags,
				mount_table[i].options) < 0) {
			l_error("Error: Failed to mount filesystem %s",
							mount_table[i].target);
		}
	}

	for (i = 0; dev_table[i].target; i++) {
		l_debug("Linking %s to %s\n", dev_table[i].linkpath,
							dev_table[i].target);

		if (symlink(dev_table[i].target, dev_table[i].linkpath) < 0)
			l_error("Failed to create device symlink: %s",
							strerror(errno));
	}

	l_debug("Creating new session group leader");
	setsid();

	l_debug("Setting controlling terminal");
	ioctl(STDIN_FILENO, TIOCSCTTY, 1);

	for (i = 0; config_table[i]; i++) {
		l_debug("Creating %s", config_table[i]);

		if (mount("tmpfs", config_table[i], "tmpfs",
				MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
				"mode=0755") < 0)
			l_error("Failed to create filesystem: %s",
							strerror(errno));
	}
}

static char *const qemu_argv[] = {
	"",
	"-nodefaults",
	"-nodefconfig",
	"-no-user-config",
	"-monitor", "none",
	"-display", "none",
	"-machine", "type=q35,accel=kvm:tcg",
	"-m", "192M",
	"-nographic",
	"-vga", "none",
	"-net", "none",
	"-balloon", "none",
	"-no-acpi",
	"-no-hpet",
	"-no-reboot",
	"-fsdev", "local,id=fsdev-root,path=/,readonly,security_model=none",
	"-device", "virtio-9p-pci,fsdev=fsdev-root,mount_tag=/dev/root",
	"-chardev", "stdio,id=chardev-serial0,signal=off",
	"-device", "pci-serial,chardev=chardev-serial0",
	"-device", "virtio-rng-pci",
	NULL
};

static char *const qemu_envp[] = {
	"HOME=/",
	NULL
};

static bool check_virtualization(void)
{
#if defined(__GNUC__) && (defined(__i386__) || defined(__amd64__))
	uint32_t ecx;

	__asm__ __volatile__("cpuid" : "=c" (ecx) : "a" (1) : "memory");

	if (!!(ecx & (1 << 5))) {
		l_info("Found support for Virtual Machine eXtensions");
		return true;
	}
#endif
	return false;
}

static void start_qemu(void)
{
	char cwd[PATH_MAX], initcmd[PATH_MAX], testargs[PATH_MAX];
	char cmdline[CMDLINE_MAX];
	char **argv;
	int i, pos;
	bool has_virt;

	has_virt = check_virtualization();

	if (!getcwd(cwd, sizeof(cwd)))
		strcat(cwd, "/");

	if (own_binary[0] == '/')
		snprintf(initcmd, sizeof(initcmd), "%s", own_binary);
	else
		snprintf(initcmd, sizeof(initcmd), "%s/%s", cwd, own_binary);

	pos = snprintf(testargs, sizeof(testargs), "%s", test_argv[0]);

	for (i = 1; i < test_argc; i++) {
		int len;

		len = sizeof(testargs) - pos;
		pos += snprintf(testargs + pos, len, " %s", test_argv[i]);
	}

	snprintf(cmdline, sizeof(cmdline),
			"console=ttyS0,115200n8 earlyprintk=serial "
			"rootfstype=9p "
			"root=/dev/root "
			"rootflags=trans=virtio,version=9p2000.u "
			"acpi=off pci=noacpi noapic quiet ro "
			"mac80211_hwsim.radios=0 "
			"init=%s TESTHOME=%s TESTVERBOUT=%u "
			"TESTDIRLIST=\'%s\' TESTARGS=\'%s\'", initcmd, cwd,
			verbose_out, test_dir_list, testargs);

	argv = alloca(sizeof(qemu_argv));
	memcpy(argv, qemu_argv, sizeof(qemu_argv));

	pos = (sizeof(qemu_argv) / sizeof(char *)) - 1;

	argv[0] = (char *) qemu_binary;
	argv[pos++] = "-kernel";
	argv[pos++] = (char *) kernel_image;
	argv[pos++] = "-append";
	argv[pos++] = (char *) cmdline;

	if (has_virt)
		argv[pos++] = "-enable-kvm";

	argv[pos] = NULL;

	execve(argv[0], argv, qemu_envp);
}

static void set_output_visibility(void)
{
	int fd;

	if (verbose_out)
		return;

	fd = open("/dev/null", O_WRONLY);

	dup2(fd, 1);
	dup2(fd, 2);

	close(fd);
}

static pid_t execute_program(char *argv[], bool wait)
{
	int status;
	pid_t pid, child_pid;

	if (!argv[0])
		return -1;

	child_pid = fork();
	if (child_pid < 0) {
		l_error("Failed to fork new process");
		return -1;
	}

	if (child_pid == 0) {
		set_output_visibility();

		execvp(argv[0], argv);

		l_error("Failed to call execvp for: %s. Error: %s", argv[0],
							strerror(errno));

		exit(EXIT_FAILURE);
	}

	if (!wait)
		goto exit;

	do {
		pid = waitpid(child_pid, &status, 0);
	} while (!WIFEXITED(status) && pid == child_pid);

	if (WEXITSTATUS(status) != EXIT_SUCCESS)
		return -1;

exit:
	return child_pid;
}

static void kill_process(pid_t pid)
{
	int status;

	l_debug("Terminate pid: %d", pid);

	kill(pid, SIGTERM);

	do {
		waitpid(pid, &status, 0);
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

static bool wait_for_socket(const char *socket, useconds_t wait_time)
{
	int i = 0;

	do {
		if (path_exist(socket))
			return true;

		usleep(wait_time);
	} while (i++ < 20);

	l_error("Error: cannot find socket: %s", socket);
	return false;
}

static void create_dbus_system_conf(void)
{
	FILE *fp;

	fp = fopen("/usr/share/dbus-1/system.conf", "we");
	if (!fp)
		return;

	fputs("<!DOCTYPE busconfig PUBLIC ", fp);
	fputs("\"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" ", fp);
	fputs("\"http://www.freedesktop.org/standards/dbus/1.0/", fp);
	fputs("busconfig.dtd\">\n", fp);
	fputs("<busconfig>\n", fp);
	fputs("<type>system</type>\n", fp);
	fputs("<listen>unix:path=/run/dbus/system_bus_socket</listen>\n", fp);
	fputs("<policy context=\"default\">\n", fp);
	fputs("<allow user=\"*\"/>\n", fp);
	fputs("<allow own=\"*\"/>\n", fp);
	fputs("<allow send_type=\"method_call\"/>\n", fp);
	fputs("<allow send_type=\"signal\"/>\n", fp);
	fputs("<allow send_type=\"method_return\"/>\n", fp);
	fputs("<allow send_type=\"error\"/>\n", fp);
	fputs("<allow receive_type=\"method_call\"/>\n", fp);
	fputs("<allow receive_type=\"signal\"/>\n", fp);
	fputs("<allow receive_type=\"method_return\"/>\n", fp);
	fputs("<allow receive_type=\"error\"/>\n", fp);
	fputs("</policy>\n", fp);
	fputs("</busconfig>\n", fp);

	fclose(fp);

	mkdir("/run/dbus", 0755);
}

static pid_t start_dbus_daemon(void)
{
	char *argv[3];
	pid_t pid;

	argv[0] = "/usr/bin/dbus-daemon";
	argv[1] = "--system";
	argv[2] = NULL;

	pid = execute_program(argv, false);
	if (pid < 0)
		return -1;

	if (!wait_for_socket("/run/dbus/system_bus_socket", 25 * 10000))
		return -1;

	l_info("D-Bus is running");

	return pid;
}

static bool set_interface_state(const char *if_name, bool isUp)
{
	char *state, *argv[4];
	pid_t pid;

	if (isUp)
		state = "up";
	else
		state = "down";

	argv[0] = "/usr/sbin/ifconfig";
	argv[1] = (char *) if_name;
	argv[2] = state;
	argv[3] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

static bool create_interface(const char *if_name, const char *phy_name)
{
	char *argv[9];
	pid_t pid;

	argv[0] = BIN_IW;
	argv[1] = "phy";
	argv[2] = (char *) phy_name;
	argv[3] = "interface";
	argv[4] = "add";
	argv[5] = (char *) if_name;
	argv[6] = "type";
	argv[7] = "managed";
	argv[8] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

static bool delete_interface(const char *if_name)
{
	char *argv[5];
	pid_t pid;

	argv[0] = BIN_IW;
	argv[1] = "dev";
	argv[2] = (char *) if_name;
	argv[3] = "del";
	argv[4] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

static bool list_interfaces(void)
{
	char *argv[3];
	pid_t pid;

	argv[0] = "ifconfig";
	argv[1] = "-a";
	argv[2] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

static bool list_hwsim_radios(void)
{
	char *argv[3];
	pid_t pid;

	if (chdir(exec_home + 5) < 0) {
		l_error("Failed to change home test directory: %s",
							strerror(errno));
		return false;
	}

	argv[0] = BIN_HWSIM;
	argv[1] = "--list";
	argv[2] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

static int read_radio_id(void)
{
	static int current_radio_id;

	return current_radio_id++;
}

static int create_hwsim_radio(const char *radio_name,
				const unsigned int channels, bool p2p_device,
							bool use_chanctx)
{
	char *argv[6];
	pid_t pid;

	if (chdir(exec_home + 5) < 0) {
		l_error("Failed to change home test directory: %s",
							strerror(errno));
		return -1;
	}

	/*TODO add the rest of params*/
	argv[0] = BIN_HWSIM;
	argv[1] = "--create";
	argv[2] = "--keep";
	argv[3] = "--name";
	argv[4] = (char *) radio_name;
	argv[5] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return -1;

	return read_radio_id();
}

static bool destroy_hwsim_radio(int radio_id)
{
	char *argv[4];
	char destroy_param[20];
	pid_t pid;

	sprintf(destroy_param, "--destroy=%d", radio_id);

	if (chdir(exec_home + 5) < 0) {
		l_error("Failed to change home test directory: %s",
							strerror(errno));
		return false;
	}

	argv[0] = BIN_HWSIM;
	argv[1] = destroy_param;
	argv[2] = NULL;

	pid = execute_program(argv, true);
	if (pid < 0)
		return false;

	return true;
}

#define HOSTAPD_CTRL_INTERFACE_PREFIX "/var/run/hostapd"

static pid_t start_hostapd(const char *config_file, const char *interface_name)
{
	char *argv[5];
	char *ctrl_interface;
	pid_t pid;

	ctrl_interface = l_strdup_printf("%s/%s", HOSTAPD_CTRL_INTERFACE_PREFIX,
								interface_name);

	argv[0] = "/usr/sbin/hostapd";
	argv[1] = "-g";
	argv[2] = ctrl_interface;
	argv[3] = (char *) config_file;
	argv[4] = NULL;

	pid = execute_program(argv, false);
	if (pid < 0) {
		goto exit;
	}

	if (!wait_for_socket(ctrl_interface, 25 * 10000))
		pid = -1;

exit:
	l_free(ctrl_interface);

	return pid;
}

static void destroy_hostapd_instances(pid_t hostapd_pids[])
{
	int i = 0;

	while (hostapd_pids[i] != -1) {
		kill_process(hostapd_pids[i]);

		l_debug("hostapd instance with pid=%d is destroyed",
			hostapd_pids[i]);

		hostapd_pids[i] = -1;

		i++;
	}
}

#define TEST_TOP_DIR_DEFAULT_NAME	"autotests"
#define TEST_DIR_PREFIX			"test"
#define TEST_FILE_SUFFIX1		"Test"
#define TEST_FILE_SUFFIX2		"Test.py"

static int is_test_file(const char *file)
{
	return l_str_has_suffix(file, TEST_FILE_SUFFIX1) ||
		l_str_has_suffix(file, TEST_FILE_SUFFIX2);
}

static int is_test_dir(const char *dir)
{
	return strncmp(dir, TEST_DIR_PREFIX, strlen(TEST_DIR_PREFIX)) == 0;
}

static bool find_test_configuration(const char *path, int level,
						struct l_hashmap *config_map)
{
	DIR *dir = NULL;
	struct l_queue *py_test_queue = NULL;
	struct dirent *entry;
	char *npath;

	if (!config_map)
		return false;

	dir = opendir(path);
	if (!dir) {
		l_error("Test directory does not exist: %s", path);
		return false;
	}

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR) {
			if (!strcmp(entry->d_name, ".") ||
					!strcmp(entry->d_name, ".."))
				continue;

			if (level == 0 && is_test_dir(entry->d_name)) {
				npath = l_strdup_printf("%s/%s", path,
								entry->d_name);

				find_test_configuration(npath, 1, config_map);

				l_free(npath);
			}
		} else if (level == 1 && is_test_file(entry->d_name)) {
			if (!py_test_queue)
				py_test_queue = l_queue_new();

			l_queue_push_tail(py_test_queue,
						l_strdup(entry->d_name));
		}
	}

	if (py_test_queue && !l_queue_isempty(py_test_queue))
		l_hashmap_insert(config_map, path, py_test_queue);

	closedir(dir);
	return true;
}

#define HW_CONFIG_FILE_NAME		"hw.conf"
#define HW_CONFIG_GROUP_HOSTAPD		"HOSTAPD"
#define HW_CONFIG_GROUP_SETUP		"SETUP"

#define HW_CONFIG_SETUP_NUM_RADIOS	"num_radios"
#define HW_CONFIG_SETUP_RADIO_CONFS	"radio_confs"
#define HW_CONFIG_SETUP_MAX_EXEC_SEC	"max_test_exec_interval_sec"

static struct l_settings *read_hw_config(const char *test_dir_path)
{
	struct l_settings *hw_settings;
	char *hw_file;

	hw_file = l_strdup_printf("%s/%s", test_dir_path, HW_CONFIG_FILE_NAME);

	hw_settings = l_settings_new();

	if (!l_settings_load_from_file(hw_settings, hw_file)) {
		l_error("No %s file found", HW_CONFIG_FILE_NAME);
		goto error_exit;
	}

	if (!l_settings_has_group(hw_settings, HW_CONFIG_GROUP_SETUP)) {
		l_error("No %s setting group found in %s",
						HW_CONFIG_GROUP_SETUP, hw_file);
		goto error_exit;
	}

	l_free(hw_file);
	return hw_settings;

error_exit:
	l_free(hw_file);
	l_settings_free(hw_settings);
	return NULL;
}

#define HW_CONFIG_PHY_CHANNELS	"channels"
#define HW_CONFIG_PHY_CHANCTX	"use_chanctx"
#define HW_CONFIG_PHY_P2P	"p2p_device"

#define HW_PHY_NAME_PREFIX	"PHY"

#define HW_MIN_NUM_RADIOS	1

#define HW_INTERFACE_PREFIX	"wln"
#define HW_INTERFACE_STATE_UP   true
#define HW_INTERFACE_STATE_DOWN false

static bool configure_hw_radios(struct l_settings *hw_settings,
						int hwsim_radio_ids[],
						char *interface_names_out[])
{
	char interface_name[7];
	char phy_name[7];
	char **radio_conf_list;
	int i, num_radios_requested, num_radios_created;
	bool status = true;
	bool has_hw_conf;

	l_settings_get_int(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_NUM_RADIOS,
							&num_radios_requested);

	if (num_radios_requested < HW_MIN_NUM_RADIOS) {
		l_error("%s must be greater or equal to %d",
			HW_CONFIG_SETUP_NUM_RADIOS, HW_MIN_NUM_RADIOS);
		return false;
	}

	has_hw_conf = l_settings_has_key(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_RADIO_CONFS);

	radio_conf_list =
		l_settings_get_string_list(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_RADIO_CONFS,
									':');

	num_radios_created = 0;
	i = 0;

	while (num_radios_requested > num_radios_created) {
		char *radio_config_group;

		unsigned int channels;
		bool p2p_device;
		bool use_chanctx;

		if (!has_hw_conf || !radio_conf_list[i]) {
			channels = 1;
			p2p_device = true;
			use_chanctx = true;

			has_hw_conf = false;
			goto configure;
		}

		radio_config_group = radio_conf_list[i++];

		if (!l_settings_has_group(hw_settings, radio_config_group)) {
			l_error("No radio configuration group [%s] found in "
					"config. file.", radio_config_group);

			status = false;
			goto exit;
		}

		if (!l_settings_get_uint(hw_settings, radio_config_group,
							HW_CONFIG_PHY_CHANNELS,
								&channels))
			channels = 1;

		if (!l_settings_get_bool(hw_settings, radio_config_group,
							HW_CONFIG_PHY_P2P,
								&p2p_device))
			p2p_device = true;

		if (!l_settings_get_bool(hw_settings, radio_config_group,
							HW_CONFIG_PHY_CHANCTX,
								&use_chanctx))
			use_chanctx = true;

configure:
		sprintf(phy_name, "%s%d", HW_PHY_NAME_PREFIX,
							num_radios_created);

		hwsim_radio_ids[num_radios_created] =
			create_hwsim_radio(phy_name, channels, p2p_device,
							use_chanctx);

		if (hwsim_radio_ids[num_radios_created] < 0) {
			status = false;
			goto exit;
		}

		sprintf(interface_name, "%s%d", HW_INTERFACE_PREFIX,
							num_radios_created);

		if (!create_interface(interface_name, phy_name)) {
			status = false;
			goto exit;
		}

		l_info("Created interface %s on %s radio", interface_name,
								phy_name);

		if (!set_interface_state(interface_name,
						HW_INTERFACE_STATE_UP)) {
			status = false;
			goto exit;
		}

		interface_names_out[num_radios_created] =
							strdup(interface_name);

		num_radios_created++;
	}

	interface_names_out[num_radios_created + 1] = NULL;

exit:
	l_strfreev(radio_conf_list);
	return status;
}

static void destroy_hw_radios(int hwsim_radio_ids[],
				char *interface_names_in[])
{
	int i = 0;

	while (interface_names_in[i]) {
		set_interface_state(interface_names_in[i],
					HW_INTERFACE_STATE_DOWN);

		delete_interface(interface_names_in[i]);
		l_debug("Removed interface %s", interface_names_in[i]);

		interface_names_in[i] = NULL;

		i++;
	}

	i = 0;

	while (hwsim_radio_ids[i] != -1) {
		destroy_hwsim_radio(hwsim_radio_ids[i]);
		l_debug("Removed radio id %d", hwsim_radio_ids[i]);

		hwsim_radio_ids[i] = -1;

		i++;
	}
}

static bool configure_hostapd_instances(struct l_settings *hw_settings,
						char *config_dir_path,
						char *interface_names_in[],
						pid_t hostapd_pids_out[])
{
	char **hostap_keys;
	int i = 0;

	if (!l_settings_has_group(hw_settings, HW_CONFIG_GROUP_HOSTAPD)) {
		l_info("No hostapd instances to create");
		return true;
	}

	hostap_keys =
		l_settings_get_keys(hw_settings, HW_CONFIG_GROUP_HOSTAPD);

	while (hostap_keys[i]) {
		char hostapd_config_file_path[PATH_MAX];
		const char *hostapd_config_file;
		char *interface_name;

		hostapd_config_file =
			l_settings_get_value(hw_settings,
						HW_CONFIG_GROUP_HOSTAPD,
						hostap_keys[i]);

		snprintf(hostapd_config_file_path, PATH_MAX - 1, "%s/%s",
				config_dir_path,
				hostapd_config_file);

		hostapd_config_file_path[PATH_MAX - 1] = '\0';

		if (!path_exist(hostapd_config_file_path)) {
			l_error("%s : hostapd configuration file [%s] "
				"does not exist.", HW_CONFIG_FILE_NAME,
						hostapd_config_file_path);
			return false;
		}

		interface_name = interface_names_in[i];

		hostapd_pids_out[i] = start_hostapd(hostapd_config_file_path,
								interface_name);

		if (hostapd_pids_out[i] < 1)
			return false;

		i++;
	}

	return true;
}

static pid_t start_iwd(void)
{
	char *argv[2];

	argv[0] = "/usr/bin/iwd";
	argv[1] = NULL;

	return execute_program(argv, false);
}

static void terminate_iwd(pid_t iwd_pid)
{
	kill_process(iwd_pid);
}

#define CONSOLE_LN_DEFAULT	"\x1B[0m"
#define CONSOLE_LN_RED		"\x1B[31m"
#define CONSOLE_LN_GREEN	"\x1B[32m"
#define CONSOLE_LN_BLACK	"\x1B[30m"
#define CONSOLE_LN_YELLOW	"\x1B[33m"
#define CONSOLE_LN_RESET	"\033[0m"

#define CONSOLE_LN_BOLD		"\x1b[1m"

#define CONSOLE_BG_WHITE	"\e[47m"
#define CONSOLE_BG_DEFAULT	"\e[0m"

enum test_status {
	TEST_STATUS_STARTED,
	TEST_STATUS_PASSED,
	TEST_STATUS_FAILED,
	TEST_STATUS_TIMEDOUT,
};

static void print_test_status(char *test_name, enum test_status ts,
								double interval)
{
	const char *clear_line = "\r";
	int int_len;
	char *color_str;
	char *status_str;
	char *interval_str;
	char *line_end = "";

	switch (ts) {
	case TEST_STATUS_STARTED:
		color_str = CONSOLE_LN_RESET;
		status_str = "STARTED   ";

		if (verbose_out)
			line_end = "\n";

		break;
	case TEST_STATUS_PASSED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_GREEN;
		status_str = "PASSED    ";
		line_end = "\n";

		break;
	case TEST_STATUS_FAILED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_RED;
		status_str = "FAILED    ";
		line_end = "\n";

		break;
	case TEST_STATUS_TIMEDOUT:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_YELLOW;
		status_str = "TIMED OUT ";
		line_end = "\n";

		break;
	}

	if (interval > 0)
		int_len = snprintf(NULL, 0, "%.3f", interval);
	else
		int_len = 3;

	int_len++;

	interval_str = l_malloc(int_len);
	memset(interval_str, ' ', int_len);
	interval_str[int_len] = '\0';

	if (interval > 0)
		sprintf(interval_str, "%.3f sec", interval);
	else
		sprintf(interval_str, "%s", "...");

	printf("%s%s%s%-60s%7s%s", color_str, status_str, CONSOLE_LN_RESET,
		test_name, interval_str, line_end);

	fflush(stdout);

	l_free(interval_str);
}

static void test_timeout_timer_tick(struct l_timeout *timeout, void *user_data)
{
	pid_t *test_exec_pid = (pid_t *) user_data;

	kill_process(*test_exec_pid);

	l_main_quit();
}

static void test_timeout_signal_handler(struct l_signal *signal, uint32_t signo,
								void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static pid_t start_execution_timeout_timer(unsigned int max_exec_interval_sec,
							pid_t *test_exec_pid)
{
	sigset_t mask;
	struct l_signal *signal;
	struct l_timeout *test_exec_timeout;
	pid_t test_timer_pid;

	test_timer_pid = fork();
	if (test_timer_pid < 0) {
		l_error("Failed to fork new process");
		return -1;
	}

	if (test_timer_pid == 0) {
		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);

		signal = l_signal_create(&mask, test_timeout_signal_handler,
							test_exec_pid, NULL);
		test_exec_timeout =
			l_timeout_create(max_exec_interval_sec,
						test_timeout_timer_tick,
						test_exec_pid,
						NULL);

		l_main_run();

		l_timeout_remove(test_exec_timeout);
		l_signal_remove(signal);

		exit(EXIT_SUCCESS);
	}

	return test_timer_pid;
}

struct test_stats {
	char *config_cycle_name;
	unsigned int num_passed;
	unsigned int num_failed;
	unsigned int num_timedout;
	double py_run_time;
};

static void run_py_tests(struct l_settings *hw_settings,
					struct l_queue *test_queue,
					struct l_queue *test_stats_queue)
{
	char *argv[3];
	pid_t test_exec_pid, test_timer_pid;
	struct timeval time_before, time_after, time_elapsed;
	unsigned int max_exec_interval;
	char *py_test = NULL;
	struct test_stats *test_stats;

	if (!l_settings_get_uint(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_MAX_EXEC_SEC,
							&max_exec_interval))
		max_exec_interval = TEST_MAX_EXEC_TIME_SEC;

	l_info(CONSOLE_LN_BOLD "%-10s%-60s%s" CONSOLE_LN_RESET, "Status",
							"Test", "Duration");

start_next_test:

	if (l_queue_isempty(test_queue))
		return;

	py_test = (char *) l_queue_pop_head(test_queue);
	if (!py_test)
		return;

	argv[0] = "/usr/bin/python";
	argv[1] = py_test;
	argv[2] = NULL;

	print_test_status(py_test, TEST_STATUS_STARTED, 0);
	test_exec_pid = execute_program(argv, false);

	gettimeofday(&time_before, NULL);

	test_timer_pid = start_execution_timeout_timer(max_exec_interval,
								&test_exec_pid);

	test_stats = (struct test_stats *) l_queue_peek_tail(test_stats_queue);

	while (true) {
		pid_t corpse;
		int status;
		double interval;
		const int BUF_LEN = 11;
		char interval_buf[BUF_LEN];

		corpse = waitpid(WAIT_ANY, &status, 0);

		if (corpse < 0 || corpse == 0)
			continue;

		if (test_exec_pid == corpse) {
			gettimeofday(&time_after, NULL);

			kill_process(test_timer_pid);

			timersub(&time_after, &time_before, &time_elapsed);
			sprintf(interval_buf, "%ld.%0ld",
					(long int) time_elapsed.tv_sec,
					(long int) time_elapsed.tv_usec);
			interval_buf[BUF_LEN - 1] = '\0';
			interval = atof(interval_buf);

			if (WIFEXITED(status) &&
					WEXITSTATUS(status) == EXIT_SUCCESS) {
				print_test_status(py_test, TEST_STATUS_PASSED,
							interval);
				test_stats->num_passed++;
			} else if (WIFSIGNALED(status)) {
				print_test_status(py_test, TEST_STATUS_TIMEDOUT,
								interval);
				test_stats->num_timedout++;
			} else {
				print_test_status(py_test, TEST_STATUS_FAILED,
								interval);
				test_stats->num_failed++;
			}

			test_stats->py_run_time += interval;

			break;
		} else if (WIFSTOPPED(status))
			l_info("Process %d stopped with signal %d", corpse,
			       WSTOPSIG(status));
		else if (WIFCONTINUED(status))
			l_info("Process %d continued", corpse);
	}

	l_free(py_test);
	py_test = NULL;

	goto start_next_test;
}

static void set_config_cycle_info(const char *config_dir_path,
					struct l_queue *test_stats_queue)
{
	char sep_line[80];
	char *config_name_ptr;
	struct test_stats *test_stats;

	memset(sep_line, '_', sizeof(sep_line) - 1);

	config_name_ptr = strrchr(config_dir_path, '/');
	config_name_ptr++;

	l_info("%s", sep_line);
	l_info(CONSOLE_LN_BOLD "Starting configuration cycle No: %d [%s]"
		CONSOLE_LN_RESET, l_queue_length(test_stats_queue) + 1,
							config_name_ptr);

	test_stats = l_new(struct test_stats, 1);
	test_stats->config_cycle_name = strdup(config_name_ptr);

	l_queue_push_tail(test_stats_queue, test_stats);
}

static void create_network_and_run_tests(const void *key, void *value,
								void *data)
{
	int hwsim_radio_ids[HWSIM_RADIOS_MAX];
	char *interface_names[HWSIM_RADIOS_MAX];
	pid_t hostapd_pids[HWSIM_RADIOS_MAX];
	pid_t iwd_pid;
	char *config_dir_path;
	struct l_settings *hw_settings;
	struct l_queue *test_queue;
	struct l_queue *test_stats_queue;

	if (!key || !value)
		return;

	memset(hwsim_radio_ids, -1, sizeof(hwsim_radio_ids));
	memset(hostapd_pids, -1, sizeof(hostapd_pids));

	config_dir_path = (char *) key;
	test_queue = (struct l_queue *) value;
	test_stats_queue = (struct l_queue *) data;

	if (l_queue_isempty(test_queue)) {
		l_error("No Python IWD tests have been found in %s",
							config_dir_path);
		return;
	}

	set_config_cycle_info(config_dir_path, test_stats_queue);

	hw_settings = read_hw_config(config_dir_path);
	if (!hw_settings)
		return;

	l_info("Configuring network...");

	if (!configure_hw_radios(hw_settings, hwsim_radio_ids,
							interface_names))
		goto exit_hwsim;

	list_hwsim_radios();

	list_interfaces();

	if (!configure_hostapd_instances(hw_settings, config_dir_path,
						interface_names, hostapd_pids))
		goto exit_hostapd;

	iwd_pid = start_iwd();
	if (iwd_pid == -1)
		goto exit_hostapd;

	if (chdir(config_dir_path) < 0) {
		l_error("Failed to change directory");
		goto exit_hostapd;
	}

	run_py_tests(hw_settings, test_queue, test_stats_queue);

	l_info("Destructing network...");

	terminate_iwd(iwd_pid);

exit_hostapd:
	destroy_hostapd_instances(hostapd_pids);

exit_hwsim:
	destroy_hw_radios(hwsim_radio_ids, interface_names);

	l_settings_free(hw_settings);
}

struct stat_totals {
	unsigned int total_passed;
	unsigned int total_failed;
	unsigned int total_timedout;
	double total_duration;
};

static void print_test_stat(void *data, void *user_data)
{
	struct test_stats *test_stats;
	struct stat_totals *stat_totals;

	test_stats = (struct test_stats *) data;
	stat_totals = (struct stat_totals *) user_data;

	stat_totals->total_duration	+= test_stats->py_run_time;
	stat_totals->total_passed	+= test_stats->num_passed;
	stat_totals->total_failed	+= test_stats->num_failed;
	stat_totals->total_timedout	+= test_stats->num_timedout;

	l_info(CONSOLE_LN_BOLD "%27s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW " %9d "
		CONSOLE_LN_RESET "| %9.3f sec",
		test_stats->config_cycle_name, test_stats->num_passed,
		test_stats->num_failed, test_stats->num_timedout,
						test_stats->py_run_time);
}

static void print_results(struct l_queue *test_stat_queue)
{
	struct stat_totals stat_totals;
	char sep_line[80];

	memset(sep_line, '_', sizeof(sep_line) - 1);

	l_info("%s\n" CONSOLE_LN_RESET, sep_line);
	l_info("%27s " CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN " %s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED " %5s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW " %9s "
		CONSOLE_LN_RESET "| Duration",
		"Configuration cycle", "PASSED", "FAILED", "TIMED OUT");

	memset(sep_line, '-', sizeof(sep_line) - 1);
	l_info("%s" CONSOLE_LN_RESET, sep_line);

	l_queue_foreach(test_stat_queue, print_test_stat, &stat_totals);

	l_info("%s" CONSOLE_LN_RESET, sep_line);
	l_info("%27s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW " %9d "
		CONSOLE_LN_RESET "| %9.3f sec",
		"Total", stat_totals.total_passed, stat_totals.total_failed,
			stat_totals.total_timedout, stat_totals.total_duration);

	memset(sep_line, '_', sizeof(sep_line) - 1);
	l_info("%s" CONSOLE_LN_RESET, sep_line);
}

static void test_stat_queue_entry_destroy(void *data)
{
	struct test_stats *ts;

	ts = (struct test_stats *) data;

	l_free(ts->config_cycle_name);
	l_free(ts);
}

static void run_command(char *cmdname)
{
	char tmp_path[PATH_MAX];
	char test_home_path[PATH_MAX];
	char *ptr;
	pid_t dbus_pid;
	int i;
	struct l_hashmap *test_config_map;
	struct l_queue *test_stat_queue;
	char **test_config_dirs;

	ptr = strrchr(exec_home, '/');
	if (!ptr)
		exit(EXIT_FAILURE);

	i = ptr - exec_home;

	strncpy(tmp_path, exec_home + 5, i - 5);
	tmp_path[i - 5] = '\0';

	sprintf(test_home_path, "%s/%s", tmp_path, TEST_TOP_DIR_DEFAULT_NAME);

	if (!path_exist(test_home_path)) {
		l_error("Test directory %s does not exist", test_home_path);
		return;
	}

	test_config_map = l_hashmap_string_new();
	if (!test_config_map)
		return;

	test_config_dirs = l_strsplit(test_dir_list, ',');

	if (test_config_dirs[0]) {
		i = 0;

		while (test_config_dirs[i]) {
			if (strchr(test_config_dirs[i], '/')) {
				if (!find_test_configuration(
							test_config_dirs[i], 1,
							test_config_map))
					goto exit;
			} else {
				char *config_dir_path;

				config_dir_path =
					l_strdup_printf("%s/%s", test_home_path,
							test_config_dirs[i]);

				if (!find_test_configuration(config_dir_path, 1,
							test_config_map)) {
					l_free(config_dir_path);

					goto exit;
				}

				l_free(config_dir_path);
			}

			i++;
		}
	} else {
		l_info("Automatic test execution requested");
		l_info("Searching for the test configurations...");

		if (!find_test_configuration(test_home_path, 0,
							test_config_map))
			goto exit;
	}

	if (l_hashmap_isempty(test_config_map)) {
		l_error("No test configuration discovered");
		goto exit;
	}

	create_dbus_system_conf();

	dbus_pid = start_dbus_daemon();
	if (dbus_pid < 0)
		goto exit;

	test_stat_queue = l_queue_new();

	l_hashmap_foreach(test_config_map, create_network_and_run_tests,
							test_stat_queue);

	print_results(test_stat_queue);

	l_queue_destroy(test_stat_queue, test_stat_queue_entry_destroy);

exit:
	l_strfreev(test_config_dirs);
	l_hashmap_destroy(test_config_map, NULL);
}

static void run_tests(void)
{
	char cmdline[CMDLINE_MAX], *ptr, *cmds;
	FILE *fp;

	fp = fopen("/proc/cmdline", "re");
	if (!fp) {
		l_error("Failed to open kernel command line");
		return;
	}

	ptr = fgets(cmdline, sizeof(cmdline), fp);
	fclose(fp);

	if (!ptr) {
		l_error("Failed to read kernel command line");
		return;
	}

	ptr = strstr(cmdline, "TESTARGS=");
	if (!ptr) {
		l_error("No test command section found");
		return;
	}

	cmds = ptr + 10;
	ptr = strchr(cmds, '\'');
	if (!ptr) {
		l_error("Malformed test command section");
		return;
	}

	*ptr = '\0';

	ptr = strstr(cmdline, "TESTVERBOUT=1");
	if (ptr) {
		l_info("Enable verbose output");
		verbose_out = true;
	}

	ptr = strstr(cmdline, "TESTDIRLIST=");
	if (!ptr) {
		l_error("No test configuration directory list section found");
		return;
	}

	test_dir_list = ptr + 13;
	ptr = strchr(test_dir_list, '\'');
	if (!ptr) {
		l_error("Malformed test configuration directory list section");
		return;
	}

	*ptr = '\0';

	ptr = strstr(cmdline, "TESTHOME=");
	if (ptr) {
		exec_home = ptr + 4;
		ptr = strpbrk(exec_home + 9, " \r\n");
		if (ptr)
			*ptr = '\0';
	}

	run_command(cmds);
}

static void usage(void)
{
	l_info("testrunner - Automated test execution utility\n"
		"Usage:\n");
	l_info("\ttest-runner [options] [--] <command> [args]\n");
	l_info("Options:\n"
		"\t-q, --qemu <path>	QEMU binary\n"
		"\t-k, --kernel <image>	Kernel image (bzImage)\n"
		"\t-t, --testdirs <dirs>	Comma separated list of the "
						"test configuration\n\t\t\t\t"
						"directories to run\n"
		"\t-v, --verbose		Enable verbose output\n"
		"\t-h, --help		Show help options\n");
}

static const struct option main_options[] = {
	{ "qemu",	required_argument, NULL, 'q' },
	{ "kernel",	required_argument, NULL, 'k' },
	{ "testdirs",	required_argument, NULL, 't' },
	{ "verbose",	no_argument,       NULL, 'v' },
	{ "help",	no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	l_log_set_stderr();

	if (getpid() == 1 && getppid() == 0) {
		prepare_sandbox();

		run_tests();

		sync();
		l_info("Done running tests. Rebooting...");

		reboot(RB_AUTOBOOT);
		return EXIT_SUCCESS;
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "q:k:t:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'q':
			qemu_binary = optarg;
			break;
		case 'k':
			kernel_image = optarg;
			break;
		case 't':
			test_dir_list = optarg;
			break;
		case 'v':
			verbose_out = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		l_error("Invalid command line parameters");
		return EXIT_FAILURE;
	}

	own_binary = argv[0];
	test_argv = argv + optind;
	test_argc = argc - optind;

	if (!qemu_binary) {
		qemu_binary = find_qemu();
		if (!qemu_binary) {
			l_error("No default QEMU binary found");
			return EXIT_FAILURE;
		}
	}

	if (!kernel_image) {
		kernel_image = find_kernel();
		if (!kernel_image) {
			l_error("No default kernel image found");
			return EXIT_FAILURE;
		}
	}

	l_info("Using QEMU binary %s", qemu_binary);
	l_info("Using kernel image %s", kernel_image);

	start_qemu();

	return EXIT_SUCCESS;
}
