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
static bool run_auto = true;
static bool verbose_out;
static const char *qemu_binary;
static const char *kernel_image;
static const char *exec_home;
static struct l_dbus *g_dbus;

static const char * const qemu_table[] = {
	"qemu-system-x86_64",
	"qemu-system-i386",
	"/usr/bin/qemu-system-x86_64",
	"/usr/bin/qemu-system-i386",
	NULL
};

static const char *find_qemu(void)
{
	int i;

	for (i = 0; qemu_table[i]; i++) {
		struct stat st;

		if (!stat(qemu_table[i], &st))
			return qemu_table[i];
	}

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

	for (i = 0; kernel_table[i]; i++) {
		struct stat st;

		if (!stat(kernel_table[i], &st))
			return kernel_table[i];
	}

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
			l_info("Creating %s\n", mount_table[i].target);
			mkdir(mount_table[i].target, 0755);
		}

		l_info("Mounting %s to %s\n", mount_table[i].fstype,
							mount_table[i].target);

		if (mount(mount_table[i].fstype,
				mount_table[i].target,
				mount_table[i].fstype,
				mount_table[i].flags,
				mount_table[i].options) < 0) {
			l_error("Error: Failed to mount filesystem %s\n",
							mount_table[i].target);
		}
	}

	for (i = 0; dev_table[i].target; i++) {
		l_info("Linking %s to %s\n", dev_table[i].linkpath,
							dev_table[i].target);

		if (symlink(dev_table[i].target, dev_table[i].linkpath) < 0)
			l_error("Failed to create device symlink: %s",
							strerror(errno));
	}

	l_info("Creating new session group leader");
	setsid();

	l_info("Setting controlling terminal");
	ioctl(STDIN_FILENO, TIOCSCTTY, 1);

	for (i = 0; config_table[i]; i++) {
		l_info("Creating %s", config_table[i]);

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

static void check_virtualization(void)
{
#if defined(__GNUC__) && (defined(__i386__) || defined(__amd64__))
	uint32_t ecx;

	__asm__ __volatile__("cpuid" : "=c" (ecx) : "a" (1) : "memory");

	if (!!(ecx & (1 << 5)))
		printf("Found support for Virtual Machine eXtensions\n");
#endif
}

static void start_qemu(void)
{
	char cwd[PATH_MAX], initcmd[PATH_MAX], testargs[PATH_MAX];
	char cmdline[CMDLINE_MAX];
	char **argv;
	int i, pos;

	check_virtualization();

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
			"init=%s TESTHOME=%s TESTAUTO=%u TESTVERBOUT=%u "
			"TESTARGS=\'%s\'", initcmd, cwd, run_auto, verbose_out,
			testargs);

	argv = alloca(sizeof(qemu_argv));
	memcpy(argv, qemu_argv, sizeof(qemu_argv));

	pos = (sizeof(qemu_argv) / sizeof(char *)) - 1;

	argv[0] = (char *) qemu_binary;
	argv[pos++] = "-kernel";
	argv[pos++] = (char *) kernel_image;
	argv[pos++] = "-append";
	argv[pos++] = (char *) cmdline;
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

	child_pid = fork();
	if (child_pid < 0) {
		l_error("Failed to fork new process");
		return -1;
	}

	if (child_pid == 0) {
		set_output_visibility();

		execvp(argv[0], argv);

		l_error("Failed to call execvp: %s", strerror(errno));

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
		struct stat st;

		if (!stat(socket, &st))
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
		pid = -1;
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

	if (num_radios_requested <= HW_MIN_NUM_RADIOS) {
		l_error("%s must be greater or equal to %d",
			HW_CONFIG_SETUP_NUM_RADIOS, HW_MIN_NUM_RADIOS);
		return false;
	}

	radio_conf_list =
		l_settings_get_string_list(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_RADIO_CONFS,
									':');
	if (!radio_conf_list)
		has_hw_conf = true;

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

		l_info("Created interface %s on %s", interface_name,
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
		return false;
	}

	hostap_keys =
		l_settings_get_keys(hw_settings, HW_CONFIG_GROUP_HOSTAPD);

	while (hostap_keys[i]) {
		char hostapd_config_file_path[PATH_MAX];
		const char *hostapd_config_file;
		struct stat st;
		char *interface_name;

		hostapd_config_file =
			l_settings_get_value(hw_settings,
						HW_CONFIG_GROUP_HOSTAPD,
						hostap_keys[i]);

		snprintf(hostapd_config_file_path, PATH_MAX - 1, "%s/%s",
				config_dir_path,
				hostapd_config_file);

		hostapd_config_file_path[PATH_MAX - 1] = '\0';

		if (stat(hostapd_config_file_path, &st) != 0) {
			l_error("%s : hostapd configuration file [%s] "
				"does not exist.", HW_CONFIG_FILE_NAME,
						hostapd_config_file_path);
			return false;
		}

		interface_name = interface_names_in[i];

		hostapd_pids_out[i] = start_hostapd(hostapd_config_file_path,
								interface_name);
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
#define CONSOLE_LN_RESET	"\033[0m"

#define CONSOLE_LN_BOLD		"\x1b[1m"

#define CONSOLE_BG_WHITE	"\e[47m"
#define CONSOLE_BG_DEFAULT	"\e[0m"

enum test_status {
	TEST_STATUS_STARTED,
	TEST_STATUS_PASSED,
	TEST_STATUS_FAILED,
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
		status_str = "STARTED ";

		if (verbose_out)
			line_end = "\n";

		break;
	case TEST_STATUS_PASSED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_GREEN;
		status_str = "PASSED  ";
		line_end = "\n";

		break;
	case TEST_STATUS_FAILED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_RED;
		status_str = "FAILED  ";
		line_end = "\n";

		break;
	}

	if (interval > 0)
		int_len = snprintf(NULL, 0, "%.3f", interval);
	else
		int_len = 0;

	int_len++;

	interval_str = l_malloc(int_len);
	memset(interval_str, ' ', int_len);
	interval_str[int_len] = '\0';

	if (interval > 0)
		sprintf(interval_str, "%.3f sec", interval);

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

static void signal_handler(struct l_signal *signal, uint32_t signo,
								void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static pid_t start_execution_timeout_timer(pid_t *test_exec_pid)
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

		signal = l_signal_create(&mask, signal_handler,
							test_exec_pid, NULL);
		test_exec_timeout =
			l_timeout_create(TEST_MAX_EXEC_TIME_SEC,
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

static void run_py_tests(char *config_dir_path, struct l_queue *test_queue)
{
	char *argv[3];
	pid_t test_exec_pid, test_timer_pid;
	struct timeval time_before, time_after, time_elapsed;
	char *py_test = NULL;

	if (!config_dir_path)
		return;

	if (chdir(config_dir_path) < 0)
		l_error("Failed to change directory");
	else {
		printf(CONSOLE_LN_BOLD CONSOLE_LN_BLACK
			CONSOLE_BG_WHITE "Running tests in %-63s"
			CONSOLE_LN_RESET CONSOLE_BG_DEFAULT
			"\n", config_dir_path);
	}

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

	test_timer_pid = start_execution_timeout_timer(&test_exec_pid);

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
					WEXITSTATUS(status) == EXIT_SUCCESS)
				print_test_status(py_test, TEST_STATUS_PASSED,
							interval);
			else
				print_test_status(py_test, TEST_STATUS_FAILED,
								interval);
		} else if (WIFSTOPPED(status))
			l_info("Process %d stopped with signal %d", corpse,
			       WSTOPSIG(status));
		else if (WIFCONTINUED(status))
			l_info("Process %d continued", corpse);

		if (corpse == test_exec_pid)
			break;
	}

	l_free(py_test);
	py_test = NULL;

	goto start_next_test;
}

static void create_network_and_run_tests(const void *key, void *value,
						void *config_cycle_count)
{
	int hwsim_radio_ids[HWSIM_RADIOS_MAX];
	char *interface_names[HWSIM_RADIOS_MAX];
	pid_t hostapd_pids[HWSIM_RADIOS_MAX];
	pid_t iwd_pid;
	char *config_dir_path;
	struct l_settings *hw_settings;
	struct l_queue *test_queue;

	l_info("Starting configuration cycle No: %d",
						++(*(int *)config_cycle_count));

	if (!key || !value)
		return;

	memset(hwsim_radio_ids, -1, sizeof(hwsim_radio_ids));
	memset(hostapd_pids, -1, sizeof(hostapd_pids));

	config_dir_path = (char *) key;
	test_queue = (struct l_queue *) value;

	if (l_queue_isempty(test_queue)) {
		l_error("No Python IWD tests have been found in %s",
							config_dir_path);
		return;
	}

	hw_settings = read_hw_config(config_dir_path);
	if (!hw_settings)
		return;

	configure_hw_radios(hw_settings, hwsim_radio_ids, interface_names);

	list_hwsim_radios();

	list_interfaces();

	configure_hostapd_instances(hw_settings, config_dir_path,
							interface_names,
								hostapd_pids);

	iwd_pid = start_iwd();
	if (iwd_pid == -1)
		goto exit;

	/*TODO wait for iwd to obtain phyX - replace with dbus call*/
	sleep(2);

	run_py_tests(config_dir_path, test_queue);

	terminate_iwd(iwd_pid);

	destroy_hostapd_instances(hostapd_pids);

	destroy_hw_radios(hwsim_radio_ids, interface_names);

exit:
	l_settings_free(hw_settings);
}

static void run_command(char *cmdname)
{
	char tmp_path[PATH_MAX];
	char test_home_path[PATH_MAX];
	char *ptr;
	pid_t dbus_pid;
	int index, config_cycle_count, level;
	struct l_hashmap *test_config_map;
	struct stat st;

	ptr = strrchr(exec_home, '/');
	if (!ptr)
		exit(EXIT_FAILURE);

	index = ptr - exec_home;

	strncpy(tmp_path, exec_home + 5, index - 5);
	tmp_path[index - 5] = '\0';

	sprintf(test_home_path, "%s/%s", tmp_path, TEST_TOP_DIR_DEFAULT_NAME);

	if (stat(test_home_path, &st) == -1) {
		l_error("Test directory %s does not exist",
			test_home_path);

		return;
	}

	test_config_map = l_hashmap_string_new();
	if (!test_config_map)
		return;

	if (run_auto)
		level = 0;
	else
		level = 1;

	l_info("Configuring network...");

	if (!find_test_configuration(test_home_path, level, test_config_map))
		goto exit;

	if (l_hashmap_isempty(test_config_map)) {
		l_error("No test configuration is found in %s.",
								test_home_path);
		goto exit;
	}

	create_dbus_system_conf();

	dbus_pid = start_dbus_daemon();
	if (dbus_pid < 0)
		goto exit;

	g_dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!g_dbus) {
		l_error("Error: cannot initialize system bus");
		goto exit;
	}

	config_cycle_count = 0;

	l_hashmap_foreach(test_config_map, create_network_and_run_tests,
							&config_cycle_count);

	l_dbus_destroy(g_dbus);

exit:
	l_hashmap_destroy(test_config_map, NULL);
}

static void run_tests(void)
{
	char cmdline[CMDLINE_MAX], *ptr, *cmds;
	FILE *fp;

	l_log_set_stderr();

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

	ptr = strstr(cmdline, "TESTAUTO=1");
	if (ptr) {
		l_info("Automatic test execution requested");
		run_auto = true;
	}

	ptr = strstr(cmdline, "TESTVERBOUT=1");
	if (ptr) {
		l_info("Enable verbose output");
		verbose_out = true;
	}

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
	printf("testrunner - Automated test execution utility\n"
		"Usage:\n");
	printf("\ttest-runner [options] [--] <command> [args]\n");
	printf("Options:\n"
		"\t-a, --auto             Find tests and run them\n"
		"\t-q, --qemu <path>      QEMU binary\n"
		"\t-k, --kernel <image>   Kernel image (bzImage)\n"
		"\t-v, --verbose          Enable verbose output\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "all",     no_argument,       NULL, 'a' },
	{ "auto",    no_argument,       NULL, 'a' },
	{ "qemu",    required_argument, NULL, 'q' },
	{ "kernel",  required_argument, NULL, 'k' },
	{ "verbose", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	if (getpid() == 1 && getppid() == 0) {
		prepare_sandbox();

		run_tests();

		sync();
		printf("Done running test. Rebooting...");

		reboot(RB_AUTOBOOT);
		return EXIT_SUCCESS;
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "aq:k:t:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'q':
			qemu_binary = optarg;
			break;
		case 'k':
			kernel_image = optarg;
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

	if (run_auto) {
		if (argc - optind > 0) {
			fprintf(stderr, "Invalid command line parameters\n");
			return EXIT_FAILURE;
		}
	} else {
		if (argc - optind < 1) {
			fprintf(stderr, "Failed to specify test command\n");
			return EXIT_FAILURE;
		}
	}

	own_binary = argv[0];
	test_argv = argv + optind;
	test_argc = argc - optind;

	if (!qemu_binary) {
		qemu_binary = find_qemu();
		if (!qemu_binary) {
			fprintf(stderr, "No default QEMU binary found\n");
			return EXIT_FAILURE;
		}
	}

	if (!kernel_image) {
		kernel_image = find_kernel();
		if (!kernel_image) {
			fprintf(stderr, "No default kernel image found\n");
			return EXIT_FAILURE;
		}
	}

	printf("Using QEMU binary %s\n", qemu_binary);
	printf("Using kernel image %s\n", kernel_image);

	start_qemu();

	return EXIT_SUCCESS;
}
