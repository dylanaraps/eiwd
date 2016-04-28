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
#include <ell/ell.h>

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#define CMDLINE_MAX			2048

#define BIN_IW				"/usr/sbin/iw"
#define BIN_HWSIM			"./hwsim"

#define HWSIM_RADIOS_MAX		100

static const char *own_binary;
static char **test_argv;
static int test_argc;

static bool start_dbus;
static bool run_auto;
static bool verbose_out;
static const char *qemu_binary;
static const char *kernel_image;
static const char *exec_home;

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
	{ "devtmpfs", "/dev",     "mode=0755", MS_NOSUID|MS_STRICTATIME },
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
	"/etc/dbus-1",
	"/usr/share/dbus-1",
	NULL
};

static void prepare_sandbox(void)
{
	int i;

	for (i = 0; mount_table[i].fstype; i++) {
		struct stat st;

		if (lstat(mount_table[i].target, &st) < 0) {
			printf("Creating %s\n", mount_table[i].target);
			mkdir(mount_table[i].target, 0755);
		}

		printf("Mounting %s to %s\n", mount_table[i].fstype,
						mount_table[i].target);

		if (mount(mount_table[i].fstype,
				mount_table[i].target,
				mount_table[i].fstype,
				mount_table[i].flags,
				mount_table[i].options) < 0)
			perror("Failed to mount filesystem");
	}

	for (i = 0; dev_table[i].target; i++) {
		printf("Linking %s to %s\n", dev_table[i].linkpath,
						dev_table[i].target);

		if (symlink(dev_table[i].target, dev_table[i].linkpath) < 0)
			perror("Failed to create device symlink");
	}

	printf("Creating new session group leader\n");
	setsid();

	printf("Setting controlling terminal\n");
	ioctl(STDIN_FILENO, TIOCSCTTY, 1);

	for (i = 0; config_table[i]; i++) {
		printf("Creating %s\n", config_table[i]);

		if (mount("tmpfs", config_table[i], "tmpfs",
				MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
				"mode=0755") < 0)
			perror("Failed to create filesystem");
	}
}

static const char * const qemu_argv[] = {
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
		int len = sizeof(testargs) - pos;

		pos += snprintf(testargs + pos, len, " %s", test_argv[i]);
	}

	snprintf(cmdline, sizeof(cmdline),
				"console=ttyS0,115200n8 earlyprintk=serial "
				"rootfstype=9p "
				"rootflags=trans=virtio,version=9p2000.L "
				"acpi=off pci=noacpi noapic quiet ro init=%s "
				"TESTHOME=%s TESTDBUS=%u "
				"TESTAUTO=%u TESTARGS=\'%s\'", initcmd, cwd,
				start_dbus, run_auto, testargs);

	argv = alloca(sizeof(qemu_argv));
	memcpy(argv, qemu_argv, sizeof(qemu_argv));

	pos = (sizeof(qemu_argv) / sizeof(char *)) - 1;

	argv[0] = (char *) qemu_binary;

	argv[pos++] = "-kernel";
	argv[pos++] = (char *) kernel_image;
	argv[pos++] = "-append";
	argv[pos++] = (char *) cmdline;

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

		l_error("Failed to call execvp: %s\n", strerror(errno));

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

	kill(pid, SIGKILL);

	do {
		waitpid(pid, &status, 0);
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	l_info("Process terminated: %d\n", pid);
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

	l_error("Error: cannot find socket: %s\n", socket);
	return false;
}

static void create_dbus_system_conf(void)
{
	FILE *fp;

	fp = fopen("/etc/dbus-1/system.conf", "we");
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
	char *argv[3], *envp[1];
	pid_t pid;
	int i;

	argv[0] = "/usr/bin/dbus-daemon";
	argv[1] = "--system";
	argv[2] = NULL;

	envp[0] = NULL;

	printf("Starting D-Bus daemon\n");

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		return -1;
	}

	if (pid == 0) {
		execve(argv[0], argv, envp);
		exit(EXIT_SUCCESS);
	}

	printf("D-Bus daemon process %d created\n", pid);

	for (i = 0; i < 20; i++) {
		struct stat st;

		if (!stat("/run/dbus/system_bus_socket", &st)) {
			printf("Found D-Bus daemon socket\n");
			break;
		}

		usleep(25 * 1000);
	}

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

		l_info("hostapd instance with pid=%d is destroyed\n",
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
		l_error("Test directory does not exist: %s\n", path);
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
		l_error("No %s file found\n", HW_CONFIG_FILE_NAME);
		goto error_exit;
	}

	if (!l_settings_has_group(hw_settings, HW_CONFIG_GROUP_SETUP)) {
		l_error("No %s setting group found in %s\n",
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
		l_error("%s must be greater or equal to %d\n",
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
					"config. file.\n", radio_config_group);

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

		l_info("Created interface %s on %s\n", interface_name,
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
		l_info("Removed interface %s\n", interface_names_in[i]);

		interface_names_in[i] = NULL;

		i++;
	}

	i = 0;

	while (hwsim_radio_ids[i] != -1) {
		destroy_hwsim_radio(hwsim_radio_ids[i]);
		l_info("Removed radio id %d\n", hwsim_radio_ids[i]);

		hwsim_radio_ids[i] = -1;

		i++;
	}
}

static const char * const daemon_table[] = {
	NULL
};

static pid_t start_bluetooth_daemon(const char *home)
{
	const char *daemon = NULL;
	char *argv[3], *envp[2];
	pid_t pid;
	int i;

	if (chdir(home + 5) < 0) {
		perror("Failed to change home directory for daemon");
		return -1;
	}

	for (i = 0; daemon_table[i]; i++) {
		struct stat st;

		if (!stat(daemon_table[i], &st)) {
			daemon = daemon_table[i];
			break;
		}
	}

	if (!daemon) {
		fprintf(stderr, "Failed to locate Bluetooth daemon binary\n");
		return -1;
	}

	printf("Using Bluetooth daemon %s\n", daemon);

	argv[0] = (char *) daemon;
	argv[1] = "--nodetach";
	argv[2] = NULL;

	envp[0] =
		"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket";
	envp[1] = NULL;

	printf("Starting Bluetooth daemon\n");

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		return -1;
	}

	if (pid == 0) {
		execve(argv[0], argv, envp);
		exit(EXIT_SUCCESS);
	}

	printf("Bluetooth daemon process %d created\n", pid);

	return pid;
}

static const char * const test_table[] = {
	NULL
};

static void run_command(char *cmdname, char *home)
{
	char *argv[9], *envp[3];
	int pos = 0, idx = 0;
	pid_t pid, dbus_pid, daemon_pid;

	if (start_dbus) {
		create_dbus_system_conf();
		dbus_pid = start_dbus_daemon();
		daemon_pid = start_bluetooth_daemon(home);
	} else {
		dbus_pid = -1;
		daemon_pid = -1;
	}

start_next:
	if (run_auto) {
		if (chdir(home + 5) < 0) {
			perror("Failed to change home test directory");
			return;
		}

		while (1) {
			struct stat st;

			if (!test_table[idx])
				return;

			if (!stat(test_table[idx], &st))
				break;

			idx++;
		}

		argv[0] = (char *) test_table[idx];
		argv[1] = "-q";
		argv[2] = NULL;
	} else {
		while (1) {
			char *ptr;

			ptr = strchr(cmdname, ' ');
			if (!ptr) {
				argv[pos++] = cmdname;
				break;
			}

			*ptr = '\0';
			argv[pos++] = cmdname;
			if (pos > 8)
				break;

			cmdname = ptr + 1;
		}

		argv[pos] = NULL;
	}

	pos = 0;
	envp[pos++] = "TERM=linux";
	if (home)
		envp[pos++] = home;
	envp[pos] = NULL;

	printf("Running command %s\n", argv[0]);

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		return;
	}

	if (pid == 0) {
		if (home) {
			printf("Changing into directory %s\n", home + 5);
			if (chdir(home + 5) < 0)
				perror("Failed to change directory");
		}

		execve(argv[0], argv, envp);
		exit(EXIT_SUCCESS);
	}

	printf("New process %d created\n", pid);

	while (1)  {
		pid_t corpse;
		int status;

		corpse = waitpid(WAIT_ANY, &status, 0);
		if (corpse < 0 || corpse == 0)
			continue;

		if (WIFEXITED(status))
			printf("Process %d exited with status %d\n",
						corpse, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			printf("Process %d terminated with signal %d\n",
						corpse, WTERMSIG(status));
		else if (WIFSTOPPED(status))
			printf("Process %d stopped with signal %d\n",
						corpse, WSTOPSIG(status));
		else if (WIFCONTINUED(status))
			printf("Process %d continued\n", corpse);

		if (corpse == dbus_pid) {
			printf("D-Bus daemon terminated\n");
			dbus_pid = -1;
		}

		if (corpse == daemon_pid) {
			printf("Bluetooth daemon terminated\n");
			daemon_pid = -1;
		}

		if (corpse == pid) {
			if (!run_auto) {
				if (daemon_pid > 0)
					kill(daemon_pid, SIGTERM);
				if (dbus_pid > 0)
					kill(dbus_pid, SIGTERM);
			}
			break;
		}
	}

	if (run_auto) {
		idx++;
		goto start_next;
	}
}

static void run_tests(void)
{
	char cmdline[CMDLINE_MAX], *ptr, *cmds, *home = NULL;
	FILE *fp;

	fp = fopen("/proc/cmdline", "re");
	if (!fp) {
		fprintf(stderr, "Failed to open kernel command line\n");
		return;
	}

	ptr = fgets(cmdline, sizeof(cmdline), fp);
	fclose(fp);

	if (!ptr) {
		fprintf(stderr, "Failed to read kernel command line\n");
		return;
	}

	ptr = strstr(cmdline, "TESTARGS=");
	if (!ptr) {
		fprintf(stderr, "No test command section found\n");
		return;
	}

	cmds = ptr + 10;
	ptr = strchr(cmds, '\'');
	if (!ptr) {
		fprintf(stderr, "Malformed test command section\n");
		return;
	}

	*ptr = '\0';

	ptr = strstr(cmdline, "TESTAUTO=1");
	if (ptr) {
		printf("Automatic test execution requested\n");
		run_auto = true;
	}

	ptr = strstr(cmdline, "TESTDBUS=1");
	if (ptr) {
		printf("D-Bus daemon requested\n");
		start_dbus = true;
	}

	ptr = strstr(cmdline, "TESTHOME=");
	if (ptr) {
		home = ptr + 4;
		ptr = strpbrk(home + 9, " \r\n");
		if (ptr)
			*ptr = '\0';
	}

	run_command(cmds, home);
}

static void usage(void)
{
	printf("test-runner - Automated test execution utility\n"
		"Usage:\n");
	printf("\ttest-runner [options] [--] <command> [args]\n");
	printf("Options:\n"
		"\t-a, --auto             Find tests and run them\n"
		"\t-d, --dbus             Start D-Bus daemon\n"
		"\t-q, --qemu <path>      QEMU binary\n"
		"\t-k, --kernel <image>   Kernel image (bzImage)\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "all",     no_argument,       NULL, 'a' },
	{ "auto",    no_argument,       NULL, 'a' },
	{ "unix",    no_argument,       NULL, 'u' },
	{ "dbus",    no_argument,       NULL, 'd' },
	{ "qemu",    required_argument, NULL, 'q' },
	{ "kernel",  required_argument, NULL, 'k' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	if (getpid() == 1 && getppid() == 0) {
		prepare_sandbox();
		run_tests();

		sync();
		reboot(RB_AUTOBOOT);
		return EXIT_SUCCESS;
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "audq:k:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'a':
			run_auto = true;
			break;
		case 'd':
			start_dbus = true;
			break;
		case 'q':
			qemu_binary = optarg;
			break;
		case 'k':
			kernel_image = optarg;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
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
