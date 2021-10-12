
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "ops.h"

static LINKED_LIST(device_linked_list);
static LINKED_LIST(interface_linked_list);

int					 stopped;
int					 debug;
static int				 signalled;
struct linked_list			*devices = &device_linked_list;
struct linked_list			*interfaces = &interface_linked_list;
static struct host_iface		 host_iface;

static int				 nsdevs = 1;
struct subsystem			 static_subsys;

void shutdown_dem(void)
{
	stopped = 1;
}

static void signal_handler(int sig_num)
{
	signalled = sig_num;

	shutdown_dem();
}

static void wait_for_signalled_shutdown(void)
{
	while (!stopped)
		usleep(100);

	if (signalled)
		printf("\n");
}

static int daemonize(void)
{
	pid_t			 pid, sid;

	pid = fork();
	if (pid < 0) {
		print_errno("fork failed", pid);
		return pid;
	}

	if (pid) /* if parent, exit to allow child to run as daemon */
		exit(0);

	umask(0022);

	sid = setsid();
	if (sid < 0) {
		print_errno("setsid failed", sid);
		return sid;
	}

	if ((chdir("/")) < 0) {
		print_err("could not change dir to /");
		return -1;
	}

	freopen("/var/log/dem_em_debug.log", "a", stdout);
	freopen("/var/log/dem_em.log", "a", stderr);

	return 0;
}

static void show_help(char *app)
{
#ifdef CONFIG_DEBUG
	const char		*arg_list = "{-q} {-d}";
#else
	const char		*arg_list = "{-d} {-S}";
#endif

	print_info("Usage: %s %s", app, arg_list);

#ifdef CONFIG_DEBUG
	print_info("  -q - quiet mode, no debug prints");
	print_info("  -d - run as a daemon process (default is standalone)");
#else
	print_info("  -d - enable debug prints in log files");
	print_info("  -S - run as a standalone process (default is daemon)");
#endif
	print_info("  In-Band (NVMe-oF) interface:");
	print_info("  -f - address family [ ipv4, ipv6 ]");
	print_info("  -a - transport address (e.g. 192.168.1.1)");
	print_info("  -s - transport service id (e.g. 4444 - not 4420 if used by NVMe-oF ctrl)");
}

static int validate_host_iface(void)
{
	int			 ret = 0;

	host_iface.ep.ops = tcp_register_ops();
	if (!host_iface.ep.ops)
		goto out;

	if (strcmp(host_iface.family, ADRFAM_STR_IPV4) == 0)
		host_iface.adrfam = NVMF_ADDR_FAMILY_IP4;
	else if (strcmp(host_iface.family, ADRFAM_STR_IPV6) == 0)
		host_iface.adrfam = NVMF_ADDR_FAMILY_IP6;

	if (!host_iface.adrfam) {
		print_info("Invalid adrfam");
		goto out;
	}

	switch (host_iface.adrfam) {
	case NVMF_ADDR_FAMILY_IP4:
		ret = inet_pton(AF_INET, host_iface.address, host_iface.addr);
		break;
	case NVMF_ADDR_FAMILY_IP6:
		ret = inet_pton(AF_INET6, host_iface.address, host_iface.addr);
		break;
	}

	if (ret < 1) {
		print_info("Invalid traddr");
		goto out;
	}

	if (host_iface.port)
		host_iface.port_num = atoi(host_iface.port);

	if (!host_iface.port_num) {
		print_info("Invalid trsvcid");
		goto out;
	}

	ret = 1;
out:
	return ret;
}

static int open_namespace(char *filename)
{
	struct nsdev *ns;

	ns = malloc(sizeof(struct nsdev));
	if (!ns) {
		errno = ENOMEM;
		return -1;
	}
	ns->fd = open(filename, O_RDWR | O_EXCL);
	if (ns->fd < 0) {
		perror("open");
		free(ns);
		return -1;
	}
	ns->nsid = nsdevs++;
	list_add(&ns->node, devices);
	return 0;
}

static void init_subsys(void)
{
	sprintf(static_subsys.nqn, NVMF_UUID_FMT,
		"62f37f51-0cc7-46d5-9865-4de22e81bd9d");
}

static void init_host_iface()
{
	strcpy(host_iface.family, "ipv4");
	strcpy(host_iface.address, "127.0.0.1");
	strcpy(host_iface.port, "4420");
}

static int init_dem(int argc, char *argv[])
{
	int			 opt;
	int			 run_as_daemon;
#ifdef CONFIG_DEBUG
	const char		*opt_list = "?qdu:r:c:t:f:a:s:n:";
#else
	const char		*opt_list = "?dSu:r:c:t:f:a:s:n:";
#endif

	if (argc > 1 && strcmp(argv[1], "--help") == 0)
		goto help;

	init_subsys();
	init_host_iface();

#ifdef CONFIG_DEBUG
	debug = 1;
	run_as_daemon = 0;
#else
	debug = 0;
	run_as_daemon = 1;
#endif

	while ((opt = getopt(argc, argv, opt_list)) != -1) {
		switch (opt) {
#ifdef CONFIG_DEBUG
		case 'q':
			debug = 0;
			break;
		case 'd':
			run_as_daemon = 1;
			break;
#else
		case 'd':
			debug = 1;
			break;
		case 'S':
			run_as_daemon = 0;
			break;
#endif
		case 'f':
			strncpy(host_iface.family, optarg,
				sizeof(host_iface.family));
			break;
		case 'a':
			strncpy(host_iface.address, optarg,
				sizeof(host_iface.address));
			break;
		case 's':
			strncpy(host_iface.port, optarg,
				sizeof(host_iface.port));
			break;
		case 'n':
			if (open_namespace(optarg) < 0)
				return 1;
			break;
		case '?':
		default:
help:
			show_help(argv[0]);
			return 1;
		}
	}

	if (optind < argc) {
		print_info("Extra arguments");
		goto help;
	}

	if (!validate_host_iface()) {
		print_err("invalid in-band address info");
		return 1;
	}

	if (run_as_daemon) {
		if (daemonize())
			return 1;
	}

	return 0;
}

static void cleanup_inb_thread(pthread_t *listen_thread)
{
	pthread_kill(*listen_thread, SIGTERM);

	/* wait for threads to cleanup before exiting so they can properly
	 * cleanup.
	 */

	usleep(100);

	/* even thought the threads are finished, need to call join
	 * otherwize, it will not release its memory and valgrind indicates
	 * a leak
	 */

	pthread_join(*listen_thread, NULL);
}

static int init_inb_thread(pthread_t *listen_thread)
{
	pthread_attr_t		 pthread_attr;
	int			 ret;

	pthread_attr_init(&pthread_attr);

	ret = pthread_create(listen_thread, &pthread_attr, interface_thread,
			     &host_iface);
	if (ret) {
		print_err("failed to start thread for Endpoint Manager");
		print_errno("pthread_create failed", ret);
	}

	pthread_attr_destroy(&pthread_attr);

	return ret;
}

void free_devices(void)
{
	struct linked_list	*p;
	struct linked_list	*n;
	struct nsdev		*dev;

	list_for_each_safe(p, n, devices) {
		list_del(p);
		dev = container_of(p, struct nsdev, node);
		if (dev->fd >= 0)
			close(dev->fd);
		free(dev);
	}
}

int main(int argc, char *argv[])
{
	pthread_t		 inb_pthread;
	int			 ret = 1;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (init_dem(argc, argv))
		goto out1;

	signalled = stopped = 0;

	if (list_empty(devices)) {
		print_info("no nvme devices found");
		goto out3;
	}

	if (init_inb_thread(&inb_pthread))
		goto out3;

	wait_for_signalled_shutdown();

	ret = 0;

	cleanup_inb_thread(&inb_pthread);

out3:
	free_devices();
out1:
	return ret;
}
