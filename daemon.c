
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "ops.h"

LINKED_LIST(subsys_linked_list);
static LINKED_LIST(device_linked_list);
static LINKED_LIST(interface_linked_list);

int					 stopped;
int					 debug;
static int				 signalled;
struct linked_list			*devices = &device_linked_list;
struct linked_list			*interfaces = &interface_linked_list;
static struct host_iface		 host_iface;

static int				 nsdevs = 1;

void shutdown_dem(void)
{
	stopped = 1;
}

static void signal_handler(int sig_num)
{
	signalled = sig_num;

	shutdown_dem();
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

static int init_subsys(void)
{
	struct subsystem *subsys;

	subsys = malloc(sizeof(*subsys));
	if (!subsys)
		return -ENOMEM;
	sprintf(subsys->nqn, "%s", NVME_DISC_SUBSYS_NAME);
	subsys->type = NVME_NQN_DISC;
	INIT_LINKED_LIST(&subsys->ctrl_list);
	list_add(&subsys->node, &subsys_linked_list);

	subsys = malloc(sizeof(*subsys));
	if (!subsys) {
		list_for_each_entry(subsys, &subsys_linked_list, node) {
			list_del(&subsys->node);
			free(subsys);
		}
		return -ENOMEM;
	}
	sprintf(subsys->nqn, NVMF_UUID_FMT,
		"62f37f51-0cc7-46d5-9865-4de22e81bd9d");
	subsys->type = NVME_NQN_NVME;
	INIT_LINKED_LIST(&subsys->ctrl_list);
	list_add(&subsys->node, &subsys_linked_list);
	return 0;
}

static void init_host_iface()
{
	host_iface.adrfam = NVMF_ADDR_FAMILY_IP4;
	strcpy(host_iface.address, "127.0.0.1");
	strcpy(host_iface.port, "8009");
}

static int init_args(int argc, char *argv[])
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

	if (init_subsys())
		return 1;
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
			if (!strcmp(optarg, "ipv4"))
				host_iface.adrfam = NVMF_ADDR_FAMILY_IP4;
			else if (!strcmp(optarg, "ipv6"))
				host_iface.adrfam = NVMF_ADDR_FAMILY_IP6;
			else {
				print_err("Invalid address family '%s'\n",
					  optarg);
				return 1;
			}
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
	int ret = 1;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = init_args(argc, argv);
	if (ret)
		return ret;

	signalled = stopped = 0;

	ret = run_host_interface(&host_iface);

	free_devices();
	return ret;
}
