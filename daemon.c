
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <getopt.h>

#define FUSE_USE_VERSION 31
#include <fuse.h>

#include "common.h"
#include "ops.h"
#include "tls.h"

LINKED_LIST(host_linked_list);
LINKED_LIST(subsys_linked_list);
LINKED_LIST(iface_linked_list);
LINKED_LIST(device_linked_list);

char *hostnqn;
char *subsysnqn;
int stopped;
int debug;
static int signalled;

static int nsdevs = 1;
static int nvmf_portid = 1;

static void signal_handler(int sig_num)
{
	signalled = sig_num;
	stopped = 1;
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

	freopen("/var/log/nofuse_debug.log", "a", stdout);
	freopen("/var/log/nofuse.log", "a", stderr);

	return 0;
}

static int open_file_ns(char *filename)
{
	struct nsdev *ns;
	struct stat st;

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
	if (fstat(ns->fd, &st) < 0) {
		perror("fstat");
		close(ns->fd);
		free(ns);
		return -1;
	}
	ns->size = st.st_size;
	ns->blksize = st.st_blksize;
	ns->ops = uring_register_ops();

	ns->nsid = nsdevs++;
	uuid_generate(ns->uuid);
	list_add_tail(&ns->node, &device_linked_list);
	return 0;
}

static int open_ram_ns(size_t size)
{
	struct nsdev *ns;

	ns = malloc(sizeof(struct nsdev));
	if (!ns) {
		errno = ENOMEM;
		return -1;
	}
	ns->size = size * 1024 * 1024; /* size in MB */
	ns->blksize = 4096;
	ns->fd = -1;
	ns->ops = null_register_ops();

	ns->nsid = nsdevs++;
	uuid_generate(ns->uuid);
	list_add_tail(&ns->node, &device_linked_list);
	return 0;
}

static int init_subsys(void)
{
	struct subsystem *subsys;

	subsys = malloc(sizeof(*subsys));
	if (!subsys)
		return -ENOMEM;
	sprintf(subsys->nqn, "%s", NVME_DISC_SUBSYS_NAME);
	subsys->type = NVME_NQN_CUR;
	pthread_mutex_init(&subsys->ctrl_mutex, NULL);
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
	if (subsysnqn)
		sprintf(subsys->nqn, "%s", subsysnqn);
	else
		sprintf(subsys->nqn, NVMF_UUID_FMT,
			"62f37f51-0cc7-46d5-9865-4de22e81bd9d");
	print_info("Using subsysten NQN %s", subsys->nqn);
	subsys->type = NVME_NQN_NVM;
	INIT_LINKED_LIST(&subsys->ctrl_list);
	pthread_mutex_init(&subsys->ctrl_mutex, NULL);
	list_add(&subsys->node, &subsys_linked_list);
	return 0;
}

static struct host_iface *new_host_iface(const char *ifaddr,
					 int adrfam, int port)
{
	struct host_iface *iface;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;
	memset(iface, 0, sizeof(*iface));
	strcpy(iface->address, ifaddr);
	iface->adrfam = adrfam;
	if (iface->adrfam != AF_INET && iface->adrfam != AF_INET6) {
		print_err("invalid address family %d", adrfam);
		free(iface);
		return NULL;
	}
	iface->portid = nvmf_portid++;
	iface->port_num = port;
	if (port == 8009)
		iface->port_type = (1 << NVME_NQN_CUR);
	else
		iface->port_type = (1 << NVME_NQN_NVM);
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	print_info("iface %d: listening on %s address %s port %d",
		   iface->portid,
		   iface->adrfam == AF_INET ? "ipv4" : "ipv6",
		   iface->address, iface->port_num);

	return iface;
}

static int get_iface(const char *ifname)
{
	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) == -1) {
		perror("getifaddrs");
		return -1;
	}


	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		char host[NI_MAXHOST];
		struct host_iface *iface;
		int ret, addrlen;

		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, ifname))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
			addrlen = sizeof(struct sockaddr_in);
		else if (ifa->ifa_addr->sa_family == AF_INET6)
			addrlen = sizeof(struct sockaddr_in6);
		else
			continue;

		ret = getnameinfo(ifa->ifa_addr, addrlen,
				  host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (ret) {
			print_err("getnameinfo failed, error %d", ret);
			continue;
		}
		iface = new_host_iface(host, ifa->ifa_addr->sa_family, 8009);
		if (iface)
			list_add_tail(&iface->node, &iface_linked_list);
        }
	freeifaddrs(ifaddrs);
	return 0;
}

static int add_host_port(int port)
{
	int iface_num = 0;
	LINKED_LIST(tmp_iface_list);
	struct host_iface *iface, *new;

	list_for_each_entry(iface, &iface_linked_list, node) {
		if (iface->port_num == port)
			continue;
		if (iface->port_num != 8009)
			continue;
		new = new_host_iface(iface->address, iface->adrfam, port);
		if (new) {
			list_add_tail(&new->node, &tmp_iface_list);
			iface_num++;
		}
	}

	list_splice_tail(&tmp_iface_list, &iface_linked_list);
	return iface_num;
}

static const struct option nofuse_options[] = {
	{ "subsysnqn", required_argument, 0, 0 },
	{ "hostnqn", required_argument, 0, 0 },
	{ "help", no_argument, 0, 'h' },
	{ "debug", no_argument, 0, 'd' },
	{ "standalone", no_argument, 0, 0 },
	{ "interface", required_argument, 0, 0},
	{ "port", required_argument, 0, 0},
	{ "file", required_argument, 0, 0},
	{ "ramdisk", required_argument, 0, 0},
	{ NULL, 0, 0, 0 },
};

static void show_help(char *app)
{
	print_info("Usage: %s <args>", app);
	print_info("Possible values for <args>");
	print_info("  --debug - enable debug prints in log files");
	print_info("  --standalone - run as a standalone process (default is daemon)");
	print_info("  --interface=<iface> - interface to use (default: 'lo')");
	print_info("  --port=<portnum> - port number (transport service id) (e.g. 4420)");
	print_info("  --file=<filename> - use file as namespace");
	print_info("  --ramdisk=<size> - create internal ramdisk with given size (in MB)");
	print_info("  --hostnqn=<NQN> - Host NQN of the configured host");
	print_info("  --subsysnqn=<NQN> - Subsystem NQN to use");
}

static int init_args(int argc, char *argv[], struct fuse_args *fuse_opts)
{
	int opt;
	int run_as_daemon;
	char *eptr;
	const char *opt_list = "s:n:hdSi:t:f:r";
	unsigned long size;
	int port_num[16];
	int port_max = 0, port, idx;
	int iface_num = 0, tls_keyring;
	char **fuse_argv;
	int fuse_argc = 0;
	int option_index;

	hostnqn = NULL;
	debug = 0;
	run_as_daemon = 1;

	fuse_argv = malloc(sizeof(char *) * argc);
	memset(fuse_argv, 0, sizeof(char *) * argc);

	while ((opt = getopt_long(argc, argv, opt_list,
				  nofuse_options, &option_index)) != -1) {
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 'S':
			run_as_daemon = 0;
			break;
		case 's':
			if (strncmp(optarg, "nqn.", 4)) {
				print_err("Invalid Subsystem NQN %s\n",
					  optarg);
				goto out_free;
			}
			subsysnqn = optarg;
			break;
		case 'i':
			if (get_iface(optarg) < 0) {
				print_err("Invalid interface %s\n",
					  optarg);
				goto out_free;
			}
			iface_num++;
			break;
		case 'p':
			errno = 0;
			if (port_max >= 16) {
				print_err("Too many port numbers specified");
				goto out_free;
			}
			port = strtoul(optarg, &eptr, 10);
			if (errno || port == 0 || port > LONG_MAX) {
				print_err("Invalid port number '%s'",
					  optarg);
				goto out_free;
			}
			for (idx = 0; idx < port_max; idx++) {
				if (port_num[idx] == port) {
					port = -1;
					break;
				}
			}
			if (port > 0) {
				port_num[idx] = port;
				port_max++;
			}
			break;
		case 'f':
			if (open_file_ns(optarg) < 0)
				goto out_free;
			break;
		case 'r':
			size = strtoul(optarg, &eptr, 10);
			if (errno || size == 0 || size > LONG_MAX) {
				print_err("Invalid size '%s'",
					  optarg);
				goto out_free;
			}
			if (open_ram_ns(size) < 0)
				goto out_free;
			break;
		case 'n':
			hostnqn = optarg;
			break;
		case '?':
		case 'h':
			show_help(argv[0]);
			goto out_free;
		default:
			fuse_argv[fuse_argc++] = argv[optind];
			break;
		}
	}

	tls_keyring = tls_global_init();

	fuse_opts->argc = fuse_argc;
	fuse_opts->argv = fuse_argv;
	fuse_opts->allocated = 0;

	if (init_subsys())
		goto out_free;

	if (list_empty(&device_linked_list)) {
		if (open_ram_ns(128) < 0) {
			print_err("Failed to create default namespace");
			goto out_free;
		}
	}

	if (list_empty(&iface_linked_list)) {
		if (get_iface("lo") < 0) {
			print_err("Failed to initialize iface 'lo'");
			goto out_free;
		}
		iface_num++;
	}

	if (!port_max) {
		struct host_iface *iface;

		/* No port specified; use 8009 as I/O port, too */
		list_for_each_entry(iface, &iface_linked_list, node) {
			iface->port_type |= (1 << NVME_NQN_NVM);
		}
	}
	for (idx = 0; idx < port_max; idx++)
		add_host_port(port_num[idx]);

	if (list_empty(&iface_linked_list)) {
		print_err("invalid host interface configuration");
		goto out_free;
	} else if (tls_keyring) {
		struct host_iface *iface;

		list_for_each_entry(iface, &iface_linked_list, node) {
			iface->tls = true;
		}
	}

	if (run_as_daemon) {
		if (daemonize())
			goto out_free;
	}

	return 0;
out_free:
	free(fuse_argv);
	return 1;
}

void free_devices(void)
{
	struct linked_list *p;
	struct linked_list *n;
	struct nsdev *dev;

	list_for_each_safe(p, n, &device_linked_list) {
		list_del(p);
		dev = container_of(p, struct nsdev, node);
		if (dev->fd >= 0)
			close(dev->fd);
		free(dev);
	}
}

void free_interfaces(void)
{
	struct host_iface *iface, *_iface;

	list_for_each_entry_safe(iface, _iface, &iface_linked_list, node) {
		if (iface->pthread)
			pthread_join(iface->pthread, NULL);
		pthread_mutex_destroy(&iface->ep_mutex);
		list_del(&iface->node);
		free(iface);
	}
}

void free_subsys(void)
{
	struct subsystem *subsys, *_subsys;

	list_for_each_entry_safe(subsys, _subsys, &subsys_linked_list, node) {
		pthread_mutex_destroy(&subsys->ctrl_mutex);
		free(subsys);
	}
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct host_iface *iface;
	struct fuse_args fuse_argv;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = init_args(argc, argv, &fuse_argv);
	if (ret)
		return ret;

	signalled = stopped = 0;

	list_for_each_entry(iface, &iface_linked_list, node) {
		pthread_attr_t pthread_attr;

		pthread_attr_init(&pthread_attr);

		ret = pthread_create(&iface->pthread, &pthread_attr,
				     run_host_interface, iface);
		if (ret) {
			iface->pthread = 0;
			print_err("failed to start iface thread");
			print_errno("pthread_create failed", ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	run_fuse(fuse_argv.argc, fuse_argv.argv);

	free(fuse_argv.argv);

	free_interfaces();

	free_devices();

	free_subsys();

	return ret;
}
