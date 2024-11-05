
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
#include "inode.h"

LINKED_LIST(host_linked_list);
LINKED_LIST(subsys_linked_list);
LINKED_LIST(iface_linked_list);
LINKED_LIST(device_linked_list);

int stopped;
int debug;

static int nsdevs = 1;
static char default_nqn[] =
	"nqn.2014-08.org.nvmexpress:uuid:62f37f51-0cc7-46d5-9865-4de22e81bd9d";

struct nofuse_context *ctx;

extern int run_fuse(struct fuse_args *args);

static struct nofuse_subsys *add_subsys(const char *nqn, int type)
{
	struct nofuse_subsys *subsys;
	int inode, subsys_ino = inode_get_root("subsystems");

	subsys = malloc(sizeof(*subsys));
	if (!subsys)
		return NULL;
	memset(subsys, 0, sizeof(*subsys));
	if (!subsys->nqn)
		strcpy(subsys->nqn, default_nqn);
	else
		strcpy(subsys->nqn, nqn);
	subsys->type = type;
	if (subsys->type == NVME_NQN_CUR ||
	    !ctx->hostnqn)
		subsys->allow_any = 1;
	else
		subsys->allow_any = 0;
	inode = inode_add_subsys(subsys, subsys_ino);
	if (inode < 0) {
		free(subsys);
		return NULL;
	}
	subsys->ino = inode;

	pthread_mutex_init(&subsys->ctrl_mutex, NULL);
	INIT_LINKED_LIST(&subsys->ctrl_list);
	list_add(&subsys->node, &subsys_linked_list);

	return subsys;
}

static void del_subsys(struct nofuse_subsys *subsys)
{
	list_del(&subsys->node);
	pthread_mutex_destroy(&subsys->ctrl_mutex);
	inode_del_subsys(subsys);
	free(subsys);
}

static int open_file_ns(const char *filename)
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
	struct nofuse_subsys *subsys, *tmp_subsys;
	struct host_iface *iface;

	subsys = add_subsys(NVME_DISC_SUBSYS_NAME, NVME_NQN_CUR);
	if (!subsys)
		return -ENOMEM;

	list_for_each_entry(iface, &iface_linked_list, node) {
		printf("%s: add subsys %s port %d\n", __func__,
		       subsys->nqn, iface->port.port_id);
		inode_add_subsys_port(subsys->nqn, iface->port.port_id);
	}

	subsys = add_subsys(ctx->subsysnqn, NVME_NQN_NVM);
	if (!subsys) {
		list_for_each_entry(iface, &iface_linked_list, node)
			inode_del_subsys_port(subsys->nqn,
					      iface->port.port_id);
		list_for_each_entry_safe(subsys, tmp_subsys,
					 &subsys_linked_list, node) {
			del_subsys(subsys);
		}
		return -ENOMEM;
	}

	list_for_each_entry(iface, &iface_linked_list, node) {
		printf("%s: add subsys %s port %d\n", __func__,
		       subsys->nqn, iface->port.port_id);
		inode_add_subsys_port(subsys->nqn, iface->port.port_id);
	}

	if (ctx->hostnqn)
		inode_add_host_subsys(ctx->hostnqn, ctx->subsysnqn);

	return 0;
}

static struct host_iface *new_host_iface(const char *ifaddr,
					 int adrfam, int port)
{
	struct host_iface *iface;
	int ret;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;
	memset(iface, 0, sizeof(*iface));
	strcpy(iface->port.traddr, ifaddr);
	iface->adrfam = adrfam;
	strcpy(iface->port.trtype, "tcp");
	if (iface->adrfam == AF_INET)
		strcpy(iface->port.adrfam, "ipv4");
	else if (iface->adrfam == AF_INET6)
		strcpy(iface->port.adrfam, "ipv6");
	else {
		print_err("invalid address family %d", adrfam);
		free(iface);
		return NULL;
	}
	iface->port_num = port;
	sprintf(iface->port.trsvcid, "%d", port);
	if (port == 8009)
		iface->port_type = NVME_NQN_CUR;
	else
		iface->port_type = NVME_NQN_NVM;
	ret = inode_add_port(&iface->port, iface->port_type);
	if (ret < 0) {
		print_err("cannot add port, error %d\n", ret);
		free(iface);
		return NULL;
	}
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	print_info("iface %d: listening on %s address %s port %s",
		   iface->port.port_id,
		   iface->adrfam == AF_INET ? "ipv4" : "ipv6",
		   iface->port.traddr, iface->port.trsvcid);

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

		if (ifname) {
			if (strcmp(ifa->ifa_name, ifname))
				continue;
		} else {
			if (strcmp(ifa->ifa_name, "lo"))
				continue;
		}

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
		new = new_host_iface(iface->port.traddr, iface->adrfam, port);
		if (new) {
			list_add_tail(&new->node, &tmp_iface_list);
			iface_num++;
		}
	}

	list_splice_tail(&tmp_iface_list, &iface_linked_list);
	return iface_num;
}

#define OPTION(t, p)				\
    { t, offsetof(struct nofuse_context, p), 1 }

static const struct fuse_opt nofuse_options[] = {
	OPTION("--subsysnqn=%s", subsysnqn),
	OPTION("--hostnqn=%s", hostnqn),
	OPTION("--help", help),
	OPTION("--debug", debug),
	OPTION("--interface=%s", interface),
	OPTION("--port=%d", portnum),
	OPTION("--file=%s", filename),
	OPTION("--ramdisk=%d", ramdisk_size),
	OPTION("--dbname=%s", dbname),
	FUSE_OPT_END,
};

static void show_help(void)
{
	print_info("Usage: nofuse <args>");
	print_info("Possible values for <args>");
	print_info("  --debug - enable debug prints in log files");
	print_info("  --interface=<iface> - interface to use (default: 'lo')");
	print_info("  --port=<portnum> - port number (transport service id) (e.g. 4420)");
	print_info("  --file=<filename> - use file as namespace");
	print_info("  --ramdisk=<size> - create internal ramdisk with given size (in MB)");
	print_info("  --hostnqn=<NQN> - Host NQN of the configured host");
	print_info("  --subsysnqn=<NQN> - Subsystem NQN to use");
	print_info("  --dbname=<filename> - Database filename");
}

static int init_args(struct fuse_args *args)
{
	int tls_keyring;

	debug = ctx->debug;

	if (get_iface(ctx->interface) < 0) {
		print_err("Invalid interface %s\n",
			  ctx->interface ? ctx->interface : "lo");
		return 1;
	}

	if (ctx->portnum) {
		add_host_port(ctx->portnum);
	}
	if (ctx->hostnqn)
		inode_add_host(ctx->hostnqn);

	if (ctx->filename) {
		if (open_file_ns(ctx->filename) < 0)
			return 1;
	}
	if (ctx->ramdisk_size) {
		if (open_ram_ns(ctx->ramdisk_size) < 0)
			return 1;
	}
	if (ctx->help) {
		show_help();
		return 1;
	}

	tls_keyring = tls_global_init();

	if (init_subsys())
		return 1;

	if (list_empty(&device_linked_list)) {
		if (open_ram_ns(128) < 0) {
			print_err("Failed to create default namespace");
			return 1;
		}
	}

	if (list_empty(&iface_linked_list)) {
		print_err("invalid host interface configuration");
		return 1;
	} else if (tls_keyring) {
		struct host_iface *iface;

		list_for_each_entry(iface, &iface_linked_list, node) {
			iface->tls = true;
		}
	}

	return 0;
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
	struct nofuse_subsys *subsys, *_subsys;

	list_for_each_entry_safe(subsys, _subsys, &subsys_linked_list, node) {
		del_subsys(subsys);
	}
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct host_iface *iface;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));
	ctx->dbname = strdup("nofuse.sqlite");

	if (fuse_opt_parse(&args, ctx, nofuse_options, NULL) < 0)
		return 1;

	ret = inode_open(ctx->dbname);
	if (ret)
		return 1;

	ret = init_args(&args);
	if (ret)
		goto out_close;

	stopped = 0;

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

	run_fuse(&args);

	printf("terminating\n");
	stopped = 1;

	list_for_each_entry(iface, &iface_linked_list, node) {
		if (iface->pthread)
			pthread_kill(iface->pthread, SIGTERM);
	}

	free_interfaces();

	free_devices();

	free_subsys();
out_close:
	inode_close(ctx->dbname);

	free(ctx);

	return ret;
}
