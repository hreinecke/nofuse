
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

LINKED_LIST(subsys_linked_list);
LINKED_LIST(iface_linked_list);
LINKED_LIST(device_linked_list);

int stopped;
int debug;
int tcp_debug;
int cmd_debug;

static char default_nqn[] =
	"nqn.2014-08.org.nvmexpress:uuid:62f37f51-0cc7-46d5-9865-4de22e81bd9d";

struct nofuse_context *ctx;

extern int run_fuse(struct fuse_args *args);

struct nofuse_subsys *add_subsys(const char *nqn, int type)
{
	struct nofuse_subsys *subsys;
	int ret;

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
	ret = inode_add_subsys(subsys);
	if (ret < 0) {
		free(subsys);
		return NULL;
	}

	pthread_mutex_init(&subsys->ctrl_mutex, NULL);
	INIT_LINKED_LIST(&subsys->ctrl_list);
	list_add(&subsys->node, &subsys_linked_list);

	return subsys;
}

static int del_subsys(struct nofuse_subsys *subsys)
{
	int ret;

	list_del(&subsys->node);
	pthread_mutex_destroy(&subsys->ctrl_mutex);
	ret = inode_del_subsys(subsys);
	if (ret == 0)
		free(subsys);
	return ret;
}

struct nofuse_subsys *find_subsys(const char *subsysnqn)
{
	struct nofuse_subsys *subsys = NULL;

	list_for_each_entry(subsys, &subsys_linked_list, node) {
		if (!strcmp(subsys->nqn, subsysnqn))
			return subsys;
	}
	return NULL;
}

static int open_file_ns(struct nofuse_subsys *subsys, const char *filename)
{
	struct nofuse_namespace *ns;
	struct stat st;
	int ret;

	ns = malloc(sizeof(*ns));
	if (!ns) {
		errno = ENOMEM;
		return -1;
	}
	memset(ns, 0, sizeof(*ns));

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

	ns->subsys = subsys;
	ns->nsid = ++subsys->max_namespaces;
	ret = inode_add_namespace(subsys->nqn, ns);
	if (ret < 0) {
		subsys->max_namespaces--;
		close(ns->fd);
		free(ns);
		return ret;
	}
	inode_set_namespace_attr(subsys->nqn, ns->nsid,
				 "device_path", filename);
	list_add_tail(&ns->node, &device_linked_list);
	return 0;
}

int open_ram_ns(struct nofuse_subsys *subsys, int nsid, size_t size)
{
	struct nofuse_namespace *ns;
	int ret;

	ns = malloc(sizeof(*ns));
	if (!ns) {
		errno = ENOMEM;
		return -1;
	}
	memset(ns, 0, sizeof(*ns));
	ns->size = size * 1024 * 1024; /* size in MB */
	ns->blksize = 4096;
	ns->fd = -1;
	ns->ops = null_register_ops();
	ns->subsys = subsys;
	ns->nsid = nsid;
	ret = inode_add_namespace(subsys->nqn, ns);
	if (ret < 0) {
		subsys->max_namespaces--;
		free(ns);
		return ret;
	}
	inode_set_namespace_attr(subsys->nqn, ns->nsid,
				 "device_path", "/dev/null");
	list_add_tail(&ns->node, &device_linked_list);
	return 0;
}

static int init_subsys(void)
{
	struct nofuse_subsys *subsys, *tmp_subsys;
	struct host_iface *iface;
	int ret;

	subsys = add_subsys(NVME_DISC_SUBSYS_NAME, NVME_NQN_CUR);
	if (!subsys)
		return -ENOMEM;

	list_for_each_entry(iface, &iface_linked_list, node) {
		inode_add_subsys_port(subsys->nqn, iface->port.port_id);
	}
	if (!ctx->subsysnqn)
		return 0;

	subsys = add_subsys(ctx->subsysnqn, NVME_NQN_NVM);
	if (!subsys) {
		ret = -ENOMEM;

		list_for_each_entry(iface, &iface_linked_list, node) {
			ret = inode_del_subsys_port(subsys->nqn,
						    iface->port.port_id);
			if (ret < 0)
				break;
		}
		if (ret)
			return ret;
		list_for_each_entry_safe(subsys, tmp_subsys,
					 &subsys_linked_list, node) {
			ret = del_subsys(subsys);
			if (ret < 0)
				break;
		}
		return ret;
	}

	list_for_each_entry(iface, &iface_linked_list, node) {
		inode_add_subsys_port(subsys->nqn, iface->port.port_id);
	}

	if (ctx->filename)
		open_file_ns(subsys, ctx->filename);
	if (ctx->ramdisk_size) {
		int nsid = subsys->max_namespaces + 1;
		ret = open_ram_ns(subsys, nsid, ctx->ramdisk_size);
		if (!ret)
			subsys->max_namespaces++;
	}

	if (ctx->hostnqn)
		inode_add_host_subsys(ctx->hostnqn, ctx->subsysnqn);

	return 0;
}

static struct host_iface *add_iface(const char *ifaddr, int port)
{
	struct host_iface *iface;
	int ret;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;
	memset(iface, 0, sizeof(*iface));
	strcpy(iface->port.traddr, ifaddr);
	strcpy(iface->port.trtype, "tcp");
	if (strchr(ifaddr, '.')) {
		iface->adrfam = AF_INET;
		strcpy(iface->port.adrfam, "ipv4");
	} else if (strchr(ifaddr, ':')) {
		iface->adrfam = AF_INET6;
		strcpy(iface->port.adrfam, "ipv6");
	} else {
		print_err("invalid transport address '%s'", ifaddr);
		free(iface);
		return NULL;
	}
	iface->port_num = port;
	sprintf(iface->port.trsvcid, "%d", port);
	ret = inode_add_port(&iface->port);
	if (ret < 0) {
		print_err("cannot add port, error %d\n", ret);
		free(iface);
		return NULL;
	}
	ret = inode_add_ana_group(iface->port.port_id, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		print_err("cannot add ana group to port, error %d\n", ret);
		inode_del_port(&iface->port);
		free(iface);
		return NULL;
	}
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	printf("iface %d: listening on %s address %s port %s\n",
	       iface->port.port_id,
	       iface->adrfam == AF_INET ? "ipv4" : "ipv6",
	       iface->port.traddr, iface->port.trsvcid);
	fflush(stdout);

	return iface;
}

#define OPTION(t, p)				\
    { t, offsetof(struct nofuse_context, p), 1 }

static const struct fuse_opt nofuse_options[] = {
	OPTION("--subsysnqn=%s", subsysnqn),
	OPTION("--hostnqn=%s", hostnqn),
	OPTION("--help", help),
	OPTION("--debug", debug),
	OPTION("--traddr=%s", traddr),
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
	print_info("  --traddr=<traddr> - transport address (default: '127.0.0.1')");
	print_info("  --port=<portnum> - port number (transport service id) (e.g. 4420)");
	print_info("  --file=<filename> - use file as namespace");
	print_info("  --ramdisk=<size> - create internal ramdisk with given size (in MB)");
	print_info("  --hostnqn=<NQN> - Host NQN of the configured host");
	print_info("  --subsysnqn=<NQN> - Subsystem NQN to use");
	print_info("  --dbname=<filename> - Database filename");
}

static int init_args(struct fuse_args *args)
{
	struct host_iface *iface = NULL;
	int tls_keyring;

	debug = ctx->debug;
	if (debug) {
		tcp_debug = 1;
		cmd_debug = 1;
	}

	if (ctx->traddr) {
		iface = add_iface(ctx->traddr, 8009);
		if (!iface) {
			print_err("Invalid transport address %s\n",
				  ctx->traddr);
			return 1;
		}
		list_add_tail(&iface->node, &iface_linked_list);
	} else {
		iface = add_iface("127.0.0.1", 8009);
		if (!iface) {
			print_err("cannot create default interface\n");
			return 1;
		}
		list_add_tail(&iface->node, &iface_linked_list);
	}

	if (ctx->portnum) {
		iface = add_iface(iface->port.traddr, ctx->portnum);
		if (!iface) {
			print_err("Invalid port %d\n", ctx->portnum);
			return 1;
		}
		list_add_tail(&iface->node, &iface_linked_list);
	}

	if (ctx->hostnqn)
		inode_add_host(ctx->hostnqn);

	if (ctx->help) {
		show_help();
		return 1;
	}

	tls_keyring = tls_global_init();

	if (init_subsys())
		return 1;

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
	struct nofuse_namespace *dev;

	list_for_each_safe(p, n, &device_linked_list) {
		list_del(p);
		dev = container_of(p, struct nofuse_namespace, node);
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

int free_subsys(const char *subsysnqn)
{
	struct nofuse_subsys *subsys, *_subsys;
	int ret = 0;

	list_for_each_entry_safe(subsys, _subsys, &subsys_linked_list, node) {
		if (!subsysnqn || strcmp(subsys->nqn, subsysnqn))
			continue;
		ret = del_subsys(subsys);
		if (ret < 0)
			break;
	}
	return ret;
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

	stopped = 1;

	list_for_each_entry(iface, &iface_linked_list, node) {
		if (iface->pthread)
			pthread_kill(iface->pthread, SIGTERM);
	}

	free_interfaces();

	free_devices();

	free_subsys(NULL);
out_close:
	inode_close(ctx->dbname);

	free(ctx);

	return ret;
}
