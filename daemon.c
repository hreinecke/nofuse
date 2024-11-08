
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

int add_namespace(struct nofuse_subsys *subsys, int nsid)
{
	struct nofuse_namespace *ns;
	int ret;

	ns = malloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;
	memset(ns, 0, sizeof(*ns));
	ns->fd = -1;
	ns->subsys = subsys;
	ns->nsid = nsid;
	ret = inode_add_namespace(subsys->nqn, ns->nsid);
	if (ret < 0) {
		free(ns);
		return ret;
	}
	if (nsid > subsys->max_namespaces)
		subsys->max_namespaces = nsid;
	list_add_tail(&ns->node, &device_linked_list);
	return nsid;
}

int enable_namespace(const char *subsysnqn, int nsid)
{
	struct nofuse_namespace *ns = NULL, *_ns;
	char path[PATH_MAX + 1], *eptr = NULL;
	int ret = 0, size;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	list_for_each_entry(_ns, &device_linked_list, node) {
		if (!strcmp(_ns->subsys->nqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENOENT;
	ret = inode_get_namespace_attr(subsysnqn, nsid, "device_path", path);
	if (ret < 0) {
		fprintf(stderr, "subsys %s nsid %d no device path, error %d\n",
			subsysnqn, nsid, ret);
		return ret;
	}
	size = strtoul(path, &eptr, 10);
	if (path != eptr) {
		ns->size = size * 1024 * 1024;
		ns->blksize = 4096;
		ns->ops = null_register_ops();
	} else {
		struct stat st;

		ns->fd = open(path, O_RDWR | O_EXCL);
		if (ns->fd < 0) {
			fprintf(stderr, "subsys %s nsid %d invalid path '%s'\n",
				subsysnqn, nsid, path);
			fflush(stderr);
			return -errno;
		}
		if (fstat(ns->fd, &st) < 0) {
			fprintf(stderr, "subsys %s nsid %d stat error %d\n",
				subsysnqn, nsid, errno);
			fflush(stderr);
			return -errno;
		}
		ns->size = st.st_size;
		ns->blksize = st.st_blksize;
		ns->ops = uring_register_ops();
	}
	ret = inode_set_namespace_attr(subsysnqn, nsid,
				       "device_enable", "1");
	if (ret < 0) {
		fprintf(stderr, "subsys %s nsid %d enable error %d\n",
			subsysnqn, nsid, ret);
		if (ns->fd > 0) {
			close(ns->fd);
			ns->fd = -1;
		}
		ns->size = 0;
		ns->blksize = 0;
		ns->ops = NULL;
	}
	return ret;
}

int disable_namespace(const char *subsysnqn, int nsid)
{
	struct nofuse_namespace *ns = NULL, *_ns;
	int ret;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	list_for_each_entry(_ns, &device_linked_list, node) {
		if (!strcmp(_ns->subsys->nqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENOENT;
	ret = inode_set_namespace_attr(subsysnqn, nsid,
				       "device_enable", "0");
	if (ret < 0)
		return ret;

	if (ns->fd > 0) {
		close(ns->fd);
		ns->fd = -1;
	}
	ns->size = 0;
	ns->blksize = 0;
	ns->ops = NULL;
	return 0;
}

int del_namespace(const char *subsysnqn, int nsid)
{
	struct nofuse_namespace *ns, *_ns;
	int ret = -ENOENT;

	list_for_each_entry(_ns, &device_linked_list, node) {
		if (!strcmp(_ns->subsys->nqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return ret;
	ret = inode_del_namespace(subsysnqn, ns->nsid);
	if (ret < 0)
		return ret;
	list_del(&ns->node);
	if (ns->fd > 0)
		close(ns->fd);
	free(ns);
	return 0;
}

static int open_file_ns(struct nofuse_subsys *subsys, const char *filename)
{
	int ret, nsid;

        nsid = add_namespace(subsys, ++subsys->max_namespaces);
	if (nsid < 0) {
		subsys->max_namespaces--;
		return nsid;
	}

	ret = inode_set_namespace_attr(subsys->nqn, nsid,
				       "device_path", filename);
	if (ret < 0)
		goto del_ns;
	ret = enable_namespace(subsys->nqn, nsid);
	if (ret < 0)
		goto del_ns;
	return 0;
del_ns:
	del_namespace(subsys->nqn, nsid);
	subsys->max_namespaces--;
	return ret;
}

int open_ram_ns(struct nofuse_subsys *subsys, size_t size)
{
	char size_str[16];
	int ret, nsid;

	sprintf(size_str, "%lu", size);
	nsid = add_namespace(subsys, ++subsys->max_namespaces);
	if (nsid < 0) {
		subsys->max_namespaces--;
		return nsid;
	}
	ret = inode_set_namespace_attr(subsys->nqn, nsid,
				       "device_path", size_str);
	if (ret < 0)
		goto del_ns;
	ret = enable_namespace(subsys->nqn, nsid);
	if (ret < 0)
		goto del_ns;
	return 0;
del_ns:
	del_namespace(subsys->nqn, nsid);
	subsys->max_namespaces--;
	return ret;
}

static int init_subsys(void)
{
	struct nofuse_subsys *subsys, *tmp_subsys;
	struct interface *iface;
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
	if (ctx->ramdisk_size)
		open_ram_ns(subsys, ctx->ramdisk_size);

	if (ctx->hostnqn)
		inode_add_host_subsys(ctx->hostnqn, ctx->subsysnqn);

	return 0;
}

int add_iface(const char *ifaddr, int id, int port)
{
	struct interface *iface;
	int ret;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return -ENOMEM;
	memset(iface, 0, sizeof(*iface));
	if (ifaddr) {
		strcpy(iface->port.trtype, "tcp");
		strcpy(iface->port.traddr, ifaddr);
		if (strchr(ifaddr, '.')) {
			iface->adrfam = AF_INET;
			strcpy(iface->port.adrfam, "ipv4");
		} else if (strchr(ifaddr, ':')) {
			iface->adrfam = AF_INET6;
			strcpy(iface->port.adrfam, "ipv6");
		} else {
			print_err("invalid transport address '%s'", ifaddr);
			free(iface);
			return -EINVAL;
		}
	} else {
		strcpy(iface->port.trtype, "loop");
	}
	iface->port_num = port;
	iface->port.port_id = id;
	if (ifaddr && port)
		sprintf(iface->port.trsvcid, "%d", port);
	ret = inode_add_port(&iface->port);
	if (ret < 0) {
		print_err("cannot add port, error %d\n", ret);
		free(iface);
		return ret;
	}
	ret = inode_add_ana_group(iface->port.port_id, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		print_err("cannot add ana group to port, error %d\n", ret);
		inode_del_port(&iface->port);
		free(iface);
		return ret;
	}
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	list_add_tail(&iface->node, &iface_linked_list);

	printf("iface %d: listening on %s address %s port %s\n",
	       iface->port.port_id,
	       iface->adrfam == AF_INET ? "ipv4" : "ipv6",
	       iface->port.traddr, iface->port.trsvcid);
	fflush(stdout);
	return 0;
}

int start_iface(int id)
{
	struct interface *iface = NULL, *_iface;
	pthread_attr_t pthread_attr;
	int ret;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->port.port_id == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface)
		return -EINVAL;

	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&iface->pthread, &pthread_attr,
			     run_host_interface, iface);
	if (ret) {
		iface->pthread = 0;
		fprintf(stderr, "iface %d: failed to start thread\n",
			iface->port.port_id);
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

int stop_iface(int id)
{
	struct interface *iface = NULL, *_iface;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->port.port_id == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface)
		return -EINVAL;

	if (iface->pthread)
		pthread_kill(iface->pthread, SIGTERM);
	return 0;
}

int del_iface(int id)
{
	struct interface *iface = NULL, *_iface;
	int ret;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->port.port_id == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface)
		return -EINVAL;

	ret = inode_del_port(&iface->port);
	if (ret < 0)
		return ret;
	list_del(&iface->node);
	free(iface);
	return 0;
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
	const char *traddr = "127.0.0.1";
	int tls_keyring;
	int num_ifaces = 0, ret;

	debug = ctx->debug;
	if (debug) {
		tcp_debug = 1;
		cmd_debug = 1;
	}

	if (!ctx->traddr)
		ctx->traddr = strdup(traddr);

	ret = add_iface(ctx->traddr, num_ifaces + 1, 8009);
	if (ret < 0) {
		fprintf(stderr, "failed to add interface for %s\n",
			ctx->traddr);
		return 1;
	}
	num_ifaces++;

	if (ctx->portnum) {
		ret = add_iface(ctx->traddr, num_ifaces + 1,
				ctx->portnum);
		if (ret < 0) {
			print_err("Invalid port %d\n", ctx->portnum);
			return 1;
		}
		num_ifaces++;
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
		struct interface *iface;

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
		inode_del_namespace(dev->subsys->nqn, dev->nsid);
		if (dev->fd >= 0)
			close(dev->fd);
		free(dev);
	}
}

void free_interfaces(void)
{
	struct interface *iface, *_iface;

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
	struct interface *iface;
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
