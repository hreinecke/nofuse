
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
#include "configdb.h"

LINKED_LIST(subsys_linked_list);
LINKED_LIST(iface_linked_list);
LINKED_LIST(device_linked_list);

int stopped;
int debug;
int tcp_debug;
int cmd_debug;
int ep_debug;
int iface_debug;

static char default_nqn[] =
	"nqn.2014-08.org.nvmexpress:uuid:62f37f51-0cc7-46d5-9865-4de22e81bd9d";

struct nofuse_context {
	const char *hostnqn;
	const char *subsysnqn;
	const char *traddr;
	const char *dbname;
	int portnum;
	int debug;
	int help;
};

extern int run_fuse(struct fuse_args *args);

static struct nofuse_subsys *find_subsys(const char *subsysnqn)
{
	struct nofuse_subsys *subsys = NULL;

	list_for_each_entry(subsys, &subsys_linked_list, node) {
		if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME) &&
		    subsys->type == NVME_NQN_CUR)
			return subsys;
		if (!strcmp(subsys->nqn, subsysnqn))
			return subsys;
	}
	return NULL;
}

int add_subsys(const char *nqn, int type)
{
	struct nofuse_subsys *subsys;
	int ret;

	if (type == NVME_NQN_CUR)
		subsys = find_subsys(NVME_DISC_SUBSYS_NAME);
	else
		subsys = find_subsys(nqn);
	if (subsys)
		return -EEXIST;
	subsys = malloc(sizeof(*subsys));
	if (!subsys)
		return -ENOMEM;
	memset(subsys, 0, sizeof(*subsys));
	if (!subsys->nqn)
		strcpy(subsys->nqn, default_nqn);
	else
		strcpy(subsys->nqn, nqn);
	subsys->type = type;
	if (subsys->type == NVME_NQN_CUR)
		subsys->allow_any = 1;
	else
		subsys->allow_any = 0;
	ret = configdb_add_subsys(subsys);
	if (ret < 0) {
		free(subsys);
		return ret;
	}

	pthread_mutex_init(&subsys->ctrl_mutex, NULL);
	INIT_LINKED_LIST(&subsys->node);
	INIT_LINKED_LIST(&subsys->ctrl_list);
	list_add(&subsys->node, &subsys_linked_list);

	return ret;
}

static int del_subsys(struct nofuse_subsys *subsys)
{
	int ret;

	printf("deleting subsys %s\n", subsys->nqn);
	ret = configdb_del_subsys(subsys);
	if (ret < 0)
		return ret;
	list_del(&subsys->node);
	pthread_mutex_destroy(&subsys->ctrl_mutex);
	free(subsys);
	return ret;
}

int add_namespace(const char *subsysnqn, int nsid)
{
	struct nofuse_namespace *ns;
	int ret;

	ns = malloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;
	memset(ns, 0, sizeof(*ns));
	ns->fd = -1;
	strcpy(ns->subsysnqn, subsysnqn);
	ns->nsid = nsid;
	ret = configdb_add_namespace(subsysnqn, ns->nsid);
	if (ret < 0) {
		free(ns);
		return ret;
	}
	INIT_LINKED_LIST(&ns->node);
	list_add_tail(&ns->node, &device_linked_list);
	return 0;
}

int enable_namespace(const char *subsysnqn, int nsid)
{
	struct nofuse_namespace *ns = NULL, *_ns;
	char path[PATH_MAX + 1], *eptr = NULL;
	int ret = 0, size;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	list_for_each_entry(_ns, &device_linked_list, node) {
		if (!strcmp(_ns->subsysnqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENOENT;
	ret = configdb_get_namespace_attr(subsysnqn, nsid, "device_path", path);
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
	ret = configdb_set_namespace_attr(subsysnqn, nsid,
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
		if (!strcmp(_ns->subsysnqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENOENT;
	ret = configdb_set_namespace_attr(subsysnqn, nsid,
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
		if (!strcmp(_ns->subsysnqn, subsysnqn) &&
		    _ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return ret;
	ret = configdb_del_namespace(subsysnqn, ns->nsid);
	if (ret < 0)
		return ret;
	list_del(&ns->node);
	if (ns->fd > 0)
		close(ns->fd);
	free(ns);
	return 0;
}

static int init_subsys(struct nofuse_context *ctx)
{
	struct nofuse_subsys *subsys;
	struct interface *iface;
	int ret;

	ret = add_subsys(ctx->subsysnqn, NVME_NQN_CUR);
	if (ret)
		return ret;

	subsys = find_subsys(ctx->subsysnqn);
	if (!subsys)
		return -ENOENT;
	list_for_each_entry(iface, &iface_linked_list, node) {
		configdb_add_subsys_port(subsys->nqn, iface->portid);
	}

	if (ctx->hostnqn)
		configdb_add_host_subsys(ctx->hostnqn, ctx->subsysnqn);

	return 0;
}

int add_iface(unsigned int id, const char *ifaddr, int port)
{
	struct interface *iface;
	int ret;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return -ENOMEM;
	memset(iface, 0, sizeof(*iface));
	iface->listenfd = -1;
	iface->portid = id;
	ret = configdb_add_port(id);
	if (ret < 0) {
		iface_err(iface, "cannot register port, error %d", ret);
		free(iface);
		return ret;
	}
	if (ifaddr && strcmp(ifaddr, "127.0.0.1")) {
		if (!strchr(ifaddr, ','))
			configdb_set_port_attr(iface->portid, "addr_adrfam",
					    "ipv6");
		configdb_set_port_attr(iface->portid, "addr_traddr", ifaddr);
	}
	if (port) {
		char trsvcid[5];

		sprintf(trsvcid, "%d", port);
		configdb_set_port_attr(iface->portid, "addr_trsvcid", trsvcid);
	}
	ret = configdb_add_ana_group(iface->portid, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		iface_err(iface, "cannot add ana group to port, error %d", ret);
		configdb_del_port(iface->portid);
		free(iface);
		return ret;
	}
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	INIT_LINKED_LIST(&iface->node);
	list_add_tail(&iface->node, &iface_linked_list);

	return 0;
}

int start_iface(int id)
{
	struct interface *iface = NULL, *_iface;
	pthread_attr_t pthread_attr;
	int ret;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->portid == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface)
		return -EINVAL;

	if (iface->pthread)
		return 0;

	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&iface->pthread, &pthread_attr,
			     run_host_interface, iface);
	if (ret) {
		iface->pthread = 0;
		iface_err(iface, "failed to start thread");
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

int stop_iface(int id)
{
	struct interface *iface = NULL, *_iface;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->portid == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface) {
		printf("interface %d not found\n", id);
		return -EINVAL;
	}

	iface_info(iface, "stop pthread %ld", iface->pthread);
	if (iface->pthread)
		pthread_kill(iface->pthread, SIGTERM);
	return 0;
}

int del_iface(int id)
{
	struct interface *iface = NULL, *_iface;
	int ret;

	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface->portid == id) {
			iface = _iface;
			break;
		}
	}
	if (!iface)
		return -EINVAL;

	if (iface->pthread) {
		iface->ops->destroy_listener(iface);
		pthread_kill(iface->pthread, SIGTERM);
		pthread_join(iface->pthread, NULL);
		iface->pthread = 0;
	}
	ret = configdb_del_ana_group(iface->portid, 1);
	if (ret < 0) {
		iface_err(iface, "cannot delete ana group from port, error %d",
			  ret);
		return ret;
	}
	ret = configdb_del_port(iface->portid);
	if (ret < 0) {
		configdb_add_ana_group(iface->portid, 1, NVME_ANA_OPTIMIZED);
		return ret;
	}
	pthread_mutex_destroy(&iface->ep_mutex);
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
	OPTION("--dbname=%s", dbname),
	FUSE_OPT_END,
};

static void show_help(void)
{
	printf("Usage: nofuse <args>");
	printf("Possible values for <args>");
	printf("  --debug - enable debug prints in log files");
	printf("  --traddr=<traddr> - transport address (default: '127.0.0.1')");
	printf("  --port=<portnum> - port number (transport service id) (e.g. 4420)");
	printf("  --hostnqn=<NQN> - Host NQN of the configured host");
	printf("  --subsysnqn=<NQN> - Subsystem NQN to use");
	printf("  --dbname=<filename> - Database filename");
}

static int init_args(struct fuse_args *args, struct nofuse_context *ctx)
{
	const char *traddr = "127.0.0.1";
	int tls_keyring;
	int num_ifaces = 0, ret;

	debug = ctx->debug;
	if (debug) {
		tcp_debug = 1;
		cmd_debug = 1;
		ep_debug = 1;
		iface_debug = 1;
	}

	if (!ctx->subsysnqn)
		ctx->subsysnqn = strdup(NVME_DISC_SUBSYS_NAME);

	if (!ctx->traddr)
		ctx->traddr = strdup(traddr);

	ret = add_iface(num_ifaces + 1, ctx->traddr, 8009);
	if (ret < 0) {
		fprintf(stderr, "failed to add interface for %s\n",
			ctx->traddr);
		return 1;
	}
	num_ifaces++;

	if (ctx->portnum) {
		ret = add_iface(num_ifaces + 1, ctx->traddr,
				ctx->portnum);
		if (ret < 0) {
			fprintf(stderr, "Invalid port %d\n", ctx->portnum);
			return 1;
		}
		num_ifaces++;
	}

	if (ctx->hostnqn)
		configdb_add_host(ctx->hostnqn);

	if (ctx->help) {
		show_help();
		return 1;
	}

	tls_keyring = tls_global_init();

	if (init_subsys(ctx))
		return 1;

	if (list_empty(&iface_linked_list)) {
		fprintf(stderr, "invalid host interface configuration");
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
		configdb_del_namespace(dev->subsysnqn, dev->nsid);
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
		if (!subsysnqn ||
		    (!strcmp(subsys->nqn, subsysnqn) &&
		     subsys->type != NVME_NQN_CUR)) {
			ret = del_subsys(subsys);
			break;
		}
	}
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct nofuse_context *ctx;
	struct interface *iface;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));
	ctx->dbname = strdup("nofuse.sqlite");

	if (fuse_opt_parse(&args, ctx, nofuse_options, NULL) < 0)
		return 1;

	ret = configdb_open(ctx->dbname);
	if (ret)
		return 1;

	ret = init_args(&args, ctx);
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
			iface_err(iface, "failed to start iface thread");
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
	configdb_close(ctx->dbname);

	free(ctx);

	return ret;
}
