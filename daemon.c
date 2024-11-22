/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * daemon.c
 * NVME-over-TCP userspace daemon
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>. All rights reserved.
 *
 * Based on nvme-dem (https://github.com/linux-nvme/nvme-dem/src/endpoint)
 * Copyright (c) 2017-2019 Intel Corporation, Inc. All rights reserved.
 */
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

LINKED_LIST(device_linked_list);

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;

struct nofuse_context {
	const char *subsysnqn;
	const char *traddr;
	const char *dbname;
	int debug;
	int help;
};

char discovery_nqn[MAX_NQN_SIZE + 1] = {};

extern int run_fuse(struct fuse_args *args);

int default_subsys_type(const char *nqn)
{
	if (!strcmp(nqn, discovery_nqn))
		return NVME_NQN_CUR;
	else
		return NVME_NQN_NVM;
}

void raise_aen(int level, int type)
{
}

struct nofuse_namespace *find_namespace(const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;

	list_for_each_entry(ns, &device_linked_list, node) {
		if (!strcmp(ns->subsysnqn, subsysnqn) &&
		    ns->nsid == nsid)
			return ns;
	}
	return NULL;
}

int add_namespace(const char *subsysnqn, u32 nsid)
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
	ret = configdb_set_namespace_anagrp(subsysnqn, ns->nsid, 1);
	if (ret < 0) {
		configdb_del_namespace(subsysnqn, ns->nsid);
		free(ns);
		return ret;
	}
	INIT_LINKED_LIST(&ns->node);
	list_add_tail(&ns->node, &device_linked_list);
	printf("%s: subsys %s nsid %d\n", __func__, subsysnqn, nsid);
	return 0;
}

int enable_namespace(const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	char path[PATH_MAX + 1], *eptr = NULL;
	int ret = 0, size;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	ns = find_namespace(subsysnqn, nsid);
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
		mode_t mode = O_RDWR | O_EXCL;

		if (stat(path, &st) < 0) {
			fprintf(stderr, "subsys %s nsid %d invalid path '%s'\n",
				subsysnqn, nsid, path);
			fflush(stderr);
			return -errno;
		}
		if (!(st.st_mode & S_IWUSR)) {
			mode = O_RDONLY;
			ns->readonly = true;
		}
		ns->fd = open(path, mode);
		if (ns->fd < 0) {
			fprintf(stderr, "subsys %s nsid %d invalid path '%s'\n",
				subsysnqn, nsid, path);
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
	printf("subsys %s nsid %d size %lu blksize %u\n",
	       subsysnqn, nsid, ns->size, ns->blksize);
	return ret;
}

int disable_namespace(const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	int ret;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	ns = find_namespace(subsysnqn, nsid);
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

int del_namespace(const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	int ret = -ENOENT;

	ns = find_namespace(subsysnqn, nsid);
	if (!ns)
		return ret;
	printf("%s: subsys %s nsid %d\n",
	       __func__, subsysnqn, nsid);
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
	struct nofuse_port *port;
	int ret;

	ret = configdb_add_subsys(ctx->subsysnqn, NVME_NQN_CUR);
	if (ret)
		return ret;

	list_for_each_entry(port, &port_linked_list, node) {
		configdb_add_subsys_port(ctx->subsysnqn, port->portid);
	}

	return 0;
}

#define OPTION(t, p)				\
    { t, offsetof(struct nofuse_context, p), 1 }

static const struct fuse_opt nofuse_options[] = {
	OPTION("--subsysnqn=%s", subsysnqn),
	OPTION("--help", help),
	OPTION("--debug", debug),
	OPTION("--traddr=%s", traddr),
	OPTION("--dbname=%s", dbname),
	FUSE_OPT_END,
};

static void show_help(void)
{
	printf("Usage: nofuse <args>");
	printf("Possible values for <args>");
	printf("  --debug - enable debug prints in log files");
	printf("  --traddr=<traddr> - transport address (default: '127.0.0.1')");
	printf("  --subsysnqn=<NQN> - Discovery subsystem NQN to use");
	printf("  --dbname=<filename> - Database filename");
}

static int init_args(struct fuse_args *args, struct nofuse_context *ctx)
{
	const char *traddr = "127.0.0.1";
	int tls_keyring;
	int ret;

	if (ctx->debug) {
		tcp_debug = true;
		cmd_debug = true;
		ep_debug = true;
		port_debug = true;
	}

	if (!ctx->subsysnqn)
		ctx->subsysnqn = strdup(NVME_DISC_SUBSYS_NAME);
	memcpy(discovery_nqn, ctx->subsysnqn,
	       strlen(ctx->subsysnqn));

	if (!ctx->traddr)
		ctx->traddr = strdup(traddr);

	ret = add_port(1, ctx->traddr, 8009);
	if (ret < 0) {
		fprintf(stderr, "failed to add port for %s\n",
			ctx->traddr);
		return 1;
	}

	if (ctx->help) {
		show_help();
		return 1;
	}

	tls_keyring = tls_global_init();

	if (init_subsys(ctx))
		return 1;

	if (list_empty(&port_linked_list)) {
		fprintf(stderr, "invalid host port configuration");
		return 1;
	} else if (tls_keyring) {
		struct nofuse_port *port;

		list_for_each_entry(port, &port_linked_list, node) {
			port->tls = true;
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

void free_ports(void)
{
	struct nofuse_port *port, *_port;

	list_for_each_entry_safe(port, _port, &port_linked_list, node)
		del_port(port);
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct nofuse_context *ctx;
	struct nofuse_port *port;
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

	list_for_each_entry(port, &port_linked_list, node)
		start_port(port);

	run_fuse(&args);

	stopped = 1;

	list_for_each_entry(port, &port_linked_list, node)
		stop_port(port);

	free_ports();

	free_devices();
out_close:
	configdb_close(ctx->dbname);

	free(ctx);

	return ret;
}
