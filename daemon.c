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
#ifdef NOFUSE_ETCD
#include "etcd_client.h"
#include "etcd_backend.h"
#else
#include "configdb.h"
#endif

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;

struct nofuse_context {
	struct etcd_ctx *etcd;
	const char *subsysnqn;
	const char *traddr;
	const char *dbname;
	const char *prefix;
	int debug;
	int help;
};

char discovery_nqn[MAX_NQN_SIZE + 1] = {};

extern int run_fuse(struct fuse_args *args, struct etcd_ctx *ctx);

int default_subsys_type(const char *nqn)
{
	if (!strcmp(nqn, discovery_nqn))
		return NVME_NQN_CUR;
	else
		return NVME_NQN_NVM;
}

static int add_subsys(struct nofuse_context *ctx, int type)
{
	int ret;

#ifdef NOFUSE_ETCD
	ret = etcd_add_subsys(ctx->etcd, ctx->subsysnqn, type);
#else
	ret = configdb_add_subsys(ctx->subsysnqn, type);
#endif
	return ret;
}

static int init_subsys(struct nofuse_context *ctx)
{
	int ret;

	ret = etcd_set_discovery_nqn(ctx->etcd, ctx->subsysnqn);
	if (ret)
		return ret;

	ret = add_subsys(ctx, NVME_NQN_CUR);
	if (ret)
		return ret;

	etcd_add_subsys_port(ctx->etcd, ctx->subsysnqn, 1);

	return 0;
}

#define OPTION(t, p)				\
    { t, offsetof(struct nofuse_context, p), 1 }

static const struct fuse_opt nofuse_options[] = {
	OPTION("--subsysnqn=%s", subsysnqn),
	OPTION("--help", help),
	OPTION("--debug", debug),
	OPTION("--traddr=%s", traddr),
#ifdef NOFUSE_ETCD
	OPTION("--prefix=%s", prefix),
#else
	OPTION("--dbname=%s", dbname),
#endif
	FUSE_OPT_END,
};

static void show_help(void)
{
	printf("Usage: nofuse <args>");
	printf("Possible values for <args>");
	printf("  --debug - enable debug prints in log files");
	printf("  --traddr=<traddr> - transport address (default: '127.0.0.1')");
	printf("  --subsysnqn=<NQN> - Discovery subsystem NQN to use");
#ifdef NOFUSE_ETCD
	printf("  --prefix=<prefix> - etcd key-value prefix");
#else
	printf("  --dbname=<filename> - Database filename");
#endif
}

static int init_args(struct fuse_args *args, struct nofuse_context *ctx)
{
	const char *traddr = "127.0.0.1";
	int ret;

	if (ctx->help) {
		show_help();
		return 1;
	}

	if (!ctx->subsysnqn)
		ctx->subsysnqn = strdup(NVME_DISC_SUBSYS_NAME);
	memcpy(discovery_nqn, ctx->subsysnqn,
	       strlen(ctx->subsysnqn));

	if (!ctx->traddr)
		ctx->traddr = strdup(traddr);

	ret = etcd_add_port(ctx->etcd, ctx->prefix, 1, ctx->traddr, 8009);
	if (ret < 0) {
		fprintf(stderr, "failed to add port for %s\n",
			ctx->traddr);
		return 1;
	}
	ret = etcd_add_ana_group(ctx->etcd, 1, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		fprintf(stderr, "failed to add ana group to port\n");
		etcd_del_port(ctx->etcd, 1);
		return 1;
	}

	if (init_subsys(ctx))
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct nofuse_context *ctx;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));
#ifndef NOFUSE_ETCD
	ctx->dbname = strdup("nofuse.sqlite");
#endif

	if (fuse_opt_parse(&args, ctx, nofuse_options, NULL) < 0)
		return 1;

	if (ctx->debug) {
		tcp_debug = true;
		cmd_debug = true;
		ep_debug = true;
		port_debug = true;
		etcd_debug = true;
	}

#ifdef NOFUSE_ETCD
	ctx->etcd = etcd_init(ctx->prefix);
	ret = etcd_lease_grant(ctx->etcd);
#else
	ret = configdb_open(ctx->dbname);
#endif
	if (ret)
		return 1;

	ret = init_args(&args, ctx);
	if (ret)
		goto out_close;

	stopped = 0;

	run_fuse(&args, ctx->etcd);

	stopped = 1;

out_close:
#ifdef NOFUSE_ETCD
	etcd_lease_revoke(ctx->etcd);
	etcd_exit(ctx->etcd);
#else
	configdb_close(ctx->dbname);
#endif

	free(ctx);

	return ret;
}
