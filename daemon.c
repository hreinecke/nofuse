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
#include "etcd_client.h"
#include "etcd_backend.h"

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;
bool http_debug;

struct nofuse_context {
	struct etcd_ctx *etcd;
	char *subsysnqn;
	const char *traddr;
	const char *dbname;
	const char *prefix;
	int debug;
	int help;
	int ttl;
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

static int init_discovery(struct nofuse_context *ctx)
{
	int ret;

	ret = etcd_get_discovery_nqn(ctx->etcd, discovery_nqn);
	if (!ret) {
		if (ctx->subsysnqn)
			free(ctx->subsysnqn);
		printf("use existing discovery NQN %s\n", discovery_nqn);
		ctx->subsysnqn = strdup(discovery_nqn);
	} else {
		if (!ctx->subsysnqn)
			ctx->subsysnqn = strdup(NVME_DISC_SUBSYS_NAME);
		ret = etcd_set_discovery_nqn(ctx->etcd, ctx->subsysnqn);
		if (ret < 0) {
			fprintf(stderr, "failed to set discovery nqn\n");
			return ret;
		}
		memcpy(discovery_nqn, ctx->subsysnqn,
		       strlen(ctx->subsysnqn));
		printf("set discovery NQN to %s\n", discovery_nqn);
	}
	if (etcd_test_subsys(ctx->etcd, ctx->subsysnqn) < 0) {
		printf("adding discovery subsystem %s\n",
		       ctx->subsysnqn);
		ret = etcd_add_subsys(ctx->etcd, ctx->subsysnqn,
				      NVME_NQN_CUR);
	}
	return ret;
}

static int init_subsys(struct nofuse_context *ctx)
{
	if (etcd_test_subsys(ctx->etcd, ctx->subsysnqn) == 0)
		etcd_add_subsys_port(ctx->etcd, ctx->subsysnqn, "1");

	return 0;
}

static void *keepalive_loop(void *arg)
{
	struct nofuse_context *ctx = arg;
	int ret;

	while (!stopped) {
		time_t t = time(NULL);

		if (etcd_debug)
			printf("%s", ctime(&t));
		ret = etcd_lease_keepalive(ctx->etcd);
		if (ret < 0)
			break;
		sleep(ctx->etcd->ttl / 2);
	}
	return NULL;
}

#define OPTION(t, p)					\
    { t, offsetof(struct nofuse_context, p), 1 }

static const struct fuse_opt nofuse_options[] = {
	OPTION("--subsysnqn=%s", subsysnqn),
	OPTION("--help", help),
	OPTION("--debug", debug),
	OPTION("--traddr=%s", traddr),
	OPTION("--prefix=%s", prefix),
	OPTION("--ttl=%d", ttl),
	FUSE_OPT_END,
};

static void show_help(void)
{
	printf("Usage: nofuse <args>");
	printf("Possible values for <args>");
	printf("  --debug - enable debug prints in log files");
	printf("  --traddr=<traddr> - transport address (default: '127.0.0.1')");
	printf("  --subsysnqn=<NQN> - Discovery subsystem NQN to use");
	printf("  --prefix=<prefix> - etcd key-value prefix");
	printf("  --ttl=<ttl> - Time-to-live for etcd key-value pairs");
}

static int init_args(struct fuse_args *args, struct nofuse_context *ctx)
{
	const char *traddr = "127.0.0.1";
	int ret;

	if (ctx->help) {
		show_help();
		return 1;
	}

	init_discovery(ctx);

	if (!ctx->traddr)
		ctx->traddr = strdup(traddr);

	ret = etcd_add_port(ctx->etcd, NULL, "1", ctx->traddr, "8009");
	if (ret < 0) {
		fprintf(stderr, "failed to add port for %s\n",
			ctx->traddr);
		return 1;
	}
	ret = etcd_add_ana_group(ctx->etcd, "1", 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		fprintf(stderr, "failed to add ana group to port\n");
		etcd_del_port(ctx->etcd, "1");
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
	pthread_t keepalive_thr;

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));

	if (fuse_opt_parse(&args, ctx, nofuse_options, NULL) < 0)
		return 1;

	if (ctx->debug) {
		tcp_debug = true;
		cmd_debug = true;
		ep_debug = true;
		port_debug = true;
		etcd_debug = true;
	}

	ctx->etcd = etcd_init(ctx->prefix);
	if (!ctx->etcd) {
		fprintf(stderr, "cannot connect to etcd\n");
		free(ctx);
		return 1;
	}
	if (ctx->ttl) {
		if (ctx->ttl < 2)
			ctx->ttl = 2;
		ctx->etcd->ttl = ctx->ttl;
	}

	ret = etcd_lease_grant(ctx->etcd);
	if (ret)
		return 1;

	ret = init_args(&args, ctx);
	if (ret)
		goto out_close;

	stopped = 0;

	ret = pthread_create(&keepalive_thr, NULL, keepalive_loop, ctx);
	if (ret) {
		fprintf(stderr, "cannot start keepalive loop\n");
		goto out_stop;
	}

	run_fuse(&args, ctx->etcd);

out_stop:
	stopped = 1;

	pthread_cancel(keepalive_thr);
	pthread_join(keepalive_thr, NULL);

out_close:
	etcd_lease_revoke(ctx->etcd);
	etcd_exit(ctx->etcd);

	free(ctx);

	return ret;
}
