/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * watcher.c
 * etcd watcher to manage nvmet configfs
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>

#include "common.h"
#include "etcd_client.h"
#include "configfs.h"

bool etcd_debug = false;
bool http_debug = false;
bool cmd_debug = false;
bool tcp_debug = false;
bool ep_debug = false;
bool port_debug = false;
bool configfs_debug = true;

int stopped = 0;
sigset_t mask;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_wait = PTHREAD_COND_INITIALIZER;

static void *signal_handler(void *arg)
{
	int ret, signo;

	for (;;) {
		ret = sigwait(&mask, &signo);
		if (ret != 0) {
			fprintf(stderr, "sigwait failed with %d\n", ret);
			break;
		}
		printf("signal %d, terminating\n", signo);
		pthread_mutex_lock(&lock);
		stopped = 1;
		pthread_mutex_unlock(&lock);
		pthread_cond_signal(&cond_wait);
		return NULL;
	}
	pthread_exit(NULL);
	return NULL;
}

static void delete_conn(void *arg)
{
	struct etcd_conn_ctx *conn = arg;

	etcd_conn_delete(conn);
}

static void *etcd_watcher(void *arg)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_conn_ctx *conn = NULL;;
	struct etcd_kv_event ev;
	int64_t start_revision = 0;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn) {
		pthread_exit(NULL);
		return NULL;
	}
	pthread_cleanup_push(delete_conn, conn);

	memset(&ev, 0, sizeof(ev));
	ev.ev_revision = start_revision;
	ev.watch_cb = etcd_watch_cb;
	ev.watch_arg = conn->ctx;

	while (!stopped) {
		ret = etcd_kv_watch(conn, ctx->prefix, &ev, pthread_self());
		if (ret && ret != -ETIME)
			break;
	}
	if (ret && ret != -ETIME)
		fprintf(stderr, "%s: etcd_kv_watch failed with %d\n",
				__func__, ret);
	pthread_cleanup_pop(1);

	pthread_exit(NULL);
	return NULL;
}

void usage(void) {
	printf("etcd_watcher - watch etcd kv entries\n");
	printf("usage: etcd_watcher <args>\n");
	printf("Arguments are:\n");
	printf("\t[-m|--mount] <dir>\tinternal configfs mount point\n");
	printf("\t[-n|--node] <name>\tetcd node name\n");
	printf("\t[-p|--prefix] <prefix>\tetcd key prefix\n");
	printf("\t[-t|--ttl] <ttl>\tetcd TTL value\n");
	printf("\t[-u|--url] <url>\tetcd daemon URL\n");
	printf("\t[-v|--verbose]\tVerbose output\n");
	printf("\t[-h|--help]\tThis help text\n");
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"mount", required_argument, 0, 'm'},
		{"node", required_argument, 0, 'n'},
		{"prefix", required_argument, 0, 'p'},
		{"ttl", required_argument, 0, 't'},
		{"url", required_argument, 0, 'u'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, '?'},
	};
	static pthread_t watcher_thr, signal_thr;
	struct stat st;
	sigset_t oldmask;
	char c, *node_name = NULL, *prefix = NULL, *eptr, *mnt = NULL, *url = NULL;
	unsigned int ttl = 0;
	int getopt_ind;
	struct etcd_ctx *ctx;
	int ret = 0;

	while ((c = getopt_long(argc, argv, "m:n:p:t:u:v?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'm':
			mnt = optarg;
			break;
		case 'n':
			node_name = optarg;
			break;
		case 'p':
			prefix = optarg;
			break;
		case 't':
			ttl = strtoul(optarg, &eptr, 10);
			if (eptr == optarg || ttl == ULONG_MAX) {
				fprintf(stderr, "Invalid TTL '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'u':
			url = optarg;
			break;
		case 'v':
			etcd_debug = true;
			port_debug = true;
			ep_debug = true;
			break;
		case '?':
			usage();
			return 0;
		}
	}

	if (mnt) {
		if (stat(mnt, &st) < 0) {
			fprintf(stderr, "Failed to access '%s', error %d\n",
				mnt, errno);
			exit(1);
		}
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "Mountpoint '%s' is not a directory\n",
				mnt);
			exit(1);
		}
		if (mount(NVMET_CONFIGFS, mnt, "configfs", MS_BIND, NULL) < 0) {
			fprintf(stderr, "Cannot bind mount to '%s'\n",
				mnt);
			exit(1);
		}
	}
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		ret = -ENOMEM;
		goto out_restore_sig;
	}

	ctx = etcd_init(url, node_name, prefix, mnt, ttl);
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		goto out_cancel_sig;
	}
	ret = configfs_load_ana(ctx);
	if (ret < 0) {
		fprintf(stderr, "loading ANA information failed\n");
		goto out_cancel_sig;
	}
	ret = configfs_validate_cluster(ctx);
	if (ret < 0) {
		fprintf(stderr, "cluster validation failed\n");
		goto out_cancel_sig;
	}
	ret = configfs_validate_ana(ctx);
	if (ret < 0) {
		fprintf(stderr, "ANA validation failed\n");
		goto out_cancel_sig;
	}
	ret = upload_configfs(ctx, ctx->configfs, "ports");
	if (ret < 0) {
		fprintf(stderr, "failed to upload port configuration\n");
		goto out_cleanup;
	}
	ret = upload_configfs(ctx, ctx->configfs, "hosts");
	if (ret < 0) {
		fprintf(stderr, "failed to upload hosts configuration\n");
		goto out_cleanup;
	}
	ret = upload_configfs(ctx, ctx->configfs, "subsystems");
	if (ret < 0) {
		fprintf(stderr, "failed to upload subsystem configuration\n");
		goto out_cleanup;
	}
	ret = pthread_create(&watcher_thr, NULL, etcd_watcher, ctx);
	if (ret) {
		watcher_thr = 0;
		fprintf(stderr, "failed to start etcd watcher, error %d\n",
			ret);
		goto out_clear_keys;
	}

	pthread_mutex_lock(&lock);
	while (!stopped)
		pthread_cond_wait(&cond_wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);

	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

out_clear_keys:
	configfs_purge_ports(ctx);
	configfs_purge_subsystems(ctx);
out_cleanup:
	etcd_exit(ctx);

out_cancel_sig:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);
out_restore_sig:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	if (mnt && umount(mnt) < 0) {
		fprintf(stderr, "Failed to umount '%s', error %d\n",
			mnt, errno);
		ret = -errno;
	}

	return ret < 0 ? 1 : 0;
}
