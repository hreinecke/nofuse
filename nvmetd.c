/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nvmetd.c
 * Fanotify watcher for nvmet configfs
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>

#include "etcd_client.h"
#include "nvmetd.h"

int stopped = 0;
sigset_t mask;

bool port_debug;
bool ep_debug;
bool etcd_debug;
bool curl_debug;
bool tcp_debug;
bool cmd_debug;
bool inotify_debug;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait = PTHREAD_COND_INITIALIZER;

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
		pthread_cond_signal(&wait);
		return NULL;
	}
	pthread_exit(NULL);
	return NULL;
}

void usage(void) {
	printf("etcd_discovery - decentralized nvme discovery\n");
	printf("usage: etcd_discovery <args>\n");
	printf("Arguments are:\n");
	printf("\t[-h|--host] <host-or-ip>\tHost to connect to\n");
	printf("\t[-p|--port] <portnum>\tetcd client port\n");
	printf("\t[-k|--key_prefix] <prefix>\tetcd key prefix\n");
	printf("\t[-s|--ssl]\tUse SSL connections\n");
	printf("\t[-v|--verbose]\tVerbose output\n");
	printf("\t[-h|--help]\tThis help text\n");
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"ssl", no_argument, 0, 's'},
		{"key_prefix", required_argument, 0, 'k'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, '?'},
	};
	pthread_t watcher_thr;
	pthread_t signal_thr;
	sigset_t oldmask;
	struct watcher_ctx *ctx;
	int ret = 0, getopt_ind;
	char c;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		exit(1);

	memset(ctx, 0, sizeof(*ctx));
	pthread_mutex_init(&ctx->etcd_mutex, NULL);
	ctx->pathname = strdup("/sys/kernel/config/nvmet");
	ctx->path_fd = open(ctx->pathname, O_DIRECTORY | O_RDONLY);
	if (ctx->path_fd < 0) {
		fprintf(stderr, "cannot open path '%s', error %d\n",
			ctx->pathname, errno);
		ret = errno;
		goto out_free;
	}

	ctx->etcd = etcd_init(NULL);
	if (!ctx->etcd) {
		ret = ENOMEM;
		fprintf(stderr, "cannot allocate context\n");
		goto out_close;
	}

	while ((c = getopt_long(argc, argv, "ae:p:h:sv?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'e':
			free(ctx->etcd->prefix);
			ctx->etcd->prefix = strdup(optarg);
			break;
		case 'h':
			ctx->etcd->host = optarg;
			break;
		case 'p':
			ctx->etcd->port = atoi(optarg);
			break;
		case 's':
			ctx->etcd->proto = "https";
			break;
		case 'v':
			etcd_debug = true;
			port_debug = true;
			ep_debug = true;
			inotify_debug = true;
			break;
		case '?':
			usage();
			sigprocmask(SIG_SETMASK, &oldmask, NULL);
			return 0;
		}
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = etcd_lease_grant(ctx->etcd);
	if (ret < 0) {
		fprintf(stderr, "failed to get etcd lease\n");
		goto out_restore;
	}

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		goto out_revoke;
	}

	ret = pthread_create(&watcher_thr, NULL, inotify_loop, ctx);
	if (ret) {
		watcher_thr = 0;
		fprintf(stderr, "failed to start etcd watcher, error %d\n",
			ret);
		goto out_cancel;
	}

	pthread_mutex_lock(&lock);
	while (!stopped)
		pthread_cond_wait(&wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);
	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

out_cancel:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);

out_revoke:
	etcd_lease_revoke(ctx->etcd);
out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	etcd_exit(ctx->etcd);
out_close:
	close(ctx->path_fd);
out_free:
	free(ctx->pathname);
	free(ctx);

	return ret ? 1 : 0;
}
