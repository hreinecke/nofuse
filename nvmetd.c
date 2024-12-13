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

static int read_attr(char *attr_path, char *value, size_t value_len)
{
	int fd, len;
	char *p;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -1;
	}
	len = read(fd, value, value_len);
	if (len < 0)
		memset(value, 0, value_len);
	else {
		p = &value[len - 1];
		if (*p == '\n')
			*p = '\0';
	}
	close(fd);
	return len;
}

int mark_files(struct watcher_ctx *ctx, char *dirname)
{
	DIR *d;
	struct dirent *de;
	int ret;
	struct etcd_ctx *ectx = etcd_dup(ctx->etcd);

	d = opendir(dirname);
	if (d < 0)
		return -errno;
	while ((de = readdir(d))) {
		char pathname[PATH_MAX];
		char value[512];

		if (!strcmp(de->d_name, ".") ||
		    !strcmp(de->d_name, ".."))
			continue;
		sprintf(pathname, "%s/%s", dirname, de->d_name);
		if (de->d_type  == DT_DIR)
			mark_files(ctx, pathname);
		else if (de->d_type == DT_LNK) {
			char *p = pathname + strlen(ctx->pathname) + 1;

			ret = readlink(pathname, value, sizeof(value));
			if (ret > 0) {
				printf("link %s\n", p);
				ret = etcd_kv_put(ectx, p, value, true);
				if (ret < 0)
					fprintf(stderr,
						"link %s put error %d\n",
						p, ret);
			}
		} else {
			char *p = pathname + strlen(ctx->pathname) + 1;

			ret = read_attr(pathname, value, sizeof(value));
			if (ret > 0 && strlen(value)) {
				printf("attr %s value '%s'\n", p, value);
				ret = etcd_kv_put(ectx, p, value, true);
				if (ret < 0)
					fprintf(stderr,
						"attr %s put error %d\n",
						p, ret);
			}
		}
	}
	closedir(d);
	etcd_exit(ectx);
	return 0;
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

	ret = etcd_lease_grant(ctx->etcd);
	if (ret < 0) {
		fprintf(stderr, "failed to get etcd lease\n");
		goto out_free_etcd;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		goto out_restore;
	}

	ret = pthread_create(&watcher_thr, NULL, inotify_loop, ctx);
	if (ret) {
		watcher_thr = 0;
		fprintf(stderr, "failed to start etcd watcher, error %d\n",
			ret);
		goto out_cancel;
	}

	mark_files(ctx, ctx->pathname);

	start_inotify(ctx);

	pthread_mutex_lock(&lock);
	while (!stopped)
		pthread_cond_wait(&wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);
	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

	stop_inotify(ctx);
out_cancel:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);

out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	etcd_lease_revoke(ctx->etcd);
out_free_etcd:
	etcd_exit(ctx->etcd);
out_close:
	close(ctx->path_fd);
out_free:
	free(ctx->pathname);
	free(ctx);

	return ret ? 1 : 0;
}
