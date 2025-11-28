/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * portd.c
 * Manage discovery ports by watching keys in etcd
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "common.h"
#include "etcd_client.h"

bool ep_debug;
bool cmd_debug;
bool port_debug;
bool tcp_debug;
bool etcd_debug;
bool http_debug;
bool configfs_debug;

int stopped = 0;
sigset_t mask;

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

static int parse_port_key(char *key, unsigned int *portid,
			  char **attr, char **subsys, unsigned int *ana_grpid)
{
	char *p, *s, *port, *eptr = NULL;
	unsigned long id;

	port = strtok_r(key, "/", &s);
	if (!port)
		return -EINVAL;
	id = strtoul(port, &eptr, 10);
	if (id == ULONG_MAX || port == eptr)
		return -EDOM;
	*portid = id;
	*attr = strtok_r(NULL, "/", &s);
	if (!*attr) {
		*portid = 0;
		return -EINVAL;
	}
	if (!strcmp(*attr, "subsystems")) {
		*subsys = strtok_r(NULL, "/", &s);
		if (!*subsys)
			return -EINVAL;
		p = strtok_r(NULL, "/", &s);
		if (p) {
			*subsys = NULL;
			return -EINVAL;
		}
		*attr = NULL;
	} else if (!strcmp(*attr, "ana_groups")) {
		char *ana_grp;

		ana_grp = strtok_r(NULL, "/", &s);
		if (!ana_grp)
			return -EINVAL;
		id = strtoul(ana_grp, &eptr, 10);
		if (id == ULONG_MAX || ana_grp == eptr)
			return -EINVAL;
		*ana_grpid = id;
		p = strtok_r(NULL, "/", &s);
		if (!p) {
			*ana_grpid = 0;
			return -EINVAL;
		}
		p = strtok_r(NULL, "/", &s);
		if (p) {
			*ana_grpid = 0;
			return -EINVAL;
		}
		*attr = NULL;
	}
	return 0;
}

static void update_port(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	char *key, *attr = NULL, *subsys = NULL;
	unsigned int portid, ana_grpid = 0;
	int ret;

	key = strdup(kv->key);
	ret = parse_port_key(key + strlen(ctx->prefix), &portid, &attr,
			     &subsys, &ana_grpid);
	if (ret < 0) {
		free(key);
		return;
	}

	if (attr) {
		/* Only react on trsvcid */
		if (strcmp(attr, "addr_trsvcid")) {
			free(key);
			return;
		}
		if (strcmp(kv->value, "8009")) {
			printf("%s: ignore nvmet port %d\n",
			       __func__, portid);
			free(key);
			return;
		}
		printf("%s: op %s port %d attr %s\n", __func__,
		       kv->deleted ? "delete" : "add",
		       portid, attr);
		if (kv->deleted)
			find_and_del_port(portid);
		else
			find_and_add_port(ctx, portid);
	} else if (subsys) {
		struct nofuse_port *port;

		port = find_port(portid);
		if (port) {
			printf("%s port %d subsys %s\n",
			       kv->deleted ? "start" : "stop",
			       portid, subsys);
			if (!kv->deleted)
				start_port(port);
			else
				stop_port(port);
			put_port(port);
		}
	} else
		printf("add port %d ana group %d\n",
		       portid, ana_grpid);
	
	free(key);
}

static void delete_conn(void *arg)
{
	struct etcd_conn_ctx *conn = arg;

	etcd_conn_delete(conn);
}

static void *etcd_watcher(void *arg)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	int64_t start_revision = 0;
	char *prefix;
	int ret;

	ret = asprintf(&prefix, "%s/ports", ctx->prefix);
	if (ret < 0)
		return NULL;

	conn = etcd_conn_create(ctx);
	if (!conn)
		goto out;

	pthread_cleanup_push(delete_conn, conn);

	memset(&ev, 0, sizeof(ev));
	ev.ev_revision = start_revision;
	ev.watch_cb = update_port;
	ev.watch_arg = ctx;

	while (!stopped) {
		ret = etcd_kv_watch(conn, prefix, &ev, pthread_self());
		if (ret && ret != -ETIME)
			break;
	}
	if (ret && ret != -ETIME)
		fprintf(stderr, "%s: etcd_kv_watch failed with %d\n",
				__func__, ret);
	pthread_cleanup_pop(1);

out:
	free(prefix);
	pthread_exit(NULL);
	return NULL;
}

void usage(void) {
	printf("etcd_discovery - decentralized nvme discovery\n");
	printf("usage: etcd_discovery <args>\n");
	printf("Arguments are:\n");
	printf("\t[-p|--prefix] <prefix>\tetcd key prefix\n");
	printf("\t[-t|--ttl] <ttl>\tetcd TTL value\n");
	printf("\t[-u|--url] <url>\tetcd URL\n");
	printf("\t[-v|--verbose]\tVerbose output\n");
	printf("\t[-h|--help]\tThis help text\n");
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"prefix", required_argument, 0, 'p'},
		{"ttl", required_argument, 0, 't'},
		{"url", required_argument, 0, 'u'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, '?'},
	};
	static pthread_t watcher_thr, signal_thr;
	struct etcd_kv *kvs;
	sigset_t oldmask;
	char c;
	unsigned long ttl = 0;
	int getopt_ind;
	struct etcd_ctx *ctx;
	char *prefix = NULL, *eptr, *url = NULL;
	int ret = 0, i;

	while ((c = getopt_long(argc, argv, "p:t:u:v?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
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

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		exit(1);
	}

	ctx = etcd_init(url, prefix, NULL, ttl);
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		goto out_restore_sig;
	}

	if (!prefix) {
		prefix = ctx->prefix;
	} else {
		free(ctx->prefix);
	}
	asprintf(&ctx->prefix, "%s/ports/%s", prefix, ctx->node_name);
	printf("Using key %s\n", ctx->prefix);

	ret = etcd_kv_range(ctx, prefix, &kvs);
	if (ret < 0) {
		fprintf(stderr, "Failed to retrieve port information\n");
		goto out_free;
	}
	for (i = 0; i < ret; i++) {
		update_port(ctx, &kvs[i]);
	}
	etcd_kv_free(kvs, ret);

	ret = pthread_create(&watcher_thr, NULL, etcd_watcher, ctx);
	if (ret) {
		watcher_thr = 0;
		fprintf(stderr, "failed to start etcd watcher, error %d\n",
			ret);
		goto out_cleanup;
	}

	pthread_mutex_lock(&lock);
	while (!stopped)
		pthread_cond_wait(&wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);

	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

out_cleanup:
	cleanup_ports();
out_free:
	free(prefix);
	etcd_exit(ctx);

out_restore_sig:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return ret < 0 ? 1 : 0;
}
