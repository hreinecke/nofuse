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
bool curl_debug;

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

	/* prefix */
	p = strtok_r(key, "/", &s);
	if (!p)
		return -EINVAL;
	/* 'ports' */
	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -EINVAL;
	port = strtok_r(NULL, "/", &s);
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

static void update_ports(struct etcd_conn_ctx *conn,
			 struct etcd_kv *kv)
{
	char *key_save, *attr, *subsys = NULL;
	unsigned int portid, ana_grpid = 0;
	int ret;

	key_save = strdup(kv->key);
	if (strncmp(key_save, conn->ctx->prefix, strlen(conn->ctx->prefix))) {
		fprintf(stderr, "Skip invalid prefix '%s'\n", kv->key);
		free(key_save);
		return;
	}
	ret = parse_port_key(key_save, &portid, &attr,
			     &subsys, &ana_grpid);
	if (ret < 0)
		goto out_free;

	if (attr) {
		printf("%s: op %s port %d attr %s\n", __func__,
		       kv->deleted ? "delete" : "add",
		       portid, attr);
		if (!kv->deleted)
			find_and_add_port(conn->ctx, portid);
		else if (!strcmp(attr, "addr_traddr"))
			find_and_del_port(portid);
	} else if (subsys) {
		struct nofuse_port *port;

		printf("%s: op %s port %d subsys %s\n",
		       __func__, kv->deleted ? "delete" : "add",
		       portid, subsys);
		port = find_port(portid);
		if (!port) {
			printf("%s: no port found\n", __func__);
			goto out_free;
		}
		if (!kv->deleted) {
			start_port(port);
		} else {
			stop_port(port);
		}
		put_port(port);
	} else {
		printf("%s: op %s port %d ana group %d\n", __func__,
		       kv->deleted ? "delete" : "add",
		       portid, ana_grpid);
	}
out_free:
	free(key_save);
}

static void parse_ports(struct etcd_ctx *ctx,
			struct etcd_kv *kvs, int num_kvs)
{
	struct nofuse_port *port;
	int i;

	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *key, *attr = NULL, *subsys = NULL;
		unsigned int portid, ana_grpid = 0;

		key = strdup(kv->key);
		if (!parse_port_key(key, &portid, &attr,
				    &subsys, &ana_grpid)) {
			if (subsys) {
				port = find_port(portid);
				if (port) {
					printf("start port %d subsys %s\n",
					       portid, subsys);
					start_port(port);
					put_port(port);
				}
			} else if (ana_grpid)
				printf("add port %d ana group %d\n",
				       portid, ana_grpid);
			else {
				find_and_add_port(ctx, portid);
				printf("add port %d attr %s\n",
				       portid, attr);
			}
		}
		free(key);
		free((char *)kv->key);
		free((char *)kv->value);
	}
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
	struct etcd_kv *kvs;
	char *prefix;
	int64_t start_revision = 0;
	int ret;

	ret = asprintf(&prefix, "%s/ports", ctx->prefix);
	if (ret < 0)
		return NULL;

	while (!stopped) {
		conn = etcd_conn_create(ctx);
		if (!conn)
			break;

		pthread_cleanup_push(delete_conn, conn);

		conn->watch_id = pthread_self();
		conn->revision = start_revision;

		ret = etcd_kv_watch(conn, prefix, &kvs);
		if (ret < 0)
			fprintf(stderr, "%s: etcd_kv_watch failed with %d\n",
				__func__, ret);

		if (ret > 0) {
			int i;

			for (i = 0; i < ret; i++) {
				struct etcd_kv *kv = &kvs[i];

				update_ports(conn, kv);
				free((char *)kv->key);
				if (kv->value)
					free((char *)kv->value);
			}
			free(kvs);
		}
		if (conn->resp_ev.ev_revision > 0) {
			start_revision = conn->resp_ev.ev_revision;
			conn->resp_ev.ev_revision = 0;
			fprintf(stderr, "%s: new start rev %ld\n",
				__func__, start_revision);
		}
		pthread_cleanup_pop(1);
	}

	free(prefix);
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
	static pthread_t watcher_thr, signal_thr;
	struct etcd_kv *kvs;
	sigset_t oldmask;
	char c;
	int getopt_ind;
	struct etcd_ctx *ctx;
	char *prefix;
	int ret = 0;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		exit(1);
	}

	ctx = etcd_init(NULL);
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		goto out_restore_sig;
	}

	while ((c = getopt_long(argc, argv, "ae:p:h:sv?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'e':
			free(ctx->prefix);
			ctx->prefix = strdup(optarg);
			break;
		case 'h':
			free(ctx->host);
			ctx->host = strdup(optarg);
			break;
		case 'p':
			ctx->port = atoi(optarg);
			break;
		case 's':
			ctx->proto = strdup("https");
			break;
		case 'v':
			etcd_debug = true;
			port_debug = true;
			ep_debug = true;
			break;
		case '?':
			usage();
			sigprocmask(SIG_SETMASK, &oldmask, NULL);
			return 0;
		}
	}

	asprintf(&prefix, "%s/ports", ctx->prefix);
	printf("Using key %s\n", prefix);

	ret = etcd_kv_range(ctx, prefix, &kvs);
	if (ret < 0) {
		fprintf(stderr, "Failed to retrieve port information\n");
		goto out_free;
	}

	parse_ports(ctx, kvs, ret);
	free(kvs);

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

	etcd_kv_watch_cancel(ctx, watcher_thr);

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
