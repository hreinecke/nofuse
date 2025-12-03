/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * discd.c
 * Manage discovery information by watching keys in etcd
 *
 * Copyright (c) 2025 Hannes Reinecke <hare@suse.de>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>

#include "common.h"
#include "etcd_client.h"
#include "configfs.h"

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

static int discd_get_port_attrs(struct etcd_ctx *ctx, char *port,
				char **trtype, char **traddr, char **trsvcid)
{
	DIR *sd;
	struct dirent *se;
	char *dirname, *path, value[1024];
	int ret, num = 0;

	ret = asprintf(&dirname, "%s/ports/%s", ctx->configfs, port);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open '%s'\n", dirname);
		free(dirname);
		return -errno;
	}
	*trtype = NULL;
	*traddr = NULL;
	*trsvcid = NULL;

	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		ret = asprintf(&path, "%s/%s", dirname, se->d_name);
		if (ret < 0)
			continue;
		if (!strcmp(se->d_name, "addr_trtype")) {
			ret = read_attr(path, value, 1024);
			if (ret < 0) {
				fprintf(stderr,
					"Failed to read '%s', error %d\n",
					path, errno);
				free(path);
				continue;
			}
			*trtype = strdup(value);
			num++;
		}
		if (!strcmp(se->d_name, "addr_trtype")) {
			ret = read_attr(path, value, 1024);
			if (ret < 0) {
				fprintf(stderr,
					"Failed to read '%s', error %d\n",
					path, errno);
				free(path);
				continue;
			}
			*traddr = strdup(value);
			num++;
		}
		if (!strcmp(se->d_name, "addr_trsvcid")) {
			ret = read_attr(path, value, 1024);
			if (ret < 0) {
				fprintf(stderr,
					"Failed to read '%s', error %d\n",
					path, errno);
				free(path);
				continue;
			}
			*trsvcid = strdup(value);
			num++;
		}
		free(path);
	}
	closedir(sd);
	free(dirname);
	if (ret < 0 || num != 3) {
		if (*trtype) {
			free(*trtype);
			*trtype = NULL;
		}
		if (*traddr) {
			free(*traddr);
			*traddr = NULL;
		}
		if (*trsvcid) {
			free(*trsvcid);
			*trsvcid = NULL;
		}
		return ret;
	}
	return 0;
}
		
static int discd_find_ports(struct etcd_ctx *ctx, char *port, char **found)
{
	DIR *sd;
	struct dirent *se;
	char *trtype, *traddr, *trsvcid;
	char *path;
	int ret, num = 0;

	ret = discd_get_port_attrs(ctx, port, &trtype, &traddr, &trsvcid);
	if (ret < 0)
		return ret;
	
	ret = asprintf(&path, "%s/ports", ctx->configfs);
	if (ret < 0) {
		ret = -ENOMEM;
		goto out_free;
	}
	sd = opendir(path);
	if (!sd) {
		fprintf(stderr, "Cannot open '%s'\n", path);
		free(path);
		ret = -errno;
		goto out_free;
	}
	while ((se = readdir(sd))) {
		char *tt, *ta, *ts;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (se->d_type != DT_DIR)
			continue;
		if (!strcmp(se->d_name, port))
			continue;
		ret = discd_get_port_attrs(ctx, se->d_name,
					   &tt, &ta, &ts);
		if (ret < 0)
			continue;
		if (strcmp(tt, trtype))
			continue;
		if (strcmp(ta, traddr))
			continue;
		num++;
		if (strcmp(ts, "8009"))
			*found = strdup(se->d_name);
		free(tt);
		free(ta);
		free(ts);
	}
out_free:
	free(trtype);
	free(traddr);
	free(trsvcid);

	return ret < 0 ? ret : num;
}

static int parse_port_key(char *key, char **port, char **attr,
			  char **subsys, unsigned int *ana_grpid)
{
	char *p, *s, *eptr = NULL;
	unsigned long id;

	*port = strtok_r(key, "/", &s);
	if (!*port)
		return -EINVAL;
	*attr = strtok_r(NULL, "/", &s);
	if (!*attr) {
		*port = 0;
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

static void discd_update_port(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	char *key, *port = NULL, *attr = NULL, *subsys = NULL;
	char *disc_portid = NULL;
	unsigned int ana_grpid = 0;
	int ret;

	key = strdup(kv->key);
	ret = parse_port_key(key + strlen(ctx->prefix), &port, &attr,
			     &subsys, &ana_grpid);
	if (ret < 0) {
		free(key);
		return;
	}

	if (attr) {
		if (kv->deleted && strcmp(attr, "addr_trsvcid")) {
			/* Only trigger on 'trsvcid' for deleting */
			free(key);
			return;
		}

		printf("%s: op %s port %s attr %s\n", __func__,
		       kv->deleted ? "delete" : "add",
		       port, attr);
		ret = discd_find_ports(ctx, port, &disc_portid);
		if (ret < 0) {
			free(key);
			return;
		}
		if (kv->deleted) {
			if (ret > 1) {
				printf("%s: skip deletion, %d ports active\n",
				       __func__, ret);
			} else if (disc_portid) {
				printf("%s: delete discovery port %s\n",
				       __func__, disc_portid);
				free(disc_portid);
			} else {
				printf("%s: no discovery port to delete\n",
				       __func__);
			}
		} else {
			if (ret == 0) {
				printf("%s: no ports found, skip creation\n",
				       __func__);
			} else if (disc_portid) {
				printf("%s: skip creation, using port %s\n",
				       __func__, disc_portid);
				free(disc_portid);
			} else {
				printf("%s: create discovery port, %d ports active\n",
				       __func__, ret);
			}
		}
	} else if (subsys) {
		ret = discd_find_ports(ctx, port, &disc_portid);
		if (disc_portid) {
			printf("%s port %s subsys %s\n",
			       kv->deleted ? "start" : "stop",
			       port, subsys);
#if 0
			if (!kv->deleted)
				discd_enable_port(ctx, port);
			else
				discd_disable_port(ctx, port);
			put_port(port);
#endif
			free(disc_portid);
		}
	} else
		printf("add port %s ana group %d\n",
		       port, ana_grpid);
	
	free(key);
}

static void discd_cleanup_ports(struct etcd_ctx *ctx)
{
	char *path;
	DIR *sd;
	struct dirent *se;
	int ret;

	ret = asprintf(&path, "%s/ports", ctx->configfs);
	if (ret < 0)
		return;

	sd = opendir(path);
	if (!sd) {
		fprintf(stderr, "Cannot open '%s'\n", path);
		goto out_free;
	}
	while ((se = readdir(sd))) {
		char *tt, *ta, *ts;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (se->d_type != DT_DIR)
			continue;
		ret = discd_get_port_attrs(ctx, se->d_name,
					   &tt, &ta, &ts);
		if (ret < 0)
			continue;
		if (strcmp(ts, "8009")) {
			printf("%s: remove port %s\n",
			       __func__, se->d_name);
		}
		free(tt);
		free(ta);
		free(ts);
	}
out_free:
	free(path);
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
	ev.watch_cb = discd_update_port;
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
	printf("\t[-n|--node] <name>\tetcd node name\n");
	printf("\t[-p|--prefix] <prefix>\tetcd key prefix\n");
	printf("\t[-t|--ttl] <ttl>\tetcd TTL value\n");
	printf("\t[-u|--url] <url>\tetcd URL\n");
	printf("\t[-v|--verbose]\tVerbose output\n");
	printf("\t[-h|--help]\tThis help text\n");
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"node", required_argument, 0, 'n'},
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
	char *node_name = NULL, *prefix = NULL, *eptr, *url = NULL;
	int ret = 0, i;

	while ((c = getopt_long(argc, argv, "n:p:t:u:v?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
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
			configfs_debug = true;
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

	ctx = etcd_init(url, node_name, prefix, NULL, ttl);
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
		discd_update_port(ctx, &kvs[i]);
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
		pthread_cond_wait(&cond_wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);

	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

out_cleanup:
	discd_cleanup_ports(ctx);
out_free:
	free(prefix);
	etcd_exit(ctx);

out_restore_sig:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return ret < 0 ? 1 : 0;
}
