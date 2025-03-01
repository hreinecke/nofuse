/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_client.h
 * etcd v3 REST API implementation
 *
 */

#ifndef _ETCD_CLIENT_H
#define _ETCD_CLIENT_H

#include <json-c/json.h>
#ifdef _USE_CURL
#include <curl/curl.h>
#include <curl/easy.h>
#endif

typedef void (*etcd_parse_cb)(struct json_object *obj, void *arg);

struct etcd_parse_data {
	struct json_tokener *tokener;
	void (*parse_cb)(struct json_object *obj, void *arg);
	void *parse_arg;
	char *uri;
	char *data;
	size_t len;
};

struct etcd_ctx {
	char *prefix;
	char *proto;
	char *host;
	char *node_name;
	char *node_id;
	int port;
	bool tls;
	int64_t lease;
	int ttl;
	pthread_mutex_t conn_mutex;
	struct etcd_conn_ctx *conn;
};

struct etcd_conn_ctx {
	struct etcd_ctx *ctx;
	struct etcd_conn_ctx *next;
	int sockfd;
	void *priv;
	int64_t revision;
	int64_t watch_id;
};

struct etcd_kv {
	char *key;
	char *value;
	int64_t create_revision;
	int64_t mod_revision;
	int64_t version;
	int64_t lease;
	int64_t ttl;
	bool ignore_lease;
	bool deleted;
};

struct etcd_kv_event {
	int64_t ev_revision;
	int error;
	struct etcd_kv *kvs;
	int num_kvs;
	struct etcd_kv *prev_kvs;
	int num_prev_kvs;
	void (*watch_cb)(void *arg, struct etcd_kv *kv);
	void *watch_arg;
};

extern bool etcd_debug;
extern bool http_debug;

struct etcd_ctx *etcd_init(const char *prefix);
void etcd_exit(struct etcd_ctx *ctx);
struct etcd_conn_ctx *etcd_conn_create(struct etcd_ctx *ctx);
int etcd_conn_init(struct etcd_conn_ctx *conn);
void etcd_conn_exit(struct etcd_conn_ctx *conn);
void etcd_conn_delete(struct etcd_conn_ctx *ctx);
void etcd_kv_free(struct etcd_kv *kvs, int num_kvs);
void etcd_ev_free(struct etcd_kv_event *ev);

int etcd_kv_exec(struct etcd_conn_ctx *conn, char *uri,
		 struct json_object *post_obj,
		 etcd_parse_cb parse_cb, void *parse_arg);

int etcd_kv_put(struct etcd_ctx *ctx, struct etcd_kv *kv);

static inline int etcd_kv_update(struct etcd_ctx *ctx, const char *key,
				 const char *value)
{
	struct etcd_kv kv = {
		.key = (char *)key,
		.value = (char *)value,
		.ignore_lease = true,
	};
	return etcd_kv_put(ctx, &kv);
}

static inline int etcd_kv_new(struct etcd_ctx *ctx, const char *key,
			      const char *value)
{
	struct etcd_kv kv = {
		.key = (char *)key,
		.value = (char *)value,
		.ignore_lease = false,
		.lease = ctx->lease,
	};
	if (!ctx->lease) {
		if (etcd_debug)
			printf("%s: no lease\n", __func__);
		return -EINVAL;
	}
	return etcd_kv_put(ctx, &kv);
}

static inline int etcd_kv_store(struct etcd_ctx *ctx, const char *key,
				const char *value)
{
	struct etcd_kv kv = {
		.key = (char *)key,
		.value = (char *)value,
		.ignore_lease = false,
	};
	return etcd_kv_put(ctx, &kv);
}

int etcd_kv_get(struct etcd_ctx *ctx, const char *key, char *value);
int etcd_kv_range(struct etcd_ctx *ctx, const char *key,
		  struct etcd_kv **ret_kvs);
int etcd_kv_delete(struct etcd_ctx *ctx, const char *key);

int etcd_kv_watch(struct etcd_conn_ctx *conn, const char *key,
		  struct etcd_kv_event *ev, int64_t watch_id);

void etcd_watch_cb(void *arg, struct etcd_kv *kv);

int etcd_lease_grant(struct etcd_ctx *ctx);
int etcd_lease_keepalive(struct etcd_ctx *ctx);
int etcd_lease_revoke(struct etcd_ctx *ctx);

#endif /* _ETCD_CLIENT_H */
