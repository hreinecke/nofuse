/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_client.h
 * etcd v3 REST API implementation
 *
 */

#ifndef _ETCD_CLIENT_H
#define _ETCD_CLIENT_H

#include <curl/curl.h>
#include <curl/easy.h>

enum kv_key_op {
	KV_KEY_OP_ADD,
	KV_KEY_OP_DELETE,
	KV_KEY_OP_GET,
	KV_KEY_OP_RANGE,
	KV_KEY_OP_WATCH,
};

struct etcd_kv {
	const char *key;
	const char *value;
	int64_t create_revision;
	int64_t mod_revision;
	int64_t version;
	int64_t lease;
	bool ignore_lease;
};

struct etcd_kv_event {
	enum kv_key_op type;
	struct etcd_kv kv;
	struct etcd_kv prev_kv;
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
	int64_t revision;
	int ttl;
	CURL *curl_ctx;
	struct etcd_kv *resp_kvs;
	int resp_val;
	struct json_tokener *tokener;
	void (*watch_cb)(struct etcd_ctx *, enum kv_key_op,
			 char *, const char *);
};

extern bool etcd_debug;
extern bool curl_debug;

struct etcd_ctx *etcd_init(const char *prefix);
struct etcd_ctx *etcd_dup(struct etcd_ctx *ctx);
void etcd_exit(struct etcd_ctx *ctx);
int etcd_kv_put(struct etcd_ctx *ctx, struct etcd_kv *kv);

static inline int etcd_kv_update(struct etcd_ctx *ctx, const char *key,
				 const char *value)
{
	struct etcd_kv kv = {
		.key = key,
		.value = value,
		.ignore_lease = true,
		.lease = 0,
	};
	return etcd_kv_put(ctx, &kv);
}

static inline int etcd_kv_new(struct etcd_ctx *ctx, const char *key,
			      const char *value)
{
	struct etcd_kv kv = {
		.key = key,
		.value = value,
		.ignore_lease = false,
		.lease = 0,
	};
	return etcd_kv_put(ctx, &kv);
}

int etcd_kv_get(struct etcd_ctx *ctx, const char *key, char *value);
int etcd_kv_range(struct etcd_ctx *ctx, const char *key,
		  struct etcd_kv **ret_kvs);
int etcd_kv_delete(struct etcd_ctx *ctx, const char *key);
int etcd_kv_watch(struct etcd_ctx *ctx, const char *key);
void etcd_kv_watch_stop(struct etcd_ctx *ctx);

int etcd_lease_grant(struct etcd_ctx *ctx);
int etcd_lease_keepalive(struct etcd_ctx *ctx);
int etcd_lease_revoke(struct etcd_ctx *ctx);

#endif /* _ETCD_CLIENT_H */
