/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_client.c
 * etcd v3 REST API implementation
 *
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <json-c/json.h>

#include "base64.h"

#include "common.h"
#include "etcd_client.h"

static char *default_etcd_prefix = "nofuse";
static char *default_etcd_host = "localhost";
static char *default_etcd_proto = "http";
static int default_etcd_port = 2379;
static int default_etcd_ttl = 60;

static char *__b64enc(const char *str, int str_len)
{
	int encoded_size = (str_len * 2) + 2, len;
	char *encoded_str = malloc(encoded_size + 1);

	if (!encoded_str)
		return NULL;
	memset(encoded_str, 0, encoded_size);
	len = base64_encode((unsigned char *)str, str_len, encoded_str);
	encoded_str[len] = '\0';
	return encoded_str;
}

static char *__b64dec(const char *encoded_str)
{
	int encoded_size = strlen(encoded_str), len;
	char *str = malloc(encoded_size + 1);

	if (!str)
		return NULL;

	memset(str, 0, encoded_size);
	len = base64_decode(encoded_str, encoded_size, (unsigned char *)str);
	str[len] = '\0';
	return str;
}

void etcd_kv_free(struct etcd_kv *kvs, int num_kvs)
{
	int i;

	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (kv->key)
			free(kv->key);
		if (kv->value)
			free(kv->value);
	}
	free(kvs);
}

void etcd_ev_free(struct etcd_kv_event *ev)
{
	if (ev->kvs) {
		etcd_kv_free(ev->kvs, ev->num_kvs);
		free(ev->kvs);
		ev->kvs = NULL;
		ev->num_kvs = 0;
	}
	if (ev->prev_kvs) {
		etcd_kv_free(ev->prev_kvs, ev->num_prev_kvs);
		free(ev->prev_kvs);
		ev->prev_kvs = NULL;
		ev->num_prev_kvs = 0;
	}
	ev->error = 0;
}

static void
etcd_parse_set_response(struct json_object *etcd_resp, void *arg)
{
	struct json_object *header_obj, *rev_obj;
	struct etcd_kv_event *ev = arg;

	if (!etcd_resp) {
		ev->error = -EBADMSG;
		return;
	}
	if (!ev->num_kvs) {
		ev->error = -EINVAL;
		return;
	}
	header_obj = json_object_object_get(etcd_resp, "header");
	if (!header_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'header' not found\n",
			       __func__);
		ev->error = -EBADMSG;
	} else {
		rev_obj = json_object_object_get(header_obj, "revision");
		if (rev_obj) {
			ev->ev_revision =
				json_object_get_int64(rev_obj);
		} else
			ev->ev_revision = -1;
	}
}

int etcd_kv_put(struct etcd_ctx *ctx, struct etcd_kv *kv)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	char *encoded_value = NULL;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	memset(&ev, 0, sizeof(ev));
	ev.ev_revision = -1;
	ev.kvs = kv;
	ev.num_kvs = 1;

	post_obj = json_object_new_object();
	encoded_key = __b64enc(kv->key, strlen(kv->key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	encoded_value = __b64enc(kv->value, strlen(kv->value));
	json_object_object_add(post_obj, "value",
			       json_object_new_string(encoded_value));
	if (kv->ignore_lease) {
		json_object_object_add(post_obj, "ignore_lease",
				       json_object_new_boolean(true));
	} else if (kv->lease) {
		json_object_object_add(post_obj, "lease",
				       json_object_new_int64(kv->lease));
	}
	ret = etcd_kv_exec(conn, "/v3/kv/put", post_obj,
			   etcd_parse_set_response, &ev);
	if (!ret) {
		if (ev.error < 0)
			ret = ev.error;
		else if (ev.ev_revision < 0)
			ret = -ENOMSG;
	}
	free(encoded_value);
	free(encoded_key);
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

static void
etcd_parse_kvs_response (struct json_object *etcd_resp, void *arg)
{
	struct json_object *header_obj, *kvs_obj;
	struct etcd_kv_event *ev = arg;
	int i;

	if (!etcd_resp) {
		ev->error = -EBADMSG;
		return;
	}
	header_obj = json_object_object_get(etcd_resp, "header");
	if (!header_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'header' not found\n",
			       __func__);
		ev->error = -EBADMSG;
	} else {
		struct json_object *rev_obj;

		rev_obj = json_object_object_get(header_obj, "revision");
		if (rev_obj) {
			ev->ev_revision =
				json_object_get_int64(rev_obj);
		} else
			ev->ev_revision = -1;
	}
	kvs_obj = json_object_object_get(etcd_resp, "kvs");
	if (!kvs_obj)
		return;

	ev->num_kvs = json_object_array_length(kvs_obj);
	ev->kvs = malloc(sizeof(struct etcd_kv) * ev->num_kvs);
	if (!ev->kvs) {
		if (etcd_debug)
			printf("%s: failed to allocate kvs\n", __func__);
		ev->error = -ENOMEM;
		ev->num_kvs = 0;
		return;
	}
	memset(ev->kvs, 0, sizeof(struct etcd_kv) * ev->num_kvs);
	for (i = 0; i < ev->num_kvs; i++) {
		struct etcd_kv *kv = &ev->kvs[i];
		struct json_object *kv_obj, *key_obj, *value_obj, *attr_obj;

		kv_obj = json_object_array_get_idx(kvs_obj, i);
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj)
			continue;
		kv->key = __b64dec(json_object_get_string(key_obj));
		value_obj = json_object_object_get(kv_obj, "value");
		if (value_obj) {
			kv->value = __b64dec(json_object_get_string(value_obj));
		}
		attr_obj = json_object_object_get(kv_obj, "create_revision");
		if (attr_obj) {
			kv->create_revision = json_object_get_int64(attr_obj);
		}
		attr_obj = json_object_object_get(kv_obj, "mod_revision");
		if (attr_obj) {
			kv->mod_revision = json_object_get_int64(attr_obj);
		}
		attr_obj = json_object_object_get(kv_obj, "version");
		if (attr_obj) {
			kv->version = json_object_get_int64(attr_obj);
		}
		if (etcd_debug)
			fprintf(stderr, "%s: key '%s', val '%s'\n",
				__func__, kv->key, kv->value);
	}
}

int etcd_kv_get(struct etcd_ctx *ctx, const char *key, char *value)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	int ret, i;

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	memset(&ev, 0, sizeof(ev));

	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));

	ret = etcd_kv_exec(conn, "/v3/kv/range", post_obj,
			   etcd_parse_kvs_response, &ev);
	if (ret)
		goto out_free;
	if (ev.error < 0) {
		ret = ev.error;
		goto out_free;
	}

	ret = -ENOENT;
	if (ev.num_kvs) {
		for (i = 0; i < ev.num_kvs; i++) {
			struct etcd_kv *kv = &ev.kvs[i];

			if (!strcmp(kv->key, key)) {
				if (value) {
					if (kv->value)
						strcpy(value, kv->value);
					else
						*value = '\0';
				}
				ret = 0;
				break;
			}
		}
		etcd_kv_free(ev.kvs, ev.num_kvs);
	}

out_free:
	free(encoded_key);
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

int etcd_kv_range(struct etcd_ctx *ctx, const char *key,
		  struct etcd_kv **ret_kvs)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL, end;
	char *encoded_range = NULL, *range;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	memset(&ev, 0, sizeof(ev));

	post_obj = json_object_new_object();
	range = strdup(key);
	end = range[strlen(range) - 1];
	end++;
	range[strlen(range) - 1] = end;
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	encoded_range = __b64enc(range, strlen(range));
	json_object_object_add(post_obj, "range_end",
			       json_object_new_string(encoded_range));

	ret = etcd_kv_exec(conn, "/v3/kv/range", post_obj,
			   etcd_parse_kvs_response, &ev);
	if (!ret) {
		ret = ev.error;
	}
	if (!ret && ev.num_kvs) {
		*ret_kvs = ev.kvs;
		ret = ev.num_kvs;
	} else
		*ret_kvs = NULL;

	free(encoded_range);
	free(encoded_key);
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

static void
etcd_parse_delete_response (struct json_object *etcd_resp, void *arg)
{
	struct etcd_kv_event *ev = arg;
	struct json_object *deleted_obj, *kvs_obj;
	int deleted = 0, i;

	if (!etcd_resp) {
		ev->error = -EBADMSG;
		return;
	}
	deleted_obj = json_object_object_get(etcd_resp, "deleted");
	if (!deleted_obj) {
		printf("%s: delete key failed, invalid key\n", __func__);
		ev->error = -ENOKEY;
		return;
	}
	deleted = json_object_get_int(deleted_obj);
	if (!deleted) {
		printf("%s: delete key failed, key not deleted\n",
		       __func__);
		ev->error = -EKEYREJECTED;
	}
	kvs_obj = json_object_object_get(etcd_resp, "prev_kvs");
	for (i = 0; i < deleted; i++) {
		struct json_object *kv_obj, *key_obj;

		kv_obj = json_object_array_get_idx(kvs_obj, i);
		key_obj = json_object_object_get(kv_obj, "key");
		if (key_obj) {
			char *key = __b64dec(json_object_get_string(key_obj));
			printf("%s: deleted %s\n", __func__, key);
			free(key);
		}
	}
}

int etcd_kv_delete(struct etcd_ctx *ctx, const char *key)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL, *end_key, *encoded_end, end;
	int ret;

	memset(&ev, 0, sizeof(ev));

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	end_key = strdup(key);
	end = key[strlen(key) - 1];
	end++;
	end_key[strlen(key) - 1] = end;
	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	encoded_end = __b64enc(end_key, strlen(end_key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	json_object_object_add(post_obj, "range_end",
			       json_object_new_string(encoded_end));
	json_object_object_add(post_obj, "prev_kv",
			       json_object_new_boolean(true));

	ret = etcd_kv_exec(conn, "/v3/kv/deleterange", post_obj,
			   etcd_parse_delete_response, &ev);
	if (!ret && ev.error < 0) {
		ret = ev.error;
	}
	free(encoded_end);
	free(encoded_key);
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

static void parse_watch_response(struct json_object *resp, void *arg)
{
	struct etcd_kv_event *ev = arg;
	json_object *result_obj, *rev_obj, *header_obj, *event_obj;
	int num_kvs, i;

	if (!resp)
		return;

	result_obj = json_object_object_get(resp, "result");
	if (!result_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'result' not found\n",
			       __func__);
		ev->error = -EBADMSG;
		return;
	}

	header_obj = json_object_object_get(result_obj, "header");
	if (!header_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'header' not found\n",
			       __func__);
		ev->error = -EBADMSG;
		return;
	}
	rev_obj = json_object_object_get(header_obj, "revision");
	if (rev_obj && ev) {
		ev->ev_revision = json_object_get_int64(rev_obj);

		if (etcd_debug)
			printf("%s: new revision %ld\n",
			       __func__, ev->ev_revision);
	}

	/* 'created' set in response to a 'WatchRequest', no data is pending */
	if (json_object_object_get(result_obj, "created")) {
		if (json_object_object_get(result_obj, "canceled")) {
			/* Watch got canceled */
			if (etcd_debug)
				printf("%s: watch canceled\n", __func__);
			ev->error = -ECANCELED;
		}
		return;
	}

	event_obj = json_object_object_get(result_obj, "events");
	if (!event_obj) {
		if (etcd_debug)
			printf("%s: empty response ('events' not found)\n",
			       __func__);
		return;
	}

	num_kvs = json_object_array_length(event_obj);
	for (i = 0; i < num_kvs; i++) {
		struct json_object *kvs_obj, *kv_obj, *key_obj;
		struct json_object *type_obj, *obj;
		struct etcd_kv kv;

		memset(&kv, 0, sizeof(kv));
		kvs_obj = json_object_array_get_idx(event_obj, i);
		type_obj = json_object_object_get(kvs_obj, "type");
		if (type_obj &&
		    !strcmp(json_object_get_string(type_obj), "DELETE"))
			kv.deleted = true;
		kv_obj = json_object_object_get(kvs_obj, "kv");
		if (!kv_obj)
			continue;
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj)
			continue;
		kv.key = __b64dec(json_object_get_string(key_obj));
		obj = json_object_object_get(kv_obj, "value");
		if (obj)
			kv.value = __b64dec(json_object_get_string(obj));
		obj = json_object_object_get(kv_obj, "create_revision");
		if (obj)
			kv.create_revision = json_object_get_int64(obj);
		obj = json_object_object_get(kv_obj, "mod_revision");
		if (obj)
			kv.mod_revision = json_object_get_int64(obj);
		obj = json_object_object_get(kv_obj, "version");
		if (obj)
			kv.version = json_object_get_int64(obj);
		obj = json_object_object_get(kv_obj, "lease");
		if (obj)
			kv.lease = json_object_get_int64(obj);
		if (ev && ev->watch_cb)
			ev->watch_cb(ev->watch_arg, &kv);
		if (kv.value)
			free(kv.value);
		free(kv.key);
	}
}

int etcd_kv_watch(struct etcd_conn_ctx *conn, const char *key,
		  struct etcd_kv_event *ev, int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	char *encoded_key, end;
	char *end_key, *encoded_end;
	int ret;

	post_obj = json_object_new_object();
	req_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(req_obj, "key",
			       json_object_new_string(encoded_key));
	end_key = strdup(key);
	end = end_key[strlen(end_key) - 1];
	end++;
	end_key[strlen(end_key) - 1] = end;
	encoded_end = __b64enc(end_key, strlen(end_key));
	json_object_object_add(req_obj, "range_end",
			       json_object_new_string(encoded_end));
	if (ev->ev_revision > 0)
		json_object_object_add(req_obj, "start_revision",
				       json_object_new_int64(ev->ev_revision));
	if (watch_id > 0)
		json_object_object_add(req_obj, "watch_id",
				       json_object_new_int64(watch_id));
	json_object_object_add(post_obj, "create_request", req_obj);

	ret = etcd_kv_exec(conn, "/v3/watch", post_obj,
			   parse_watch_response, ev);
	if (ret < 0) {
		printf("error %d executing watch request\n", ret);
	} else if (ev->error) {
		printf("watch response error %d\n", ev->error);
		ret = ev->error;
	}

	free(encoded_key);
	free(encoded_end);
	json_object_put(post_obj);
	return ret < 0 ? ret : 0;
}

static void
etcd_parse_lease_response(struct json_object *etcd_resp, void *arg)
{
	struct json_object *id_obj, *ttl_obj;
	struct etcd_kv_event *ev = arg;

	if (!etcd_resp) {
		ev->error = -EBADMSG;
		return;
	}
	id_obj = json_object_object_get(etcd_resp, "ID");
	if (!id_obj) {
		printf("%s: invalid response, 'ID' not found\n",
		       __func__);
		ev->error = -EBADMSG;
		return;
	}
	ev->kvs->lease = json_object_get_int64(id_obj);
	ttl_obj = json_object_object_get(etcd_resp, "TTL");
	if (!ttl_obj) {
		printf("%s: invalid response, 'TTL' not found\n",
		       __func__);
		ev->kvs->ttl = -1;
	} else {
		ev->kvs->ttl = json_object_get_int(ttl_obj);
	}
}

int etcd_lease_grant(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.kvs = malloc(sizeof(struct etcd_kv));
	if (!ev.kvs)
		return -ENOMEM;
	ev.num_kvs = 1;

	conn = etcd_conn_create(ctx);
	if (!conn) {
		free(ev.kvs);
		return -ENOMEM;
	}

	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(0));
	json_object_object_add(post_obj, "TTL",
			       json_object_new_int(ctx->ttl));

	ret = etcd_kv_exec(conn, "/v3/lease/grant", post_obj,
			   etcd_parse_lease_response, &ev);
	if (!ret) {
		if (ev.error < 0) {
			fprintf(stderr, "lease error %d\n", ret);
			ret = ev.error;
		} else if (!ev.kvs->lease) {
			fprintf(stderr, "no lease has been granted\n");
			ret = -ENOKEY;
		} else if (ev.kvs->ttl < 0) {
			fprintf(stderr, "invalid time-to-live value\n");
			ret = -EINVAL;
		} else {
			ctx->lease = ev.kvs->lease;
			ctx->ttl = ev.kvs->ttl;
			printf("Granted lease %ld ttl %d\n",
			       ctx->lease, ctx->ttl);
		}
	} else {
		fprintf(stderr, "etcd lease call failed with %d\n", ret);
	}
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	free(ev.kvs);
	return ret;
}

static void
etcd_parse_keepalive_response(struct json_object *etcd_resp, void *arg)
{
	struct json_object *result_obj;
	struct etcd_kv_event *ev = arg;
	struct json_object *id_obj, *ttl_obj;
	int64_t lease;

	if (!etcd_resp) {
		printf("%s: keepalive failed, not valid json response\n",
		       __func__);
		ev->error = -EBADMSG;
		return;
	}
	result_obj = json_object_object_get(etcd_resp, "result");
	if (!result_obj) {
		printf("%s: keepalive failed, 'result' not found\n",
		       __func__);
		ev->error = -EBADMSG;
		return;
	}
	id_obj = json_object_object_get(result_obj, "ID");
	if (!id_obj) {
		printf("%s: keepalive failed, 'ID' not found\n",
		       __func__);
		ev->error = -EBADMSG;
		return;
	}
	lease = json_object_get_int64(id_obj);
	if (lease != ev->kvs->lease) {
		printf("%s: keepalive failed, lease mismatch\n", __func__);
		ev->error = -EKEYREJECTED;
		return;
	}
	ttl_obj = json_object_object_get(result_obj, "TTL");
	if (!ttl_obj) {
		printf("%s: lease expired\n", __func__);
		ev->error = -EKEYEXPIRED;
	} else if (ev->num_kvs) {
		ev->kvs->ttl = json_object_get_int64(ttl_obj);
	}
}

int etcd_lease_keepalive(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj;
	int ret;

	if (!ctx->lease) {
		printf("%s: no lease granted\n", __func__);
		return -ENOKEY;
	}
	memset(&ev, 0, sizeof(ev));
	ev.kvs = malloc(sizeof(struct etcd_kv));
	if (!ev.kvs)
		return -ENOMEM;
	memset(ev.kvs, 0, sizeof(struct etcd_kv));
	ev.num_kvs = 1;
	ev.kvs->lease = ctx->lease;

	conn = etcd_conn_create(ctx);
	if (!conn) {
		free(ev.kvs);
		return -ENOMEM;
	}

	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));
	json_object_object_add(post_obj, "TTL",
			       json_object_new_int(ctx->ttl));

	ret = etcd_kv_exec(conn, "/v3/lease/keepalive", post_obj,
			   etcd_parse_keepalive_response, &ev);
	if (!ret) {
		if (ev.error < 0) {
			printf("%s: etcd error %d\n", __func__, ev.error);
			ret = ev.error;
		} else if (ev.kvs->ttl != ctx->ttl) {
			printf("%s: ttl update to %ld\n",
			       __func__, ev.kvs->ttl);
			ctx->ttl = ev.kvs->ttl;
		}
	} else
		printf("%s: etcd_kv_exec error %d\n", __func__, ret);

	json_object_put(post_obj);
	etcd_conn_delete(conn);
	free(ev.kvs);
	return ret;
}

int etcd_lease_timetolive(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj;
	int ret;

	if (!ctx->lease) {
		printf("%s: no lease granted\n", __func__);
		return -ENOKEY;
	}
	memset(&ev, 0, sizeof(ev));
	ev.kvs = malloc(sizeof(struct etcd_kv));
	ev.num_kvs = 1;
	ev.kvs->lease = ctx->lease;

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));

	ret = etcd_kv_exec(conn, "/v3/lease/timetolive", post_obj,
			   etcd_parse_keepalive_response, &ev);
	if (!ret) {
		if (ev.error < 0) {
			ret = ev.error;
		}
	}

	json_object_put(post_obj);
	free(ev.kvs);
	etcd_conn_delete(conn);
	return ret;
}

static void
etcd_parse_revoke_response(struct json_object *etcd_resp, void *arg)
{
	struct json_object *error_obj;
	struct etcd_kv_event *ev = arg;

	if (!etcd_resp) {
		ev->error = -EBADMSG;
		return;
	}
	/* Revoke response */
	error_obj = json_object_object_get(etcd_resp, "error");
	if (error_obj) {
		const char *err_str = json_object_get_string(error_obj);

		printf("%s: revoke error '%s'\n",
		       __func__, err_str);
		ev->error = -EINVAL;
	} else {
		ev->error = 0;
	}
}

int etcd_lease_revoke(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	struct json_object *post_obj;
	int ret;

	if (!ctx->lease) {
		printf("%s: no lease granted\n", __func__);
		return -ENOKEY;
	}

	memset(&ev, 0, sizeof(ev));

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));
	ret = etcd_kv_exec(conn, "/v3/lease/revoke", post_obj,
			   etcd_parse_revoke_response, &ev);
	if (!ret && ev.error < 0)
		ret = ev.error;

	if (!ret)
		ctx->lease = 0;
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

static void
etcd_parse_member_response (struct json_object *etcd_resp, void *arg)
{
	struct json_object *hdr_obj, *mbs_obj;
	struct etcd_ctx *ctx = arg;
	char *default_url;
	int i, ret;

	if (!etcd_resp)
		return;

	ret = asprintf(&default_url, "%s://%s:%d",
		       ctx->proto, ctx->host, ctx->port);
	if (ret < 0) {
		printf("%s: out of memory\n", __func__);
		return;
	}

	hdr_obj = json_object_object_get(etcd_resp, "header");
	if (!hdr_obj) {
		printf("%s: invalid response, 'header' not found\n",
		       __func__);
		free(default_url);
		return;
	}
	mbs_obj = json_object_object_get(etcd_resp, "members");
	if (!mbs_obj) {
		printf("%s: invalid response, 'members' not found\n",
		       __func__);
		free(default_url);
		return;
	}

	for (i = 0; i < json_object_array_length(mbs_obj); i++) {
		struct json_object *mb_obj, *name_obj, *id_obj, *urls_obj;
		const char *node_name, *node_id;
		int j;

		mb_obj = json_object_array_get_idx(mbs_obj, i);
		if (!mb_obj)
			continue;
		name_obj = json_object_object_get(mb_obj, "name");
		if (!name_obj)
			continue;
		node_name = json_object_get_string(name_obj);

		id_obj = json_object_object_get(mb_obj, "ID");
		if (!id_obj)
			continue;
		node_id = json_object_get_string(id_obj);

		urls_obj = json_object_object_get(mb_obj, "clientURLs");
		for (j = 0; j < json_object_array_length(urls_obj); j++) {
			struct json_object *url_obj;
			const char *url;

			url_obj = json_object_array_get_idx(urls_obj, j);
			url = json_object_get_string(url_obj);

			if (!strcmp(url, default_url)) {
				ctx->node_name = strdup(node_name);
				ctx->node_id = strdup(node_id);
				if (etcd_debug)
					printf("%s: using node name %s (id %s)\n",
					       __func__,
					       ctx->node_name,
					       ctx->node_id);
			}
		}
	}
	free(default_url);
}

int etcd_member_id(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;
	struct json_object *post_obj;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn)
		return -ENOMEM;

	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "linearizable",
			       json_object_new_boolean(true));

	ret = etcd_kv_exec(conn, "/v3/cluster/member/list", post_obj,
			   etcd_parse_member_response, ctx);
	if (!ret && !ctx->node_name)
		ret = -ENOENT;
	json_object_put(post_obj);
	etcd_conn_delete(conn);
	return ret;
}

struct etcd_ctx *etcd_init(const char *prefix, unsigned int ttl)
{
	struct etcd_ctx *ctx;
	int ret;

	ctx = malloc(sizeof(struct etcd_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		return NULL;
	}
	memset(ctx, 0, sizeof(struct etcd_ctx));
	ctx->host = strdup(default_etcd_host);
	ctx->proto = strdup(default_etcd_proto);
	ctx->port = default_etcd_port;
	if (prefix)
		ctx->prefix = strdup(prefix);
	else
		ctx->prefix = strdup(default_etcd_prefix);
	ctx->configfs = strdup(NVMET_CONFIGFS);
	ctx->lease = 0;
	ctx->ttl = ttl > 0 ? ttl : default_etcd_ttl;
	pthread_mutex_init(&ctx->conn_mutex, NULL);

	if (etcd_debug)
		printf("%s: using prefix '%s'\n", __func__, ctx->prefix);
	ret = etcd_member_id(ctx);
	if (ret < 0) {
		etcd_exit(ctx);
		errno = -ret;
		return NULL;
	}
	return ctx;
}

void etcd_exit(struct etcd_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->node_name)
		free(ctx->node_name);
	free(ctx->configfs);
	free(ctx->prefix);
	free(ctx->host);
	free(ctx->proto);
	free(ctx);
}

struct etcd_conn_ctx *etcd_conn_create(struct etcd_ctx *ctx)
{
	struct etcd_conn_ctx *conn;

	conn = malloc(sizeof(struct etcd_conn_ctx));
	if (!conn) {
		fprintf(stderr, "cannot allocate context\n");
		return NULL;
	}
	memset(conn, 0, sizeof(*conn));
	conn->ctx = ctx;

	if (etcd_conn_init(conn) < 0) {
		free(conn);
		return NULL;
	}

	pthread_mutex_lock(&ctx->conn_mutex);
	if (!ctx->conn)
		ctx->conn = conn;
	else {
		struct etcd_conn_ctx *c = ctx->conn;

		while (c->next)
			c = c->next;
		c->next = conn;
	}
	pthread_mutex_unlock(&ctx->conn_mutex);
	return conn;
}

void etcd_conn_delete(struct etcd_conn_ctx *conn)
{
	struct etcd_ctx *ctx = conn->ctx;

	pthread_mutex_lock(&ctx->conn_mutex);
	if (ctx->conn) {
		if (ctx->conn == conn) {
			if (conn->next) {
				ctx->conn = conn->next;
				conn->next = NULL;
			} else
				ctx->conn = NULL;
		} else {
			struct etcd_conn_ctx *c = ctx->conn;

			while (c->next && c->next != conn)
				c = c->next;
			if (c->next == conn) {
				c->next = conn->next;
				conn->next = NULL;
			}
		}
	}
	pthread_mutex_unlock(&ctx->conn_mutex);
	etcd_conn_exit(conn);
	free(conn);
}
