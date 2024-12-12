/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_client.c
 * etcd v3 REST API implementation
 *
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "base64.h"

#include "etcd_client.h"

static char *default_etcd_prefix = "nofuse";
static char *default_etcd_host = "localhost";
static char *default_etcd_proto = "http";
static int default_etcd_port = 2379;

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

static size_t
etcd_parse_range_response (char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *kvs_obj;
	struct etcd_ctx *ctx = arg;
	int i;

	etcd_resp = json_tokener_parse_ex(ctx->tokener, ptr,
					  size * nmemb);
	if (!etcd_resp) {
		if (json_tokener_get_error(ctx->tokener) == json_tokener_continue) {
			/* Partial / chunked response; continue */
			return size * nmemb;
		}
		if (etcd_debug)
			printf("%s: ERROR:\n%s\n", __func__, ptr);

		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		return 0;
	}
	if (etcd_debug)
		printf("%s: DATA:\n%s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));
	kvs_obj = json_object_object_get(etcd_resp, "kvs");
	if (!kvs_obj)
		goto out;

	for (i = 0; i < json_object_array_length(kvs_obj); i++) {
		struct json_object *kv_obj, *key_obj, *value_obj;
		char *key_str, *value_str;

		kv_obj = json_object_array_get_idx(kvs_obj, i);
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj)
			continue;
		value_obj = json_object_object_get(kv_obj, "value");
		if (!value_obj)
			continue;
		key_str = __b64dec(json_object_get_string(key_obj));
		value_str = __b64dec(json_object_get_string(value_obj));
		if (etcd_debug)
			fprintf(stderr, "%s: key '%s', val '%s'\n",
				__func__, key_str, value_str);
		json_object_object_add(ctx->resp_obj, key_str,
				       json_object_new_string(value_str));
		free(value_str);
		free(key_str);
	}
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

static CURL *etcd_curl_init(struct etcd_ctx *ctx)
{
	CURL *curl;
	CURLoption opt;
	CURLcode err;

	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl easy init failed\n");
		return NULL;
	}

	opt = CURLOPT_FOLLOWLOCATION;
	err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_FORBID_REUSE;
	err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_POST;
	err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_WRITEDATA;
	err = curl_easy_setopt(curl, opt, ctx);
	if (err != CURLE_OK)
		goto out_err_opt;
	if (ctx->ttl > 0) {
		opt = CURLOPT_TIMEOUT;
		err = curl_easy_setopt(curl, opt, ctx->ttl);
	}
	if (err != CURLE_OK)
		goto out_err_opt;
	if (curl_debug)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	return curl;

out_err_opt:
	fprintf(stderr, "curl setopt %d, error %d: %s\n",
		opt, err, curl_easy_strerror(err));
	curl_easy_cleanup(curl);
	return NULL;
}

int etcd_kv_exec(struct etcd_ctx *ctx, char *url,
		 struct json_object *post_obj, curl_write_callback write_cb)
{
	CURLcode err;
	const char *post_data;

	ctx->curl_ctx = etcd_curl_init(ctx);
	if (!ctx->curl_ctx)
		return -ENOMEM;

	err = curl_easy_setopt(ctx->curl_ctx, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s\n",
			curl_easy_strerror(err));
		err = EINVAL;
		goto err_out;
	}
	err = curl_easy_setopt(ctx->curl_ctx, CURLOPT_WRITEFUNCTION, write_cb);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s\n",
			curl_easy_strerror(err));
		err = EINVAL;
		goto err_out;
	}

	if (etcd_debug)
		printf("%s: POST:\n%s\n", __func__,
		       json_object_to_json_string_ext(post_obj,
						      JSON_C_TO_STRING_PRETTY));

	if (post_obj) {
		post_data = json_object_to_json_string(post_obj);
		err = curl_easy_setopt(ctx->curl_ctx, CURLOPT_POSTFIELDS,
				       post_data);
		if (err != CURLE_OK) {
			fprintf(stderr, "curl setop postfields failed, %s\n",
				curl_easy_strerror(err));
			err = EINVAL;
			goto err_out;
		}

		err = curl_easy_setopt(ctx->curl_ctx, CURLOPT_POSTFIELDSIZE,
				       strlen(post_data));
		if (err != CURLE_OK) {
			fprintf(stderr, "curl setop postfieldsize failed, %s\n",
				curl_easy_strerror(err));
			err = EINVAL;
			goto err_out;
		}
	}

	err = curl_easy_perform(ctx->curl_ctx);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl perform failed, %d (%s)\n",
			err, curl_easy_strerror(err));
		if (err == CURLE_OPERATION_TIMEDOUT)
			err = -ETIME;
		else
			err = -EIO;
	}

err_out:
	curl_easy_cleanup(ctx->curl_ctx);
	ctx->curl_ctx = NULL;
	return err;
}

static size_t
etcd_parse_set_response(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp;
	struct etcd_ctx *ctx = arg;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
	} else if (etcd_debug)
		printf("%s: %s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_kv_put(struct etcd_ctx *ctx, const char *key, const char *value,
		bool lease)
{
	char url[1024];
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	char *encoded_value = NULL;
	int ret;

	sprintf(url, "%s://%s:%u/v3/kv/put",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	encoded_value = __b64enc(value, strlen(value));
	json_object_object_add(post_obj, "value",
			       json_object_new_string(encoded_value));
	if (lease)
		json_object_object_add(post_obj, "lease",
				       json_object_new_int64(ctx->lease));
	else
		json_object_object_add(post_obj, "ignore_lease",
				       json_object_new_boolean(true));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_set_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}
	free(encoded_value);
	free(encoded_key);
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

int etcd_kv_get(struct etcd_ctx *ctx, const char *key, char *value)
{
	char url[1024];
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	int ret;

	sprintf(url, "%s://%s:%u/v3/kv/range",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	ctx->tokener = json_tokener_new_ex(5);
	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_range_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}

	json_object_put(post_obj);
	free(encoded_key);
	json_tokener_free(ctx->tokener);
	if (!ret) {
		struct json_object_iterator its, ite;
		struct json_object *val_obj;

		its = json_object_iter_begin(ctx->resp_obj);
		ite = json_object_iter_end(ctx->resp_obj);

		ret = -ENOENT;
		while (!json_object_iter_equal(&its, &ite)) {
			val_obj = json_object_iter_peek_value(&its);
			if (ret) {
				if (value)
					strcpy(value,
					       json_object_get_string(val_obj));
				ret = 0;
			}
			json_object_iter_next(&its);
		}
	}
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

struct json_object *etcd_kv_range(struct etcd_ctx *ctx, const char *key)
{
	char url[1024];
	struct json_object *post_obj = NULL, *resp = NULL;
	char *encoded_key = NULL, end;
	char *encoded_range = NULL, *range;
	int ret;

	ctx->resp_obj = json_object_new_object();
	sprintf(url, "%s://%s:%u/v3/kv/range",
		ctx->proto, ctx->host, ctx->port);

	ctx->tokener = json_tokener_new_ex(5);
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

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_range_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}

	free(encoded_range);
	free(encoded_key);
	json_object_put(post_obj);
	json_tokener_free(ctx->tokener);
	if (ret < 0)
		json_object_put(ctx->resp_obj);
	else
		resp = ctx->resp_obj;
	ctx->resp_obj = NULL;
	return resp;
}

static size_t
etcd_parse_revision_response (char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *hdr_obj, *rev_obj;
	struct etcd_ctx *ctx = arg;
	int value;

	etcd_resp = json_tokener_parse_ex(ctx->tokener, ptr,
					  size * nmemb);
	if (!etcd_resp) {
		if (json_tokener_get_error(ctx->tokener) == json_tokener_continue) {
			/* Partial / chunked response; continue */
			return size * nmemb;
		}
		if (etcd_debug)
			printf("%s: ERROR:\n%s\n", __func__, ptr);

		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		return 0;
	}
	if (etcd_debug)
		printf("%s: DATA:\n%s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));
	hdr_obj = json_object_object_get(etcd_resp, "header");
	if (!hdr_obj) {
		char *err_str = "invalid response, 'header' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	rev_obj = json_object_object_get(hdr_obj, "revision");
	if (!rev_obj) {
		char *err_str = "invalid response, 'revision' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	value = json_object_get_int(rev_obj);
	json_object_object_add(ctx->resp_obj, "revision",
			       json_object_new_int(value));
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_kv_revision(struct etcd_ctx *ctx, const char *key)
{
	char url[1024];
	struct json_object *post_obj = NULL, *rev_obj;
	char *encoded_key = NULL;
	int ret;

	sprintf(url, "%s://%s:%u/v3/kv/range",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	ctx->tokener = json_tokener_new_ex(5);
	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_revision_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "etcd_kv_exec: %s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}
	if (!ret) {
		rev_obj = json_object_object_get(ctx->resp_obj, "revision");
		if (!rev_obj) {
			fprintf(stderr,
				"invalid response, 'revision' not found\n");
			errno = -ENOKEY;
			ret = -1;
		} else {
			ret = json_object_get_int(rev_obj);
		}
	}
	json_object_put(post_obj);
	free(encoded_key);
	json_tokener_free(ctx->tokener);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

static size_t
etcd_parse_delete_response (char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct etcd_ctx *ctx = arg;
	struct json_object *etcd_resp, *deleted_obj;
	int deleted = 0;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	if (etcd_debug)
		printf("%s: %s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));

	deleted_obj = json_object_object_get(etcd_resp, "deleted");
	if (!deleted_obj) {
		char *err_str = "delete key failed, invalid key";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EKEYREJECTED));
		goto out;
	}
	deleted = json_object_get_int(deleted_obj);
	if (!deleted) {
		char *err_str = "delete key failed, key not deleted";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EKEYREJECTED));
	}
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_kv_delete(struct etcd_ctx *ctx, const char *key)
{
	char url[1024];
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL, *end_key, *encoded_end, end;
	int ret;

	sprintf(url, "%s://%s:%u/v3/kv/deleterange",
		ctx->proto, ctx->host, ctx->port);

	end_key = strdup(key);
	end = key[strlen(key) - 1];
	end++;
	end_key[strlen(key) - 1] = end;
	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	encoded_end = __b64enc(end_key, strlen(end_key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	json_object_object_add(post_obj, "range_end",
			       json_object_new_string(encoded_end));
	json_object_object_add(post_obj, "prev_kv",
			       json_object_new_boolean(true));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_delete_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}
	free(encoded_end);
	free(encoded_key);
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

static size_t
etcd_parse_watch_response(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *result_obj, *event_obj;
	struct json_object *header_obj, *rev_obj;
	struct etcd_ctx *ctx = arg;
	int i;

	etcd_resp = json_tokener_parse_ex(ctx->tokener, ptr,
					  size * nmemb);
	if (!etcd_resp) {
		if (json_tokener_get_error(ctx->tokener) == json_tokener_continue) {
			/* Partial / chunked response; continue */
			return size * nmemb;
		}
		if (etcd_debug)
			printf("%s: invalid response\n'%s'\n",
			       __func__, ptr);
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		return 0;
	}
	if (etcd_debug)
		printf("%s: %s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));
	result_obj = json_object_object_get(etcd_resp, "result");
	if (!result_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'result' not found",
			       __func__);
		goto out;
	}

	header_obj = json_object_object_get(result_obj, "header");
	if (!header_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'header' not found",
			       __func__);
		goto out;
	}
	rev_obj = json_object_object_get(header_obj, "revision");
	if (rev_obj) {
		ctx->revision = json_object_get_int64(rev_obj);
		if (etcd_debug)
			printf("%s: new revision %ld\n",
			       __func__, ctx->revision);
	}

	/* 'created' set in response to a 'WatchRequest', no data is pending */
	if (json_object_object_get(result_obj, "created"))
		goto out;

	event_obj = json_object_object_get(result_obj, "events");
	if (!event_obj) {
		if (etcd_debug)
			printf("%s: invalid response, 'events' not found",
			       __func__);
		goto out;
	}

	for (i = 0; i < json_object_array_length(event_obj); i++) {
		struct json_object *kvs_obj, *kv_obj, *key_obj;
		struct json_object *type_obj, *value_obj;
		char *key_str, *value_str;

		kvs_obj = json_object_array_get_idx(event_obj, i);
		type_obj = json_object_object_get(kvs_obj, "type");
		kv_obj = json_object_object_get(kvs_obj, "kv");
		if (!kv_obj)
			continue;
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj)
			continue;
		key_str = __b64dec(json_object_get_string(key_obj));
		value_obj = json_object_object_get(kv_obj, "value");
		if (!value_obj) {
			if (!strcmp(json_object_get_string(type_obj),
				    "DELETE") && ctx->watch_cb)
				ctx->watch_cb(ctx, KV_KEY_OP_DELETE,
					      key_str, NULL);
			free(key_str);
			continue;
		}
		value_str = __b64dec(json_object_get_string(value_obj));
		if (ctx->watch_cb)
			ctx->watch_cb(ctx, KV_KEY_OP_ADD, key_str, value_str);
		free(value_str);
		free(key_str);
	}
out:
	json_object_put(etcd_resp);
	json_tokener_reset(ctx->tokener);
	return size * nmemb;
}

int etcd_kv_watch(struct etcd_ctx *ctx, const char *key)
{
	char url[1024];
	struct json_object *post_obj, *req_obj;
	char *encoded_key, *end_key, *encoded_end, end;
	int ret;

	sprintf(url, "%s://%s:%u/v3/watch",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	ctx->tokener = json_tokener_new_ex(10);
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
	if (ctx->revision > 0)
		json_object_object_add(req_obj, "start_revision",
				       json_object_new_int64(ctx->revision));
	json_object_object_add(post_obj, "create_request", req_obj);

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_watch_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}
	free(encoded_key);
	free(encoded_end);
	free(end_key);
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

void etcd_kv_watch_stop(struct etcd_ctx *ctx)
{
	if (ctx->curl_ctx) {
		curl_easy_cleanup(ctx->curl_ctx);
		ctx->curl_ctx = NULL;
	}
}

static size_t
etcd_parse_lease_response(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *id_obj, *ttl_obj;
	struct etcd_ctx *ctx = arg;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	if (etcd_debug)
		printf("%s: %s\n", __func__,
		       json_object_to_json_string_ext(etcd_resp,
						      JSON_C_TO_STRING_PRETTY));
	if (ctx->ttl == -1) {
		struct json_object *error_obj;

		/* Revoke response */
		error_obj = json_object_object_get(etcd_resp, "error");
		if (error_obj) {
			const char *err_str = json_object_get_string(error_obj);

			json_object_object_add(ctx->resp_obj, "error",
					       json_object_new_string(err_str));
			json_object_object_add(ctx->resp_obj, "errno",
					       json_object_new_int(EKEYREJECTED));
		} else {
			printf("Revoke lease %ld\n", ctx->lease);
			ctx->lease = 0;
		}
		goto out;
	}
	id_obj = json_object_object_get(etcd_resp, "ID");
	if (!id_obj) {
		char *err_str = "invalid response, 'ID' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	ctx->lease = json_object_get_int64(id_obj);
	ttl_obj = json_object_object_get(etcd_resp, "TTL");
	if (!ttl_obj) {
		char *err_str = "keepalive failed, key expired";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EKEYEXPIRED));
		ctx->ttl = -1;
	} else {
		ctx->ttl = json_object_get_int(ttl_obj);
	}
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_lease_grant(struct etcd_ctx *ctx)
{
	char url[1024];
	struct json_object *post_obj;
	int ret;

	sprintf(url, "%s://%s:%u/v3/lease/grant",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(0));
	json_object_object_add(post_obj, "TTL",
			       json_object_new_int(ctx->ttl));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_lease_response);
	if (!ret) {
		if (!ctx->lease || ctx->ttl < 0) {
			struct json_object *err_obj;

			err_obj = json_object_object_get(ctx->resp_obj, "error");
			if (err_obj)
				fprintf(stderr, "%s\n",
					json_object_get_string(err_obj));
			else if (!ctx->lease)
				fprintf(stderr, "no lease has been granted\n");
			else
				fprintf(stderr, "invalid time-to-live value\n");
			err_obj = json_object_object_get(ctx->resp_obj, "errno");
			if (err_obj)
				errno = json_object_get_int(err_obj);
			else if (!ctx->lease)
				errno = ENOKEY;
			else
				errno = EINVAL;
			ret = -1;
		} else
			printf("Granted lease %ld ttl %d\n",
			       ctx->lease, ctx->ttl);

	}
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

static size_t
etcd_parse_keepalive_response(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *result_obj;
	struct etcd_ctx *ctx = arg;
	struct json_object *id_obj, *ttl_obj;
	int64_t lease;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	if (etcd_debug)
		printf("%s\n", json_object_to_json_string_ext(etcd_resp,
				      JSON_C_TO_STRING_PRETTY));
	result_obj = json_object_object_get(etcd_resp, "result");
	if (!result_obj) {
		char *err_str = "keepalive failed, 'result' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	id_obj = json_object_object_get(result_obj, "ID");
	if (!id_obj) {
		char *err_str = "keepalive failed, 'ID' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	lease = json_object_get_int64(id_obj);
	if (lease != ctx->lease) {
		char *err_str = "keepalive failed, lease mismatch";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EKEYREJECTED));
		goto out;
	}
	ttl_obj = json_object_object_get(result_obj, "TTL");
	if (!ttl_obj)
		ctx->ttl = -1;
	else
		ctx->ttl = json_object_get_int(ttl_obj);

out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_lease_keepalive(struct etcd_ctx *ctx)
{
	char url[1024];
	struct json_object *post_obj;
	int ret;

	sprintf(url, "%s://%s:%u/v3/lease/keepalive",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));
	json_object_object_add(post_obj, "TTL",
			       json_object_new_int(ctx->ttl));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_keepalive_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
		if (!ret && ctx->ttl == -1) {
			fprintf(stderr, "lease expired\n");
			errno = EKEYEXPIRED;
			ret = -1;
		}
	}
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

int etcd_lease_timetolive(struct etcd_ctx *ctx)
{
	char url[1024];
	struct json_object *post_obj;
	int ret;

	sprintf(url, "%s://%s:%u/v3/lease/timetolive",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_keepalive_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EINVAL;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
		if (!ret && ctx->ttl == -1) {
			fprintf(stderr, "lease expired\n");
			errno = EKEYEXPIRED;
			ret = -1;
		}
	}

	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

int etcd_lease_revoke(struct etcd_ctx *ctx)
{
	char url[1024];
	struct json_object *post_obj;
	int ret;

	sprintf(url, "%s://%s:%u/v3/lease/revoke",
		ctx->proto, ctx->host, ctx->port);

	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "ID",
			       json_object_new_int64(ctx->lease));
	ctx->ttl = -1;
	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_lease_response);
	if (!ret) {
		struct json_object *err_obj;

		err_obj = json_object_object_get(ctx->resp_obj, "error");
		if (err_obj) {
			fprintf(stderr, "%s\n",
				json_object_get_string(err_obj));
			errno = EKEYREJECTED;
			ret = -1;
		}
		err_obj = json_object_object_get(ctx->resp_obj, "errno");
		if (err_obj) {
			errno = json_object_get_int(err_obj);
			ret = -1;
		}
	}
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

static size_t
etcd_parse_member_response (char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *hdr_obj, *mbs_obj;
	struct etcd_ctx *ctx = arg;
	char default_url[PATH_MAX];
	int i;

	sprintf(default_url, "%s://%s:%d",
		ctx->proto, ctx->host, ctx->port);

	etcd_resp = json_tokener_parse_ex(ctx->tokener, ptr,
					  size * nmemb);
	if (!etcd_resp) {
		if (json_tokener_get_error(ctx->tokener) == json_tokener_continue) {
			/* Partial / chunked response; continue */
			return size * nmemb;
		}
		if (etcd_debug)
			printf("%s: ERROR:\n%s\n", __func__, ptr);

		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(ptr));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		return 0;
	}

	if (etcd_debug)
		printf("DATA:\n%s\n", json_object_to_json_string_ext(etcd_resp,
					JSON_C_TO_STRING_PRETTY));
	hdr_obj = json_object_object_get(etcd_resp, "header");
	if (!hdr_obj) {
		char *err_str = "invalid response, 'header' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
	}
	mbs_obj = json_object_object_get(etcd_resp, "members");
	if (!mbs_obj) {
		char *err_str = "invalid response, 'members' not found";
		json_object_object_add(ctx->resp_obj, "error",
				       json_object_new_string(err_str));
		json_object_object_add(ctx->resp_obj, "errno",
				       json_object_new_int(EBADMSG));
		goto out;
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
					       __func__, ctx->node_name,
					       ctx->node_id);
			}
		}
	}
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

int etcd_member_id(struct etcd_ctx *ctx)
{
	struct json_object *post_obj;
	char url[1024];
	int ret;

	sprintf(url, "%s://%s:%u/v3/cluster/member/list",
		ctx->proto, ctx->host, ctx->port);

	ctx->tokener = json_tokener_new_ex(5);
	ctx->resp_obj = json_object_new_object();
	post_obj = json_object_new_object();
	json_object_object_add(post_obj, "linearizable",
			       json_object_new_boolean(true));

	ret = etcd_kv_exec(ctx, url, post_obj, etcd_parse_member_response);
	json_object_put(post_obj);
	json_object_put(ctx->resp_obj);
	ctx->resp_obj = NULL;
	return ret;
}

struct etcd_ctx *etcd_init(const char *prefix)
{
	struct etcd_ctx *ctx;
	int ret;

	ctx = malloc(sizeof(struct etcd_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		return NULL;
	}
	memset(ctx, 0, sizeof(struct etcd_ctx));
	ctx->host = default_etcd_host;
	ctx->proto = default_etcd_proto;
	ctx->port = default_etcd_port;
	if (prefix)
		ctx->prefix = strdup(prefix);
	else
		ctx->prefix = strdup(default_etcd_prefix);
	ctx->lease = -1;
	ctx->ttl = 240;

	if (etcd_debug)
		printf("%s: using prefix '%s'\n", __func__, ctx->prefix);

	ret = etcd_member_id(ctx);
	if (ret < 0) {
		errno = -ret;
		free(ctx->prefix);
		free(ctx);
		return NULL;
	}
	return ctx;
}

struct etcd_ctx *etcd_dup(struct etcd_ctx *ctx)
{
	struct etcd_ctx *new_ctx;

	new_ctx = malloc(sizeof(struct etcd_ctx));
	if (!new_ctx) {
		fprintf(stderr, "cannot allocate context\n");
		return NULL;
	}
	memset(new_ctx, 0, sizeof(struct etcd_ctx));
	new_ctx->host = ctx->host;
	new_ctx->proto = ctx->proto;
	new_ctx->port = ctx->port;
	new_ctx->prefix = strdup(ctx->prefix);
	new_ctx->lease = -1;
	new_ctx->ttl = ctx->ttl;
	if (ctx->node_name) {
		new_ctx->node_name = strdup(ctx->node_name);
		new_ctx->node_id = ctx->node_id;
	}

	return new_ctx;
}

void etcd_exit(struct etcd_ctx *ctx)
{
	if (!ctx)
		return;
	json_object_put(ctx->resp_obj);
	if (ctx->node_name)
		free(ctx->node_name);
	free(ctx->prefix);
	free(ctx);
}
