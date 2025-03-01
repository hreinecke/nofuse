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

#include "etcd_client.h"

static int etcd_kv_transfer(CURL *curl_ctx)
{
	CURLcode err;
	int ret = 0;


	err = curl_easy_perform(curl_ctx);
	if (err != CURLE_OK) {
		fprintf(stderr,
			"curl_perform() failed, %s\n",
			curl_easy_strerror(err));
		if (err == CURLE_OPERATION_TIMEDOUT)
			ret = -ETIME;
		else
			ret = -EIO;
	}
	return ret;
}

static size_t
etcd_parse_response(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct etcd_parse_data *data = arg;
	struct json_object *resp;

	resp = json_tokener_parse_ex(data->tokener, ptr,
				     size * nmemb);
	if (!resp) {
		if (json_tokener_get_error(data->tokener) == json_tokener_continue) {
			/* Partial / chunked response; continue */
			return size * nmemb;
		}
		if (etcd_debug)
			printf("%s: ERROR:\n%s\n", __func__, ptr);
	} else if (etcd_debug)
		printf("%s\n%s\n", __func__,
		       json_object_to_json_string_ext(resp,
						      JSON_C_TO_STRING_PRETTY));

	data->parse_cb(resp, data->parse_arg);
	json_object_put(resp);
	return size * nmemb;
}

int etcd_kv_exec(struct etcd_conn_ctx *conn, char *uri,
		 struct json_object *post_obj,
		 etcd_parse_cb parse_cb, void *parse_arg)
{
	char *url;
	CURL *curl_ctx = curl_easy_duphandle(conn->priv);
	CURLcode err;
	const char *post_data;
	int ret;
	struct etcd_parse_data parse_data = {
		.parse_cb = parse_cb,
		.parse_arg = parse_arg,
		.tokener = json_tokener_new_ex(10),
	};

	ret = asprintf(&url, "%s://%s:%u%s",
		       conn->ctx->proto, conn->ctx->host,
		       conn->ctx->port, uri);
	if (ret < 0) {
		ret = -ENOMEM;
		goto out_cleanup;
	}

	ret = -EINVAL;
	err = curl_easy_setopt(curl_ctx, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s\n",
			curl_easy_strerror(err));
		goto out_free;
	}
	err = curl_easy_setopt(curl_ctx, CURLOPT_WRITEFUNCTION,
			       etcd_parse_response);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s\n",
			curl_easy_strerror(err));
		goto out_free;
	}
	err = curl_easy_setopt(curl_ctx, CURLOPT_WRITEDATA,
			       &parse_data);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writedata failed, %s\n",
			curl_easy_strerror(err));
		goto out_free;
	}

	if (post_obj) {
		if (etcd_debug)
			printf("%s: POST %s:\n%s\n", __func__, url,
			       json_object_to_json_string_ext(post_obj,
						      JSON_C_TO_STRING_PRETTY));

		post_data = json_object_to_json_string(post_obj);
		err = curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDS,
				       post_data);
		if (err != CURLE_OK) {
			fprintf(stderr, "curl setop postfields failed, %s\n",
				curl_easy_strerror(err));
			goto out_free;
		}

		err = curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDSIZE,
				       strlen(post_data));
		if (err != CURLE_OK) {
			fprintf(stderr, "curl setop postfieldsize failed, %s\n",
				curl_easy_strerror(err));
			goto out_free;
		}
	}

	ret = etcd_kv_transfer(curl_ctx);

out_free:
	free(url);
out_cleanup:
	json_tokener_free(parse_data.tokener);
	curl_easy_cleanup(curl_ctx);
	return ret;
}

int etcd_conn_init(struct etcd_conn_ctx *conn)
{
	CURL *curl_ctx;
	CURLoption opt;
	CURLcode err;
	struct curl_slist *headers = NULL;

	curl_ctx = curl_easy_init();
	if (!curl_ctx) {
		fprintf(stderr, "curl easy init failed\n");
		return -ENOMEM;
	}

	opt = CURLOPT_FOLLOWLOCATION;
	err = curl_easy_setopt(curl_ctx, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_FORBID_REUSE;
	err = curl_easy_setopt(curl_ctx, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_POST;
	err = curl_easy_setopt(curl_ctx, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	if (conn->ctx && conn->ctx->ttl > 0) {
		opt = CURLOPT_TIMEOUT;
		err = curl_easy_setopt(curl_ctx, opt,
				       conn->ctx->ttl);
		if (err != CURLE_OK)
			goto out_err_opt;
	}
	headers = curl_slist_append(headers, "Expect:");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl_ctx, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl_ctx, CURLOPT_PRIVATE, conn);

	if (http_debug)
		curl_easy_setopt(curl_ctx, CURLOPT_VERBOSE, 1L);

	conn->priv = curl_ctx;
	return 0;

out_err_opt:
	fprintf(stderr, "curl setopt %d, error %d: %s\n",
		opt, err, curl_easy_strerror(err));
	curl_easy_cleanup(curl_ctx);
	return -EINVAL;
}

void etcd_conn_exit(struct etcd_conn_ctx *conn)
{
	if (conn->priv) {
		CURL *curl_ctx = conn->priv;

		curl_easy_cleanup(curl_ctx);
		conn->priv = NULL;
	}
}

void etcd_kv_watch_stop(struct etcd_conn_ctx *conn)
{
	etcd_conn_exit(conn);
}
