/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_socket.c
 * socket interface for etcd v3 REST API implementation
 *
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <limits.h>
#include <netdb.h>
#include <errno.h>

#include <json-c/json.h>
#include "http_parser.h"
#include "base64.h"

#include "etcd_client.h"

bool http_data_debug = false;

static int etcd_socket_connect(struct etcd_ctx *ctx)
{
	char port[16];
	struct addrinfo hints, *ai, *aip;
	int sockfd = -1, ret;

	sprintf(port, "%d", ctx->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(ctx->host, port, &hints, &ai);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() on %s:%d failed: %s\n",
			ctx->host, ctx->port, gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		fprintf(stderr, "no results from getaddrinfo()\n");
		return -EHOSTUNREACH;
	}

	for (aip = ai; aip != NULL; aip = aip->ai_next) {
		sockfd = socket(aip->ai_family, aip->ai_socktype,
				aip->ai_protocol);
		if (sockfd < 0) {
			fprintf(stderr, "socket error %d\n", errno);
			continue;
		}
		if (connect(sockfd, aip->ai_addr, aip->ai_addrlen) == 0)
			break;

		close(sockfd);
		sockfd = -ENOTCONN;
	}

	freeaddrinfo(ai);

	if (sockfd > 0) {
		int flags = fcntl(sockfd, F_GETFL);
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}

	return sockfd;
}

char *http_header =
	"POST %s HTTP/1.1\r\n"
	"Host: %s:%d\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/json\r\n"
	"Content-Length: %d\r\n\r\n";

static char *format_hdr(struct etcd_ctx *ctx, char *uri, int len)
{
	char *hdr;
	int hdrlen;

	hdrlen = asprintf(&hdr, http_header, uri,
			  ctx->host, ctx->port, len);
	if (hdrlen < 0)
		return NULL;
	return hdr;
}

static int send_data(int sockfd, const char *data, size_t data_len)
{
	const char *data_ptr;
	size_t data_left, len;

	data_ptr = data;
	data_left = data_len;
	while (data_left) {
		len = write(sockfd, data_ptr, data_left);
		if (len < 0) {
			fprintf(stderr, "error %d sending http header\n",
				errno);
			return -errno;
		}
		if (len == 0) {
			fprintf(stderr,
				"connection closed, %ld bytes pending\n",
				data_left);
			return -ENOTCONN;
		}
		data_left -= len;
		data_ptr += len;
	}
	return data_left;
}

int send_http(int sockfd, char *hdr, size_t hdrlen,
	      const char *post, size_t postlen)
{
	int ret;

	if (http_debug) {
		printf("%s: http header (%ld bytes)\n",
		       __func__, hdrlen);
		if (http_data_debug)
			printf("%s: %s\n", __func__, hdr);
	}
	ret = send_data(sockfd, hdr, hdrlen);
	if (ret < 0)
		return ret;
	if (http_debug) {
		printf("%s: http post (%ld bytes)\n",
		       __func__, postlen);
		if (http_data_debug)
			printf("%s: %s\n", __func__, post);
	}
	ret = send_data(sockfd, post, postlen);
	return ret;
}

static int parse_json(http_parser *http, const char *body, size_t len)
{
	struct etcd_parse_data *arg = http->data;
	json_object *resp;

	if (!len) {
		if (http_debug)
			printf("%s: no data to parse\n", __func__);
		return 0;
	}
	if (arg->data) {
		char *tmp;
		tmp = malloc(arg->len + len + 1);
		memset(tmp, 0, arg->len + len + 1);
		strcpy(tmp, arg->data);
		memcpy(tmp + arg->len, body, len);
		free(arg->data);
		arg->data = tmp;
		arg->len += len;
		json_tokener_reset(arg->tokener);
	} else {
		arg->data = malloc(len + 1);
		memset(arg->data, 0, len + 1);
		memcpy(arg->data, body, len);
		arg->len = len;
	}
	resp = json_tokener_parse_ex(arg->tokener,
				     arg->data, arg->len);
	if (!resp) {
		if (json_tokener_get_error(arg->tokener) ==
		    json_tokener_continue) {
			if (http_debug)
				printf("%s: continue after %ld bytes\n%s\n",
				       __func__, len, arg->data);
			return 0;
		}
		printf("%s: invalid response\n'%s'\n",
		       __func__, arg->data);
		if (arg->parse_cb)
			arg->parse_cb(NULL, arg->parse_arg);
		free(arg->data);
		arg->data = NULL;
		arg->len = 0;
		return -EBADMSG;
	}

	if (http_debug) {
		printf("%s: http data (%ld bytes)\n", __func__, len);
		printf("%s: %s\n", __func__,
		       json_object_to_json_string_ext(resp,
						      JSON_C_TO_STRING_PRETTY));
	}

	if (arg->parse_cb)
		arg->parse_cb(resp, arg->parse_arg);

	json_object_put(resp);
	free(arg->data);
	arg->data = NULL;
	arg->len = 0;
	return 0;
}

int recv_http(struct etcd_conn_ctx *conn, http_parser *http,
	      http_parser_settings *settings)
{
	size_t alloc_size = 1024, result_size = 0;
	char *result;
	int ret = 0;

	result = malloc(alloc_size);
	if (!result)
		return -ENOMEM;
	memset(result, 0, alloc_size);

	while (true) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(conn->sockfd, &rfd);
		if (conn->ctx->ttl > 0)
			tmo.tv_sec = conn->ctx->ttl;
		else
			tmo.tv_sec = 1;
		tmo.tv_usec = 0;
		ret = select(conn->sockfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			fprintf(stderr, "%s: select error %d\n",
				__func__, errno);
			break;
		}
		if (!FD_ISSET(conn->sockfd, &rfd)) {
			if (http_debug)
				printf("%s: no events\n", __func__);
			ret = -ENODATA;
			break;
		}
		ret = read(conn->sockfd, result, alloc_size);
		if (ret < 0) {
			fprintf(stderr,
				"%s: error %d during read, %ld bytes read\n",
				__func__, errno, result_size);
			ret = -errno;
			break;
		}
		if (ret == 0) {
			fprintf(stderr,
				"%s: socket closed during read, %ld bytes read\n",
				__func__, result_size);
			break;
		}
		result_size = ret;
		if (http_debug) {
			printf("%s: %ld bytes read\n",
			       __func__, result_size);
			if (http_data_debug)
				printf("%s: %s\n",
				       __func__, result);
		}
		ret = http_parser_execute(http, settings,
					  result, result_size);
		if (!ret) {
			printf("%s: No bytes processed\n%s\n",
			       __func__, result);
			break;
		}
		if (result_size < alloc_size)
			break;
		memset(result, 0, alloc_size);
	}
	free(result);
	return ret;
}

int etcd_kv_exec(struct etcd_conn_ctx *conn, char *uri,
		 struct json_object *post_obj,
		 etcd_parse_cb parse_cb, void *parse_arg)
{
	struct etcd_parse_data *parse_data;
	http_parser_settings settings;
	http_parser *http = conn->priv;
	char *hdr, *post;
	size_t postlen;
	int ret = 0;

	if (!http || !http->data) {
		fprintf(stderr, "%s: connection not initialized\n", __func__);
		return -EINVAL;
	}
	parse_data = http->data;
	parse_data->parse_cb = parse_cb;
	parse_data->parse_arg = parse_arg;

	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_json;

	post = strdup(json_object_to_json_string_ext(post_obj,
						     JSON_C_TO_STRING_PLAIN));
	postlen = strlen(post);

	hdr = format_hdr(conn->ctx, uri, postlen);
	if (!hdr) {
		free(post);
		return -ENOMEM;
	}
	if (http_debug) {
		printf("%s: uri %s\n", __func__, uri);
		printf("%s: %s\n", __func__, post);
	}
	ret = send_http(conn->sockfd, hdr, strlen(hdr), post, postlen);
	free(hdr);

	if (ret < 0) {
		free(post);
		return -errno;
	}
	ret = recv_http(conn, http, &settings);
	if (ret > 0)
		ret = 0;

	parse_data->parse_cb = NULL;
	parse_data->parse_arg = NULL;
	free(post);
	return ret;
}

int etcd_conn_continue(struct etcd_conn_ctx *conn)
{
	http_parser_settings settings;

	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_json;

	return recv_http(conn, conn->priv, &settings);
}

int etcd_conn_init(struct etcd_conn_ctx *conn)
{
	struct etcd_parse_data *parse_data;
	http_parser *http;

	conn->sockfd = etcd_socket_connect(conn->ctx);
	if (conn->sockfd < 0) {
		fprintf(stderr, "%s: failed to connect, error %d\n",
			__func__, errno);
		return -errno;
	}

	http = malloc(sizeof(*http));
	if (!http)
		goto out_close;

	memset(http, 0, sizeof(*http));
	http_parser_init(http, HTTP_RESPONSE);
	parse_data = malloc(sizeof(*parse_data));
	if (!parse_data)
		goto out_free;

	memset(parse_data, 0, sizeof(*parse_data));
	parse_data->tokener = json_tokener_new_ex(10);
	http->data = parse_data;
	conn->priv = http;

	return 0;
out_free:
	free(http);
out_close:
	close(conn->sockfd);
	conn->sockfd = -1;
	return -ENOMEM;
}

void etcd_conn_exit(struct etcd_conn_ctx *conn)
{
	http_parser *http = conn->priv;

	if (http) {
		if (http->data) {
			struct etcd_parse_data *parse_data;

			parse_data = http->data;
			json_tokener_free(parse_data->tokener);
			free(parse_data);
			http->data = NULL;
		}
		free(http);
	}
	if (conn->sockfd > 0) {
		close(conn->sockfd);
		conn->sockfd = -1;
	}
}
