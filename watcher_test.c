
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

#include "common.h"
#include "etcd_client.h"

struct http_parser_data {
	json_tokener *tokener;
	char *body;
	size_t len;
};

bool etcd_debug = true;

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

static int etcd_connect(struct etcd_ctx *ctx)
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
		if (connect(sockfd, aip->ai_addr, aip->ai_addrlen) == 0) {
			const char *fam = "IPv4";

			if (aip->ai_family == AF_INET6)
				fam = "IPv6";

			printf("connected to %s:%d with %s\n",
			       ctx->host, ctx->port, fam);
			break;
		}
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

char *format_hdr(struct etcd_ctx *ctx, char *url, int len)
{
	char *hdr;
	int hdrlen;

	hdrlen = asprintf(&hdr, http_header, url,
			  ctx->host, ctx->port, len);
	if (hdrlen < 0)
		return NULL;
	return hdr;
}

char *format_watch(char *key, int64_t revision, int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	char *encoded_key, end, *end_key, *encoded_end;
	const char *tmp;
	char *buf;

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
	if (revision > 0)
		json_object_object_add(req_obj, "start_revision",
				       json_object_new_int64(revision));
	if (watch_id > 0)
		json_object_object_add(req_obj, "watch_id",
				       json_object_new_int64(watch_id));
	json_object_object_add(post_obj, "create_request", req_obj);

	tmp = json_object_to_json_string_ext(post_obj,
					     JSON_C_TO_STRING_PRETTY);

	buf = strdup(tmp);
	json_object_put(post_obj);
	free(encoded_key);
	free(encoded_end);
	free(end_key);
	return buf;
}

char *format_cancel(struct etcd_ctx *ctx, int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	const char *tmp;
	char *buf;

	post_obj = json_object_new_object();
	req_obj = json_object_new_object();
	if (watch_id > 0)
		json_object_object_add(req_obj, "watch_id",
				       json_object_new_int64(watch_id));
	json_object_object_add(post_obj, "cancel_request", req_obj);

	tmp = json_object_to_json_string_ext(post_obj,
					     JSON_C_TO_STRING_PRETTY);

	buf = strdup(tmp);
	json_object_put(post_obj);
	return buf;
}

int send_data(int sockfd, const char *data, size_t data_len)
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
	      char *post, size_t postlen)
{
	int ret;

	printf("http header (%ld bytes)\n", hdrlen);
	ret = send_data(sockfd, hdr, hdrlen);
	if (ret < 0)
		return ret;
	printf("http post (%ld bytes)\n", postlen);
	ret = send_data(sockfd, post, postlen);
	return ret;
}

int send_cancel(struct etcd_conn_ctx *conn, int64_t watch_id)
{
	char *hdr, *post;
	size_t postlen;
	int ret;

	post = format_cancel(conn->ctx, watch_id);
	postlen = strlen(post);

	hdr = format_hdr(conn->ctx, "/v3/watch", postlen);
	if (!hdr) {
		free(post);
		return -ENOMEM;
	}

	ret = send_http(conn->sockfd, hdr, strlen(hdr), post, postlen);
	free(post);
	free(hdr);
	return ret;
}

int send_watch(struct etcd_conn_ctx *conn, char *key, int64_t watch_id)
{
	char *hdr, *post;
	size_t postlen;
	int ret;

	post = format_watch(key, 0, watch_id);
	postlen = strlen(post);

	hdr = format_hdr(conn->ctx, "/v3/watch", postlen);
	if (!hdr) {
		free(post);
		return -ENOMEM;
	}

	ret = send_http(conn->sockfd, hdr, strlen(hdr), post, postlen);
	free(post);
	free(hdr);
	return ret;
}

int parse_json(http_parser *http, const char *body, size_t len)
{
	struct http_parser_data *data = http->data;
	json_object *etcd_resp;

	if (data->body) {
		char *tmp;
		tmp = malloc(data->len + len + 1);
		memset(tmp, 0, data->len + len + 1);
		strcpy(tmp, data->body);
		strcpy(tmp + data->len, body);
		free(data->body);
		data->body = tmp;
		data->len += len;
		json_tokener_reset(data->tokener);
	} else {
		data->body = malloc(len + 1);
		memset(data->body, 0, len + 1);
		strcpy(data->body, body);
		data->len = len;
	}
	etcd_resp = json_tokener_parse_ex(data->tokener,
					  data->body, data->len);
	if (!etcd_resp) {
		if (json_tokener_get_error(data->tokener) ==
		    json_tokener_continue) {
			printf("%s: continue after %ld bytes\n%s\n",
			       __func__, len, data->body);
			return 0;
		}
		printf("%s: invalid response\n'%s'\n",
		       __func__, data->body);
		free(data->body);
		data->body = NULL;
		data->len = 0;
		return -EBADMSG;
	}

	printf("http data (%ld bytes)\n%s\n", len,
	       json_object_to_json_string_ext(etcd_resp,
					      JSON_C_TO_STRING_PRETTY));

	json_object_put(etcd_resp);
	free(data->body);
	data->body = NULL;
	data->len = 0;
	return 0;
}

int recv_http(struct etcd_conn_ctx *conn, http_parser *http,
	      http_parser_settings *settings)
{
	size_t alloc_size, result_inc = 1024, result_size;
	char *result;
	int ret;

	alloc_size = result_inc;
	result_size = 0;
	result = malloc(alloc_size);
	if (!result)
		return -ENOMEM;
	memset(result, 0, alloc_size);

	while (conn->sockfd > 0) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(conn->sockfd, &rfd);
		tmo.tv_sec = 1;
		tmo.tv_usec = 0;
		ret = select(conn->sockfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			fprintf(stderr, "select error %d\n", errno);
			break;
		}
		if (!FD_ISSET(conn->sockfd, &rfd)) {
			printf("no events, continue\n");
			continue;
		}
		ret = read(conn->sockfd, result, alloc_size);
		if (ret < 0) {
			fprintf(stderr,
				"error %d during read, %ld bytes read\n",
				errno, result_size);
			ret = -errno;
			break;
		}
		if (ret == 0) {
			fprintf(stderr,
				"socket closed during read, %ld bytes read\n",
				result_size);
			break;
		}
		result_size = ret;
		printf("%ld bytes read\n", result_size);
		ret = http_parser_execute(http, settings,
					  result, result_size);
		if (!ret) {
			printf("No bytes processed\n%s\n",
				result);
			break;
		}
		if (ret != result_size) {
			printf("%d from %ld bytes processed\n",
			       ret, result_size);
			break;
		}
		memset(result, 0, alloc_size);
	}
	free(result);
	return ret;
}

int main(int argc, char **argv)
{
	struct etcd_ctx *ctx;
	struct etcd_conn_ctx *conn;
	int ret;
	http_parser *http;
	http_parser_settings settings;
	struct http_parser_data data;

	ctx = etcd_init(NULL);

	http = malloc(sizeof(*http));
	memset(http, 0, sizeof(*http));
	http_parser_init(http, HTTP_RESPONSE);
	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_json;
	data.body = NULL;
	data.len = 0;
	data.tokener = json_tokener_new_ex(10);
	http->data = &data;

	conn = etcd_conn_create(ctx);
	conn->sockfd = etcd_connect(ctx);
	if (conn->sockfd < 0) {
		etcd_conn_delete(conn);
		return 1;
	}

	ret = send_watch(conn, "nofuse/ports", 0);
	if (ret < 0) {
		printf("error %d sending watch request\n", ret);
	} else {
		ret = recv_http(conn, http, &settings);
	}
	close(conn->sockfd);
	etcd_conn_delete(conn);
	etcd_exit(ctx);
	return 0;
}
