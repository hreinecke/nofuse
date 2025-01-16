
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

int stopped = 0;

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

json_object *format_watch(const char *key, int64_t revision, int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	char *encoded_key, end, *end_key, *encoded_end;

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
	return post_obj;
}

void parse_json(struct json_object *resp, void *arg)
{
	printf("%s\n",
	       json_object_to_json_string_ext(resp,
					      JSON_C_TO_STRING_PRETTY));
}

int etcd_kv_watch(struct etcd_ctx *ctx, const char *key,
		  struct etcd_kv_event *ev, int64_t watch_id)
{
	struct etcd_conn_ctx *conn;
	json_object *post_obj;
	int ret;

	conn = etcd_conn_create(ctx);

	post_obj = format_watch(key, ev->ev_revision, watch_id);
	ret = etcd_kv_exec(conn, "/v3/watch", post_obj,
			   parse_json, NULL);
	if (ret < 0) {
		printf("error %d sending watch request\n", ret);
	}

	etcd_conn_delete(conn);
	return ret;
}
	
int main(int argc, char **argv)
{
	struct etcd_ctx *ctx;
	struct etcd_kv_event ev;
	int ret;

	ctx = etcd_init(NULL);
	memset(&ev, 0, sizeof(ev));
	ret = etcd_kv_watch(ctx, "nofuse/ports", &ev, 0);
	etcd_exit(ctx);
	return ret ? 1 : 0;
}
