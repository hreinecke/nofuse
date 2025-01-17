
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
bool curl_debug = true;
int stopped = 0;

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
