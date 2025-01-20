
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

bool etcd_debug = true;
bool http_debug = true;
int stopped = 0;

static void update_nvmetd(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;

	printf("%s: %s key %s value %s\n", __func__,
	       kv->deleted ? "delete" : "add",
	       kv->key, kv->value);
}

int main(int argc, char **argv)
{
	struct etcd_ctx *ctx;
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	int ret;

	ctx = etcd_init(NULL);
	conn = etcd_conn_create(ctx);
	if (!conn)
		return 1;

	memset(&ev, 0, sizeof(ev));
	ev.watch_cb = update_nvmetd;

	ret = etcd_kv_watch(conn, "nofuse/ports", &ev, 0);

	while (ret >= 0) {
		ret = etcd_kv_watch_continue(conn, &ev);
		if (ret < 0 && ret != -EAGAIN)
			break;
	}
	etcd_conn_delete(conn);
	etcd_exit(ctx);
	return ret ? 1 : 0;
}
