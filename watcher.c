
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <limits.h>

#include "common.h"
#include "etcd_client.h"

bool etcd_debug = true;
bool http_debug = false;
bool cmd_debug = false;
bool tcp_debug = false;
bool ep_debug = false;
bool port_debug = false;
int stopped = 0;

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

	ret = etcd_lease_grant(ctx);
	if (ret < 0) {
		fprintf(stderr, "failed to get etcd lease\n");
		goto out_delete;
	}

	memset(&ev, 0, sizeof(ev));
	ev.watch_cb = etcd_watch_cb;
	ev.watch_arg = ctx;

	ret = etcd_kv_watch(conn, ctx->prefix, &ev, 0);

	while (ret >= 0) {
		ret = etcd_kv_watch_continue(conn, &ev);
		if (ret < 0 && ret != -EAGAIN)
			break;
	}
	etcd_lease_revoke(ctx);
out_delete:
	etcd_conn_delete(conn);
	etcd_exit(ctx);
	return ret ? 1 : 0;
}
