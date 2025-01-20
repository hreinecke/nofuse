
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
bool http_debug = false;
int stopped = 0;

static void update_nvmetd(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct stat st;
	char *attr, *path;
	int fd, ret;

	if (kv->deleted)
		printf("%s: delete key %s\n",
		       __func__, kv->key);
	else
		printf("%s: add key %s value %s\n", __func__,
		       kv->key, kv->value);

	attr = kv->key + strlen(ctx->prefix) + 1;
	ret = asprintf(&path, "/sys/kernel/config/nvmet/%s", attr);
	if (ret < 0) {
		return;
	}
	ret = stat(path, &st);
	if (ret < 0) {
		if (errno != ENOENT && !kv->deleted)
			printf("%s: error %d accessing %s\n",
			       __func__, errno, path);
		return;
	}
	if (kv->deleted) {
		printf("%s: delete %s\n",
		       __func__, path);
		return;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("%s: error opening %s\n",
		       __func__, path);
	} else {
		char buf[256];

		ret = read(fd, buf, 256);
		if (ret < 0) {
			printf("error reading %s\n", path);
		} else if (strncmp(kv->value, buf, strlen(kv->value)))
			printf("update from %s to %s\n", buf, kv->value);
		close(fd);
	}
	free(path);
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
	ev.watch_arg = ctx;

	ret = etcd_kv_watch(conn, "nofuse", &ev, 0);

	while (ret >= 0) {
		ret = etcd_kv_watch_continue(conn, &ev);
		if (ret < 0 && ret != -EAGAIN)
			break;
	}
	etcd_conn_delete(conn);
	etcd_exit(ctx);
	return ret ? 1 : 0;
}
