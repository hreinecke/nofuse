
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

static char *path_to_key(struct etcd_ctx *ctx, const char *path)
{
	char *key;
	const char *attr = path + strlen("/sys/kernel/config/nvmet") + 1;
	int ret;

	if (!strncmp(attr, "ports/", 6)) {
		char *node_name = ctx->node_name;
		const char *suffix = attr + 6;

		if (!node_name)
			node_name = "localhost";
		ret = asprintf(&key, "%s/ports/%s:%s",
			       ctx->prefix, node_name, suffix);
	} else {
		ret = asprintf(&key, "%s/%s",
			       ctx->prefix, attr);
	}
	if (ret < 0)
		return NULL;
	return key;
}

static int read_attr(char *attr_path, char *value, size_t value_len)
{
	int fd, len;
	char *p;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -1;
	}
	len = read(fd, value, value_len);
	if (len < 0)
		memset(value, 0, value_len);
	else {
		p = &value[len - 1];
		if (*p == '\n')
			*p = '\0';
	}
	close(fd);
	return len;
}

static int update_value(struct etcd_ctx *ctx,
			const char *dirname, const char *name,
			int type)
{
	char *pathname, value[PATH_MAX + 1], *t, *key;
	int ret;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	if (type == DT_LNK) {
		t = "link";
		memset(value, 0, sizeof(value));
		ret = readlink(pathname, value, sizeof(value));
	} else {
		t = "attr";
		ret = read_attr(pathname, value, sizeof(value));
		if (!strcmp(name, "device_path")) {
			char *node_name = ctx->node_name;
			char *tmp = strdup(value);

			if (!node_name)
				node_name = "localhost";
			/*
			 * Prefix the device path with the node name to
			 * indicate on which node the namespace resides.
			 */
			sprintf(value, "%s:%s", node_name, tmp);
			free(tmp);
		}
	}
	key = path_to_key(ctx, pathname);
	free(pathname);
	if (!key) {
		return -ENOMEM;
	}
	printf("%s: upload %s key %s value '%s'\n", __func__,
	       t, key, value);
	if (ret > 0) {
		ret = etcd_kv_new(ctx, key, value);
		if (ret < 0)
			fprintf(stderr, "%s: %s key %s upload error %d\n",
				__func__, t, key, ret);
	} else {
		fprintf(stderr, "%s: %s %s value error %d\n",
			__func__, t, key, ret);
	}
	free(key);
	return ret;
}

int walk_nvmet(struct etcd_ctx *ctx,
	       const char *dir, const char *file)
{
	char *dirname;
	DIR *sd;
	struct dirent *se;
	int ret;

	printf("%s: walk dir %s file %s\n",
	       __func__, dir, file);

	ret = asprintf(&dirname, "%s/%s", dir, file);
	if (ret < 0)
		return -ENOMEM;

	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (!strcmp(se->d_name, "passthru"))
			continue;

		if (!strcmp(se->d_name, "revalidate_size"))
			continue;

		if (se->d_type == DT_REG || se->d_type == DT_LNK) {
			ret = update_value(ctx, dirname, se->d_name,
					   se->d_type);
			if (ret < 0)
				break;
		}

		if (se->d_type == DT_DIR) {
			ret = walk_nvmet(ctx, dirname, se->d_name);
			if (ret < 0)
				break;
		}
	}
	closedir(sd);
	free(dirname);
	return ret;
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

	ret = etcd_lease_grant(ctx);
	if (ret < 0) {
		fprintf(stderr, "failed to get etcd lease\n");
		goto out_delete;
	}

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		fprintf(stderr, "unshare error %d\n", errno);
		ret = -errno;
		goto out_revoke;
	}

	walk_nvmet(ctx, "/sys/kernel/config/nvmet", "hosts");
	walk_nvmet(ctx, "/sys/kernel/config/nvmet", "ports");
	walk_nvmet(ctx, "/sys/kernel/config/nvmet", "subsystems");

	memset(&ev, 0, sizeof(ev));
	ev.watch_cb = etcd_watch_cb;
	ev.watch_arg = ctx;

	ret = etcd_kv_watch(conn, ctx->prefix, &ev, 0);

	while (ret >= 0) {
		ret = etcd_kv_watch_continue(conn, &ev);
		if (ret < 0 && ret != -EAGAIN)
			break;
	}
out_revoke:
	etcd_lease_revoke(ctx);
out_delete:
	etcd_conn_delete(conn);
	etcd_exit(ctx);
	return ret ? 1 : 0;
}
