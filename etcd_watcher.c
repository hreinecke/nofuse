
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

#include "common.h"
#include "etcd_client.h"

static char *key_to_attr(struct etcd_ctx *ctx, char *key)
{
	char *attr, *path;
	int ret;

	attr = key + strlen(ctx->prefix) + 1;
	if (!strncmp(attr, "ports/", 6)) {
		char *p = attr + 6, *node_name = ctx->node_name;

		if (!node_name)
			node_name = "localhost";
		if (strncmp(p, ctx->node_name, strlen(ctx->node_name))) {
			printf("%s: ignoring foreign port %s\n",
			       __func__, attr);
			return NULL;
		}
		p = strchr(attr, ':');
		if (!p) {
			printf("%s: invalid port %s\n",
			       __func__, attr);
			return NULL;
		}
		ret = asprintf(&path, "%s/ports/%s",
			       NVMET_CONFIGFS, p + 1);
	} else
		ret = asprintf(&path, "%s/%s",
			       NVMET_CONFIGFS, attr);
	if (ret < 0) {
		printf("%s: out of memory\n", __func__);
		return NULL;
	}
	return path;
}

static int create_parent(char *path)
{
	char *parent, *ptr;
	struct stat st;
	int ret;

	/* Trying to create parent */
	parent = strdup(path);
	ptr = strrchr(parent, '/');
	if (!ptr) {
		printf("%s: invalid parent %s\n",
		       __func__, parent);
		ret = -EINVAL;
		goto out;
	}
	*ptr = '\0';
	ret = stat(parent, &st);
	if (ret < 0) {
		if (errno != ENOENT) {
			printf("%s: error %d accessing parent %s\n",
			       __func__, errno, parent);
			ret = -errno;
			goto out;
		}
		printf("%s: create parent %s\n", __func__, parent);
		ret = mkdir(parent, 0755);
		if (ret < 0) {
			printf("%s: error %d creating parent %s\n",
			       __func__, errno, parent);
			ret = -errno;
			goto out;
		}
		ret = stat(path, &st);
		if (ret < 0) {
			printf("%s: error %d accessing new path %s\n",
			       __func__, errno, path);
			ret = -errno;
			goto out;
		}
	} else if ((st.st_mode & S_IFMT) != S_IFDIR) {
		printf("%s: parent %s is not a directory\n",
		       __func__, parent);
		ret = -ENOTDIR;
	}
out:
	free(parent);
	return ret;
}

int delete_parent(char *path)
{
	char *parent, *ptr;
	struct stat st;
	int ret;

	/* Trying to create parent */
	parent = strdup(path);
	ptr = strrchr(parent, '/');
	if (!ptr) {
		printf("%s: invalid parent %s\n",
		       __func__, parent);
		free(parent);
		return -EINVAL;
	}
	*ptr = '\0';
	ret = stat(parent, &st);
	if (ret < 0) {
		/* already deleted ... */
		if (errno == ENOENT) {
			free(parent);
			return 0;
		}
		printf("%s: error %d accessing %s\n",
		       __func__, errno, parent);
		ret = -errno;
	} else {
		size_t offset = strlen(parent) - 12;
		if (!strcmp(parent + offset, "ana_groups/1")) {
			printf("%s: skip ana group 1\n", __func__);
			ret = 0;
		} else {
			ret = rmdir(parent);
			if (ret < 0) {
				printf("%s: error %d deleting parent %s\n",
				       __func__, errno, parent);
				ret = -errno;
			}
		}
	}
	free(parent);
	return ret;
}

static int update_value(char *path, char *value)
{
	int fd, ret;
	char buf[256];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		printf("%s: error opening %s\n",
		       __func__, path);
		return -errno;
	}

	ret = read(fd, buf, 256);
	if (ret < 0) {
		printf("error reading %s\n", path);
		ret = -errno;
	} else if (strncmp(value, buf, strlen(value))) {
		printf("update from %s to %s\n", buf, value);
		ret = write(fd, value, strlen(value));
		if (ret < 0) {
			printf("%s: failed to update %s, error %d\n",
			       __func__, path, errno);
			ret = -errno;
		}
	}
	close(fd);
	return ret;
}

void etcd_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct stat st;
	char *path;
	int ret;

	if (kv->deleted)
		printf("%s: delete key %s\n",
		       __func__, kv->key);
	else
		printf("%s: add key %s value %s\n", __func__,
		       kv->key, kv->value);

	path = key_to_attr(ctx, kv->key);
	if (!path) {
		return;
	}
	ret = stat(path, &st);
	if (ret < 0) {
		if (errno != ENOENT) {
			printf("%s: error %d accessing %s\n",
			       __func__, errno, path);
			goto out_free;
		}
		if (kv->deleted)
			/* KV deleted and path not present, all done */
			goto out_free;

		printf("%s: create parent %s\n",
		       __func__, path);
		/* Trying to create parent */
		ret = create_parent(path);
		if (ret < 0)
			goto out_free;
		/* retry, should succeed now */
		ret = stat(path, &st);
		if (ret < 0) {
			printf("%s: error %d accessing %s\n",
			       __func__, errno, path);
			goto out_free;
		}
	}
	if (kv->deleted) {
		printf("%s: delete parent %s\n",
		       __func__, path);
		ret = delete_parent(path);
	} else if (!kv->value) {
		printf("%s: no value\n", __func__);
	} else if ((st.st_mode & S_IFMT) == S_IFREG) {
		ret = update_value(path, kv->value);
	} else if ((st.st_mode & S_IFMT) == S_IFLNK) {
		printf("%s: update link to %s\n",
		       __func__, kv->value);
	} else {
		printf("%s: unhandled attribute type for %s\n",
		       __func__, path);
		ret = -EINVAL;
	}
out_free:
	free(path);
}
