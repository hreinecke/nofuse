/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * configfs.c
 * configfs functions for etcd discovery
 *
 * Copyright (c) 2025 Hannes Reinecke <hare@suse.de>
 *
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <fcntl.h>

#include "common.h"
#include "utils.h"
#include "etcd_client.h"
#include "etcd_backend.h"

int read_attr(char *attr_path, char *value, size_t value_len)
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
		while (isspace(*p)) {
			*p = '\0';
			p--;
			len--;
			if (p == value)
				break;
		}
		if (!strcmp(value, "(null)")) {
			memset(value, 0, value_len);
			len = 0;
		}
	}
	close(fd);
	return len;
}

static char *path_to_key(struct etcd_ctx *ctx, const char *path)
{
	const char *attr = path + strlen(ctx->configfs) + 1;
	char *key;
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

static int update_value(struct etcd_ctx *ctx,
			const char *dirname, const char *name)
{
	struct stat st;
	char *pathname, value[1024], old[1024], *key;
	int ret;

	memset(value, 0, sizeof(value));
	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	ret = lstat(pathname, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: attr %s error %d\n",
			__func__, pathname, errno);
		free(pathname);
		return -errno;
	}
	if (!(st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
		printf("%s: skip attr %s, not readable\n",
		       __func__, pathname);
		free(pathname);
		return 0;
	}
	if ((st.st_mode & S_IFMT) == S_IFLNK) {
		ret = readlink(pathname, value, sizeof(value));
	} else if ((st.st_mode & S_IFMT) == S_IFREG) {
		if (!strcmp(name, "addr_origin")) {
			printf("%s: skip attr %s, internal only\n",
			       __func__, pathname);
			free(pathname);
			return 0;
		}
		ret = read_attr(pathname, value, sizeof(value));
		if (ret > 0 && strlen(value) && !strcmp(name, "device_path")) {
			char *node_name = ctx->node_name;
			char *tmp = strdup(value);

			if (!node_name)
				node_name = "localhost";

			/*
			 * Prefix the device path with the node name to
			 * indicate on which node the namespace resides.
			 */
			sprintf(value, "%s:%s", ctx->node_name, tmp);
			free(tmp);
		}
	} else {
		if ((st.st_mode & S_IFMT) != S_IFDIR)
			fprintf(stderr, "%s: skip unhandled attr %s mode %x\n",
				__func__, pathname, (st.st_mode & S_IFMT));
		free(pathname);
		return 0;
	}
	key = path_to_key(ctx, pathname);
	if (!key) {
		free(pathname);
		return -ENOMEM;
	}
	if (ret < 0) {
		fprintf(stderr, "%s: %s value error %d\n",
			__func__, key, ret);
		goto out_free;
	}

	memset(old, 0, sizeof(old));
	ret = etcd_kv_get(ctx, key, old);
	if (ret < 0) {
		if (ret != -ENOENT) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
			goto out_free;
		}
		if (configfs_debug)
			printf("%s: upload key %s value '%s'\n", __func__,
			       key, value);

		ret = etcd_kv_store(ctx, key, value);
		if (ret < 0) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
		}
	} else if (strcmp(old, value)) {
		if (configfs_debug)
			printf("%s: update key %s value '%s'\n", __func__,
			       key, value);

		ret = etcd_kv_update(ctx, key, value);
		if (ret < 0)
			fprintf(stderr, "%s: key %s update error %d\n",
				__func__, key, ret);
	}
out_free:
	free(key);
	free(pathname);
	return ret;
}

int upload_configfs(struct etcd_ctx *ctx, const char *dir,
		    const char *file)
{
	char *dirname;
	DIR *sd;
	struct dirent *se;
	int ret;

	if (file) {
		ret = asprintf(&dirname, "%s/%s", dir, file);
		if (ret < 0)
			return -ENOMEM;
	} else {
		dirname = (char *)dir;
	}
	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		if (dirname != dir)
			free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (configfs_debug) {
			char *type_name;

			if (se->d_type == DT_DIR)
				type_name = "dir";
			else if (se->d_type == DT_LNK)
				type_name = "link";
			else if (se->d_type == DT_REG)
				type_name = "file";
			else
				type_name = "unknown";
			printf("%s: checking %s %s %s\n",
			       __func__, type_name, dirname, se->d_name);
		}
		if (!strcmp(se->d_name, "passthru"))
			continue;

		ret = update_value(ctx, dirname, se->d_name);
		if (ret < 0)
			break;

		if (se->d_type == DT_DIR) {
			ret = upload_configfs(ctx, dirname, se->d_name);
			if (ret < 0)
				break;
		}
	}
	closedir(sd);
	if (dirname != dir)
		free(dirname);
	return ret;
}

