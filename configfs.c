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

char *path_to_key(struct etcd_ctx *ctx, const char *path)
{
	const char *attr = path + strlen(ctx->configfs) + 1;
	char *key;
	int ret;

	if (!strncmp(attr, "ports/", 6)) {
		struct port_map_entry *p;
		const char *suffix = attr + 6;
		char *eptr;
		unsigned long port, c_port = ULONG_MAX, port_max = 0;

		port = strtoul(suffix, &eptr, 10);
		if (port == ULONG_MAX || suffix == eptr) {
			fprintf(stderr, "Cannot parse port path '%s'\n",
				path);
			return NULL;
		}
		if (*eptr != '/') {
			fprintf(stderr, "Cannot parse port path '%s'\n",
				path);
			return NULL;
		}
		suffix = eptr + 1;
		list_for_each_entry(p, &ctx->port_map_list, list) {
			if (strcmp(p->node_id, ctx->node_id))
				continue;
			if (p->node_port == port) {
				c_port = p->cluster_port;
			}
			if (p->cluster_port > port_max)
				port_max = p->cluster_port;
		}
		if (c_port == ULONG_MAX) {
			port_max++;
			p = malloc(sizeof(*p));
			memset(p, 0, sizeof(*p));
			p->node_id = strdup(ctx->node_id);
			p->node_port = port;
			p->cluster_port = ++port_max;
			list_add(&p->list, &ctx->port_map_list);
			c_port = p->cluster_port;
		}
		ret = asprintf(&key, "%s/ports/%ld/%s",
			       ctx->prefix, c_port, suffix);
	} else {
		ret = asprintf(&key, "%s/%s", ctx->prefix, attr);
	}
	if (ret < 0)
		return NULL;
	return key;
}

int update_value(struct etcd_ctx *ctx,
		 const char *dirname, const char *name)
{
	struct stat st;
	char *pathname, value[1024], old[1024], *key;
	int ret;

	memset(value, 0, sizeof(value));
	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	if (!strcmp(name, "addr_origin")) {
		/* Synthetic attribute, not present in configfs */
		char *port = strrchr(dirname, '/');
		if (!port) {
			free(pathname);
			return -EINVAL;
		}
		port++;
		sprintf(value, "%s:%s",
			ctx->node_name ? ctx->node_name : "localhost",
			port);
		ret = 0;
		goto store_key;
	}
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
		ret = read_attr(pathname, value, sizeof(value));
	} else {
		if ((st.st_mode & S_IFMT) != S_IFDIR)
			fprintf(stderr, "%s: skip unhandled attr %s mode %x\n",
				__func__, pathname, (st.st_mode & S_IFMT));
		free(pathname);
		return 0;
	}
store_key:
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
		dirname = strdup(dir);
	}
	ret = 0;
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

		if (!strcmp(se->d_name, "addr_trtype")) {
			ret = update_value(ctx, dirname, "addr_origin");
			if (ret < 0)
				break;
		}
		if (se->d_type == DT_DIR) {
			ret = upload_configfs(ctx, dirname, se->d_name);
			if (ret < 0)
				break;
		}
	}
	closedir(sd);
	free(dirname);
	return ret;
}

