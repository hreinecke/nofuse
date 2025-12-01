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

	ret = asprintf(&key, "%s/%s", ctx->prefix, attr);
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
		strcpy(value, ctx->node_name);
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
	if (!strcmp(name, "attr_cntlid_min")) {
		unsigned long cntlid, cluster_spacing, cluster_id;
		size_t off;
		char *eptr;
		int i;

		cntlid = strtoul(value, &eptr, 10);
		if (cntlid == ULONG_MAX || value == eptr) {
			fprintf(stderr, "%s: %s parse error\n",
				__func__, name);
			ret = -ERANGE;
			goto out_free;
		}
		/* Controller ID 0 is invalid */
		if (cntlid == 1) {
			cntlid = 0;
		}
		cluster_spacing = CLUSTER_MAX_SIZE / ctx->cluster_size;
		printf("%s: using cluster spacing %lx\n",
		       __func__, cluster_spacing);
		if (cntlid % (cluster_spacing + 1)) {
			fprintf(stderr, "%s: %s %lu not cluster boundary\n",
				__func__, name, cntlid);
			ret = -EINVAL;
			goto out_free;
		}
		cluster_id = cntlid / (cluster_spacing + 1);
		if (ctx->cluster_id == -1) {
			ctx->cluster_id = cluster_id;
			printf("%s: using cluster id %u\n",
			       __func__, ctx->cluster_id);
		} else if (ctx->cluster_id != cluster_id) {
			cntlid = (ctx->cluster_id * cluster_spacing);
			fprintf(stderr,
				"%s: cluster id mismatch (should be %lu)\n",
				__func__, cntlid);
			ret = -EINVAL;
			goto out_free;
		}
		off = 0;
		memset(value, 0, 1024);
		for (i = 0; i < CLUSTER_DEFAULT_SIZE; i++) {
			if (i == ctx->cluster_id) {
				ret = sprintf(value + off, "%lu-%lu", cntlid,
					      cntlid + cluster_spacing);
				off += ret;
			}
			strcat(value + off, ",");
			off++;
		}
		free(pathname);
		ret = asprintf(&pathname, "%s/attr_cntlid_range", dirname);
	}
	if (!strcmp(name, "attr_cntlid_max")) {
		unsigned long cntlid, cluster_spacing;
		char *eptr;

		cntlid = strtoul(value, &eptr, 10);
		if (cntlid == ULONG_MAX || value == eptr) {
			fprintf(stderr, "%s: %s parse error\n",
				__func__, name);
			goto out_free;
		}
		cluster_spacing = CLUSTER_MAX_SIZE / ctx->cluster_size;
		if ((cntlid + 1) % cluster_spacing) {
			fprintf(stderr, "%s: %s not cluster boundary\n",
				__func__, name);
			goto out_free;
		}
		printf("%s: skip attr %s\n",
		       __func__, name);
		goto out_free;
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
		free(key);
		goto out_free;
	}

	memset(old, 0, sizeof(old));
	ret = etcd_kv_get(ctx, key, old);
	if (ret < 0) {
		if (ret != -ENOENT) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
			free(key);
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
	free(key);
out_free:
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
	bool upload_ports = false;

	if (!strcmp(file, "ports"))
		upload_ports = true;
	ret = asprintf(&dirname, "%s/%s", dir, file);
	if (ret < 0)
		return -ENOMEM;

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

		if (upload_ports) {
			char *path, *key, value[1024];

			/* Check for port number mismatch */
			ret = asprintf(&path, "%s/%s/addr_origin",
				       dirname, se->d_name);
			if (ret < 0) {
				ret = -ENOMEM;
				goto out;
			}
			key = path_to_key(ctx, path);
			if (!key) {
				free(path);
				ret = -ENOMEM;
				goto out;
			}
			free(path);
			ret = etcd_kv_get(ctx, key, value);
			free(key);
			if (ret < 0)
				goto update;
			if (strcmp(value, ctx->node_name)) {
				fprintf(stderr, "%s: port %s already "
					"registered for %s\n",
					__func__, se->d_name, value);
				ret = -EEXIST;
				goto out;
			}
		}
	update:
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
out:
	closedir(sd);
	free(dirname);
	return ret;
}
