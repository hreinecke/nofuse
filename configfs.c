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

static void transform_cntlid_range(struct etcd_ctx *ctx, char *old, char *value)
{
	char new[1024], *p, *n;
	int i = 0;

	memset(new, 0, 1024);
	p = old;
	n = strchr(p, ',');
	while (n) {
		if (i != ctx->cluster_id) {
			if (n == p) {
				strcat(new, ",");
			} else {
				strncat(new, p, (n - p) + 1);
			}
		} else {
			strcat(new, value);
			strcat(new, ",");
		}
		p = n + 1;
		n = strchr(p, ',');
		i++;
	}
	strcpy(value, new);
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
		unsigned long cntlid, cluster_spacing;
		char *eptr;

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
		sprintf(value, "%lu-%lu", cntlid,
			cntlid + cluster_spacing);
		free(pathname);
		ret = asprintf(&pathname, "%s/attr_cntlid_range", dirname);
	}
	if (!strcmp(name, "attr_cntlid_max")) {
		if (configfs_debug)
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
		if (!strcmp(name, "attr_cntlid_min")) {
			memset(old, ',', ctx->cluster_size);
			transform_cntlid_range(ctx, old, value);
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
		if (!strcmp(name, "attr_cntlid_min")) {
			transform_cntlid_range(ctx, old, value);
			if (!strcmp(old, value)) {
				free(key);
				goto out_free;
			}
		}
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

static int validate_cluster_id(struct etcd_ctx *ctx, char *subsys,
			       char *value, bool cntlid_max)
{
	unsigned long cntlid, cntlid_min, cluster_spacing, cluster_id;
	char *eptr;

	cluster_spacing = (CLUSTER_MAX_SIZE / ctx->cluster_size);
	cntlid = strtoul(value, &eptr, 10);
	if (cntlid == ULONG_MAX || value == eptr) {
		fprintf(stderr, "%s: %s parse error on %s\n",
			__func__, subsys, value);
		return -ERANGE;
	}
	/* Controller ID 0 is invalid */
	if (cntlid == 1)
		cntlid = 0;
	else if (cntlid_max) {
		cntlid ++;
		cntlid_min = ctx->cluster_id * cluster_spacing;
	}

	if (cntlid % cluster_spacing) {
		fprintf(stderr,
			"%s: subsys %s cntlid_%s %lu not cluster boundary\n",
			__func__, subsys, cntlid_max ? "max": "min", cntlid);
		if (cntlid_max)
			fprintf(stderr, "%s: should be %lu\n", __func__,
				cntlid_min + (cluster_spacing - 1));
		else
			fprintf(stderr, "%s: should be %lu\n", __func__,
				(cntlid / cluster_spacing) * cluster_spacing);
		return -EINVAL;
	} else if (cntlid_max &&
		   (cntlid / cluster_spacing) != ctx->cluster_id + 1) {
		fprintf(stderr, "%s: subsys %s cntlid_max %lu out of range for cluster\n",
			__func__, subsys, cntlid);
		fprintf(stderr, "%s: should be %lu\n", __func__,
			cntlid_min + (cluster_spacing - 1));
		return -EINVAL;
	}
	if (cntlid_max)
		return 0;
	cluster_id = cntlid / cluster_spacing;
	if (ctx->cluster_id == -1) {
		ctx->cluster_id = cluster_id;
		printf("%s: subsys %s using cluster id %u\n",
		       __func__, subsys, ctx->cluster_id);
	} else if (ctx->cluster_id != cluster_id) {
		cntlid = ctx->cluster_id * cluster_spacing;
		fprintf(stderr, "%s: subsys %s cluster id mismatch (should be %lu)\n",
			__func__, subsys, cntlid);
		return -EINVAL;
	}
	return 0;
}

/**
 * validate_cluster -- Validate local settings
 *
 * The local nvmet configfs settings need to be compatible with the cluster
 * to allow for a merge of the local configuration with the existing
 * cluster settings.
 * - The cluster boundary is given by the max number of cntlids divided
 *   by the size of the cluster (ie the possible number of nodes in the cluster)
 * - The cluster id is derived from the 'cntlid_min' subsystem setting.
 *   The 'cntlid_min' setting needs to fall on a cluster boundary, and
 *   the cluster id is the cntlid_min setting divided by the cluster boundary.
 * - 'cntlid_min'/'cntlid_max' settings need to be identical for all
 *   local subsystems
 * - the 'cntlid_max' setting need to fall on a cluster boundary - 1,
 *   and needs to be at the end of the current cluster boundary.
 *
 * The port ids needs to be divided per cluster id; all port ids not
 * in the range of the local cluster node will be rejected.
 */
int validate_cluster(struct etcd_ctx *ctx)
{
	int ret, errors = 0;
	DIR *sd;
	struct dirent *se;
	char *dirname;

	ret = asprintf(&dirname, "%s/subsystems", ctx->configfs);
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
		char *path, value[1024];

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;
		ret = asprintf(&path, "%s/%s/attr_cntlid_min",
			       dirname, se->d_name);
		if (ret < 0) {
			ret = -errno;
			break;
		}
		ret = read_attr(path, value, sizeof(value));
		free(path);
		if (ret < 0)
			break;

		ret = validate_cluster_id(ctx, se->d_name, value, false);
		if (ret < 0) {
			errors++;
			continue;
		}

		ret = asprintf(&path, "%s/%s/attr_cntlid_max",
			       dirname, se->d_name);
		if (ret < 0) {
			ret = -errno;
			break;
		}
		ret = read_attr(path, value, sizeof(value));
		free(path);
		if (ret < 0)
			break;

		ret = validate_cluster_id(ctx, se->d_name, value, true);
		if (ret < 0)
			errors++;
	}
	closedir(sd);
	free(dirname);
	if (ret < 0)
		return ret;
	if (errors)
		return -EINVAL;

	ret = asprintf(&dirname, "%s/ports", ctx->configfs);
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
		char *eptr;
		unsigned long portid, port_spacing, cluster_id;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;

		portid = strtoul(se->d_name, &eptr, 10);
		if (portid == ULONG_MAX || se->d_name == eptr) {
			fprintf(stderr, "%s: port %s parse error\n",
				__func__, se->d_name);
			ret = -ERANGE;
			break;
		}
		port_spacing = (USHRT_MAX  + 1) / ctx->cluster_size;
		printf("%s: using port spacing %lu\n", __func__, port_spacing);
		cluster_id = portid / port_spacing;
		if (cluster_id != ctx->cluster_id) {
			fprintf(stderr, "%s: port %s out of range\n",
				__func__, se->d_name);
			fprintf(stderr, "%s: needs to be range %lu - %lu\n",
				__func__, ctx->cluster_id * port_spacing,
				((ctx->cluster_id + 1) * port_spacing) - 1);
			ret = -ERANGE;
			break;
		}
	}
	closedir(sd);
	free(dirname);
	return ret;
}

int purge_ports(struct etcd_ctx *ctx)
{
	unsigned int portid_begin, portid_end, port_spacing;
	char *key, *end_key;
	int ret;

	port_spacing = (USHRT_MAX + 1) / ctx->cluster_size;
	portid_begin = ctx->cluster_id * port_spacing;
	portid_end = (ctx->cluster_id + 1) * port_spacing;
	while (portid_begin < portid_end) {
		unsigned int portid;
		char end;

		ret = asprintf(&key, "%s/ports/%u",
			       ctx->prefix, portid_begin);
		if (ret < 0)
			return -errno;
		if (portid_begin < 10) {
			if (portid_end < 10)
				portid = portid_end;
			else
				portid = 9;
		} else if (portid_begin < 100) {
			if (portid_end < 100)
				portid = portid_end;
			else
				portid = 99;
		} else if (portid_begin < 1000) {
			if (portid_end < 999)
				portid = portid_end;
			else
				portid = 999;
		} else if (portid_begin < 10000) {
			if (portid_end < 9999)
				portid = portid_end;
			else
				portid = 9999;
		} else
			portid = portid_end;

		ret = asprintf(&end_key, "%s/ports/%u",
			       ctx->prefix, portid);
		if (ret < 0) {
			free(key);
			return -errno;
		}
		end = end_key[strlen(end_key) - 1];
		end++;
		end_key[strlen(end_key) - 1] = end;
		printf("Deleting port '%s' to '%s'\n",
		       key, end_key);
		ret = etcd_kv_delete_range(ctx, key, end_key);
		if (ret < 0 && ret != -ENOKEY) {
			fprintf(stderr, "%s: failed to delete port keys\n",
				__func__);
			break;
		}
		portid_begin = portid + 1;
		free(end_key);
		free(key);
	}

	return ret;
}
