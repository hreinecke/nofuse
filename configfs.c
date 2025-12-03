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

struct ana_group {
	struct linked_list list;
	int grpid;
	struct linked_list namespaces;
	struct linked_list optimized;
	struct linked_list non_optimized;
	struct linked_list inaccessible;
	struct linked_list persistent_loss;
};

struct ana_group_entry {
	struct linked_list list;
	struct ana_group *grp;
	unsigned int portid;
	bool is_local;
};

struct ana_ns_entry {
	struct linked_list list;
	struct ana_group *grp;
	char *subsys;
	char *ns;
	bool enabled;
};

LINKED_LIST(ana_group_list);

struct ana_group *find_ana_group(unsigned int ana_grpid)
{
	struct ana_group *tmp_grp, *grp = NULL;

	list_for_each_entry(tmp_grp, &ana_group_list, list) {
		if (tmp_grp->grpid == ana_grpid) {
			grp = tmp_grp;
			break;
		}
	}
	if (grp) {
		printf("%s: using ANA group %u\n",
		       __func__, grp->grpid);
		return grp;
	}
	grp = malloc(sizeof(*grp));
	if (!grp)
		return NULL;

	grp->grpid = ana_grpid;
	INIT_LINKED_LIST(&grp->namespaces);
	INIT_LINKED_LIST(&grp->optimized);
	INIT_LINKED_LIST(&grp->non_optimized);
	INIT_LINKED_LIST(&grp->inaccessible);
	INIT_LINKED_LIST(&grp->persistent_loss);
	list_add(&grp->list, &ana_group_list);
	printf("%s: allocating new ANA group %u\n",
	       __func__, ana_grpid);
	return grp;
}

struct ana_group_entry *find_ana_port(struct ana_group *grp,
				      unsigned int portid,
				      char *state)
{
	struct ana_group_entry *tmp_ge, *ge = NULL;
	struct linked_list *grp_list;

	if (!strcmp(state, "optimized")) {
		grp_list = &grp->optimized;
	} else if (!strcmp(state, "non-optimized")) {
		grp_list = &grp->non_optimized;
	} else if (!strcmp(state, "persistent-loss")) {
		grp_list = &grp->persistent_loss;
	} else {
		grp_list = &grp->inaccessible;
	}

	list_for_each_entry(tmp_ge, grp_list, list) {
		if (tmp_ge->portid == portid) {
			ge = tmp_ge;
			break;
		}
	}
	if (ge) {
		printf("%s: using port %u grp %u state %s\n",
		       __func__, portid, ge->grp->grpid, state);
		return ge;
	}
	ge = malloc(sizeof(*ge));
	if (!ge)
		return NULL;
	ge->grp = grp;
	ge->portid = portid;
	ge->is_local = false;
	list_add(&ge->list, grp_list);
	printf("%s: add new port %u to ana group %u\n",
	       __func__, portid, ge->grp->grpid);
	return ge;
}

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

static void clear_cntlid_range(struct etcd_ctx *ctx, char *old, char *new)
{
	char *p, *n;
	int i = 0;

	memset(new, 0, 1024);
	if (!old)
		return;
	p = old;
	n = strchr(p, ',');
	while (n) {
		if (i != ctx->cluster_id &&
		    (n != p)) {
			strncat(new, p, (n - p) + 1);
		} else {
			strcat(new, ",");
		}
		p = n + 1;
		n = strchr(p, ',');
		i++;
	}
}

int validate_local_port(struct etcd_ctx *ctx, unsigned int portid)
{
	char *key, value[1024];
	int ret = 0;

	ret = asprintf(&key, "%s/ports/%u/addr_origin",
		       ctx->prefix, portid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	if (ret < 0) {
		free(key);
		return ret == -ENOENT ? 0 : ret;
	}
	if (strcmp(ctx->node_name, value))
		ret = -EEXIST;
	return ret;
}

int update_value_to_key(struct etcd_ctx *ctx,
			const char *dirname, const char *name)
{
	struct stat st;
	char *pathname, value[1024], old[1024], *key;
	int ret;

	memset(value, 0, sizeof(value));
	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	if (!strcmp(name, "addr_origin") ||
	    !strcmp(name, "device_origin")) {
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
		} else
			ret = strlen(value);
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
		else
			ret = strlen(value);
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

		ret = update_value_to_key(ctx, dirname, se->d_name);
		if (ret < 0)
			break;

		if (!strcmp(se->d_name, "addr_trtype")) {
			ret = update_value_to_key(ctx, dirname, "addr_origin");
			if (ret < 0)
				break;
		}
		/* Do not set 'origin' if no device path is set */
		if (!strcmp(se->d_name, "device_path") && ret > 0) {
			ret = update_value_to_key(ctx, dirname, "device_origin");
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

static int validate_ana_grpid(struct etcd_ctx *ctx, const char *subsys,
			      const char *ns)
{
	unsigned long ana_grpid;
	struct ana_group *grp = NULL;
	struct ana_ns_entry *ans = NULL, *tmp_ans;
	char *path, value[1024], *eptr;
	bool ns_enabled = false;
	int ret;

	ret = asprintf(&path, "%s/subsystems/%s/namespaces/%s/enable",
		       ctx->configfs, subsys, ns);
	if (ret < 0)
		return -ENOMEM;

	ret = read_attr(path, value, sizeof(value));
	free(path);
	if (ret < 0)
		return -ENOENT;

	if (strcmp(value, "1"))
		ns_enabled = true;

	ret = asprintf(&path, "%s/subsystems/%s/namespaces/%s/ana_grpid",
		       ctx->configfs, subsys, ns);
	if (ret < 0)
		return -errno;

	ret = read_attr(path, value, sizeof(value));
	free(path);
	if (ret < 0)
		return ret;

	ana_grpid = strtoul(value, &eptr, 10);
	if (ana_grpid == ULONG_MAX || value == eptr) {
		fprintf(stderr, "subsys %s ns %s grpid %s parse error\n",
			subsys, ns, value);
		return -ERANGE;
	}
	grp = find_ana_group(ana_grpid);
	if (!grp)
		return -ENOMEM;
	list_for_each_entry(tmp_ans, &grp->namespaces, list) {
		if (strcmp(tmp_ans->subsys, subsys))
			continue;
		if (!strcmp(tmp_ans->ns, ns)) {
			ans = tmp_ans;
			break;
		}
	}
	if (ans) {
		fprintf(stderr, "subsys %s ns %s allocated with grpid %lu\n",
			subsys, ns, ana_grpid);
		ret = -EEXIST;
	} else {
		ans = malloc(sizeof(*ans));
		if (!ans)
			return -ENOMEM;
		ans->subsys = strdup(subsys);
		ans->ns = strdup(ns);
		ans->grp = grp;
		ans->enabled = ns_enabled;
		list_add(&ans->list, &grp->namespaces);
		printf("%s: adding subsys %s ns %s to ANA group %u\n",
		       __func__, subsys, ns, ans->grp->grpid);
	}

	return ret;
}

static int validate_namespaces(struct etcd_ctx *ctx, const char *subsys)
{
	DIR *sd;
	struct dirent *se;
	char *dirname;
	int ret;

	printf("%s: validating namespaces for subsys %s\n",
	       __func__, subsys);
	ret = asprintf(&dirname, "%s/subsystems/%s/namespaces",
		       ctx->configfs, subsys);
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
		unsigned long nsid;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (se->d_type != DT_DIR)
			continue;

		printf("%s: validating subsys %s ns %s\n",
		       __func__, subsys, se->d_name);
		nsid = strtoul(se->d_name, NULL, 10);
		if (nsid == ULONG_MAX)
			continue;
		printf("%s: validate %s namespace %lu\n",
		       __func__, subsys, nsid);

		ret = etcd_validate_namespace(ctx, subsys, nsid);
		if (ret < 0 && ret != -ENOENT) {
			ret = etcd_test_namespace(ctx, subsys, nsid);
			if (ret < 0)
				continue;
			if (ret == 1) {
				fprintf(stderr,
					"%s: subsys %s namespace %s is remote\n",
					__func__, subsys, se->d_name);
				ret = -EEXIST;
				break;
			}
		}
		ret = validate_ana_grpid(ctx, subsys, se->d_name);
		if (ret < 0)
			break;
		ret = 0;
	}
	closedir(sd);
	free(dirname);
	return ret;
}

static int validate_port(struct etcd_ctx *ctx, char *port)
{
	unsigned long portid;
	char *dirname, *eptr;
	DIR *sd;
	struct dirent *se;
	int ret;

	portid = strtoul(port, &eptr, 10);
	if (portid == ULONG_MAX || port == eptr)
		return -ERANGE;

	ret = asprintf(&dirname, "%s/ports/%lu/ana_groups",
		       ctx->configfs, portid);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		char *path, value[1024];
		unsigned long ana_grpid;
		struct ana_group *grp;
		struct ana_group_entry *ge;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;

		ana_grpid = strtoul(se->d_name, NULL, 10);
		if (ana_grpid == ULONG_MAX)
			continue;
		grp = find_ana_group(ana_grpid);
		if (!grp)
			continue;
		ret = asprintf(&path, "%s/%s/ana_state",
			       dirname, se->d_name);
		if (ret < 0)
			continue;
		ret = read_attr(path, value, sizeof(value));
		free(path);
		if (ret < 0)
			continue;
		ge = find_ana_port(grp, portid, value);
		if (!ge)
			continue;
		ge->is_local = true;
	}
	closedir(sd);
	free(dirname);
	return ret;
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

		ret = validate_namespaces(ctx, se->d_name);
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
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;

		ret = validate_port(ctx, se->d_name);
		if (ret < 0)
			break;
	}
	closedir(sd);
	free(dirname);
	return ret;
}

int load_ana(struct etcd_ctx *ctx)
{
	struct etcd_kv *kvs;
	char *key;
	int ret, num_kvs, i;

	ret = asprintf(&key, "%s/ports", ctx->prefix);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	num_kvs = ret;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv =&kvs[i];
		char *attr, *p, *eptr;
		unsigned long portid, ana_grpid;
		struct ana_group *grp;
		struct ana_group_entry *ge = NULL;
		bool is_local = false;

		attr = kv->key + strlen(ctx->prefix) + 7;
		p = strrchr(attr, '/');
		if (!p || strcmp(p, "/ana_state"))
			continue;
		portid = strtoul(attr, &eptr, 10);
		if (portid == ULONG_MAX || attr == eptr)
			continue;
		ret = validate_local_port(ctx, portid);
		if (ret == 0)
			is_local = true;

		if (!strcmp(eptr, "/ana_groups/"))
			continue;
		p = eptr + strlen("/ana_groups/");
		ana_grpid = strtoul(p, &eptr, 10);
		if (ana_grpid == ULONG_MAX || p == eptr)
			continue;
		printf("%s: parsing %s portid %lu ana grpid %lu\n",
		       __func__, kv->key, portid, ana_grpid);
		grp = find_ana_group(ana_grpid);
		if (!grp)
			continue;
		ge = find_ana_port(grp, portid, kv->value);
		if (!ge)
			continue;
		ge->is_local = is_local;
	}
	etcd_kv_free(kvs, num_kvs);
	return ret;
}

int validate_ana(struct etcd_ctx *ctx)
{
	struct ana_group *grp;

	list_for_each_entry(grp, &ana_group_list, list) {
		struct ana_group_entry *ge;
		struct ana_ns_entry *ns;
		bool ns_enabled = false, is_local = false;

		list_for_each_entry(ns, &grp->namespaces, list) {
			if (ns->enabled)
				ns_enabled = true;
		}
		if (!ns_enabled) {
			printf("%s: ANA group %u no namespaces enabled\n",
			       __func__, grp->grpid);
			continue;
		}
		list_for_each_entry(ge, &grp->optimized, list) {
			if (ge->is_local)
				is_local = true;
		}
		if (!is_local) {
			fprintf(stderr, "%s: ANA group %u no local ports\n",
				__func__, grp->grpid);
			return -EINVAL;
		}
	}
	return 0;
}

int purge_ports(struct etcd_ctx *ctx)
{
	struct etcd_kv *kvs;
	char *key;
	int num_kvs, i, ret;

	ret = asprintf(&key, "%s/ports", ctx->prefix);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	num_kvs = ret;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *attr;

		attr = strrchr(kv->key, '/');
		if (!attr)
			continue;
		if (strcmp(attr, "/addr_origin"))
			continue;
		if (strcmp(kv->value, ctx->node_name))
			continue;
		*attr = '\0';
		if (configfs_debug)
			printf("Deleting port '%s'\n", kv->key);
		ret = etcd_kv_delete(ctx, kv->key);
		if (ret < 0) {
			fprintf(stderr, "%s: failed to delete '%s'\n",
				__func__, kv->key);
			break;
		}
	}
	etcd_kv_free(kvs, num_kvs);
	return ret;
}

int purge_subsystems(struct etcd_ctx *ctx)
{
	struct etcd_kv *kvs;
	char *key, empty_range[1024];
	int num_kvs, ret, i;

	memset(empty_range, ',', 1024);

	ret = asprintf(&key, "%s/subsystems", ctx->prefix);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	num_kvs = ret;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char value[1024], *p;

		p = strrchr(kv->key, '/');
		if (!p)
			continue;
		if (strcmp(p, "/attr_cntlid_range"))
			continue;

		if (!kv->value)
			continue;
		clear_cntlid_range(ctx, kv->value, value);
		if (!strcmp(kv->value, value))
			continue;
		if (configfs_debug)
			printf("%s: new range '%s'\n",
			       __func__, value);
		ret = etcd_kv_update(ctx, kv->key, value);
		if (ret < 0) {
			if (configfs_debug)
				fprintf(stderr, "%s: failed to update key '%s'\n",
					__func__, kv->key);
			break;
		}
		if (!strncmp(value, empty_range, ctx->cluster_size)) {
			strcpy(value, kv->key);
			p = strrchr(value, '/');
			*p = '\0';
			if (configfs_debug)
				printf("%s: delete subsystem '%s'\n",
				       __func__, value);
			ret = etcd_kv_delete(ctx, value);
			if (ret < 0) {
				if (configfs_debug)
					fprintf(stderr,
						"%s: failed to delete %s\n",
						__func__, value);
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return ret;
}
