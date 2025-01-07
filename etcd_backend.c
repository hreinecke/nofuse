#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <uuid/uuid.h>

#include "common.h"
#include "etcd_backend.h"
#include "etcd_client.h"
#include "firmware.h"

struct key_value_template {
	const char *key;
	const char *value;
};

int etcd_set_discovery_nqn(struct etcd_ctx *ctx, const char *buf)
{
	struct etcd_kv kv;
	char *key;
	int ret;

	ret = asprintf(&key, "%s/discovery_nqn", ctx->prefix);
	if (ret < 0)
		return ret;
	kv.key = key;
	kv.value = buf;
	kv.ignore_lease = false;
	kv.lease = 0;
	ret = etcd_kv_put(ctx, &kv);
	free(key);
	return ctx->resp_val;
}

int etcd_get_discovery_nqn(struct etcd_ctx *ctx, char *buf)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/discovery_nqn", ctx->prefix);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, buf);
	free(key);
	return ret;
}

static int _count_key_range(struct etcd_ctx *ctx, char *key, int *num)
{
	struct etcd_kv *kvs;
	int val = 0, ret, i;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key)))
			val++;
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	*num = val;
	return 0;
}

int etcd_count_root(struct etcd_ctx *ctx, const char *root, int *nlinks)
{
	struct etcd_kv *kvs;
	char *key, *attr;
	int ret, num = 0, i;

	ret = asprintf(&key, "%s/%s", ctx->prefix, root);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_key";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_allow_any_host";
	else if (!strcmp(root, "ports"))
		attr = "addr_traddr";
	else
		return -EINVAL;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];
		const char *p;

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, attr))
				num++;
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	printf("%s: root %s %d elements\n", __func__, root, num);
	free(kvs);
	*nlinks = num;
	return 0;
}

int etcd_fill_root(struct etcd_ctx *ctx, const char *root,
		   void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *attr, *p;
	int ret, key_offset, i;

	ret = asprintf(&key, "%s/%s/", ctx->prefix, root);
	if (ret < 0)
		return ret;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_hash";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_allow_any_host";
	else if (!strcmp(root, "ports"))
		attr = "addr_traddr";
	else
		return -EINVAL;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, attr)) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	return 0;
}

#define NUM_HOST_ATTRS 4
static struct key_value_template host_template[NUM_HOST_ATTRS] = {
	{ .key = "dhchap_key", .value = "" },
	{ .key = "dhchap_hash", .value = "sha(256)" },
	{ .key = "dhchap_dhgroup", .value = "" },
	{ .key = "dhchap_ctrl_key", .value = "" },
};

int etcd_fill_host_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "hosts", buf, filler);
}

int etcd_fill_host(struct etcd_ctx *ctx, const char *nqn,
		   void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_HOST_ATTRS; i++) {
		struct key_value_template *kv = &host_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int etcd_add_host(struct etcd_ctx *ctx, const char *nqn)
{
	int ret, i;

	for (i = 0; i < NUM_HOST_ATTRS; i++) {
		struct key_value_template *kv = &host_template[i];
		char *key;

		ret = asprintf(&key, "%s/hosts/%s/%s",
			       ctx->prefix, nqn, kv->key);
		if (ret < 0)
			return ret;
		ret = etcd_kv_new(ctx, key, (char *)kv->value);
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_host(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/dhchap_hash",
		       ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, NULL);
	free(key);
	return ret;
}

int etcd_get_host_attr(struct etcd_ctx *ctx, const char *nqn,
		       const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, value);
	free(key);
	if (ret == -ENOENT) {
		int i;

		for (i = 0; i < NUM_HOST_ATTRS; i++) {
			struct key_value_template *kv = &host_template[i];

			if (!strcmp(kv->key, attr)) {
				if (value)
					*value = '\0';
				return 0;
			}
		}
	}
	return ret;
}

int etcd_del_host(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s", ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_PORT_ATTRS 8
static struct key_value_template port_template[NUM_PORT_ATTRS] = {
	{ .key = "addr_trtype", .value = "tcp" },
	{ .key = "addr_adrfam", .value = "ipv4" },
	{ .key = "addr_traddr", .value = "127.0.0.1" },
	{ .key = "addr_trsvcid", .value = "" },
	{ .key = "addr_treq", .value = "not specified" },
	{ .key = "addr_tsas", .value = "none" },
	{ .key = "addr_node", .value = "" },
	{ .key = "addr_origin", .value = "" },
};

int etcd_fill_port_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "ports", buf, filler);
}

int etcd_fill_port(struct etcd_ctx *ctx, unsigned int id,
		   void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	filler(buf, "ana_groups", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "referrals", NULL, 0, FUSE_FILL_DIR_PLUS);
	return 0;
}

int etcd_add_port(struct etcd_ctx *ctx, const char *origin,
		  unsigned int id, const char *traddr, unsigned int port)
{
	int ret, i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];
		char portnum[16], *key;
		const char *value;

		ret = asprintf(&key, "%s/ports/%d/%s",
			       ctx->prefix, id, kv->key);
		if (ret < 0)
			return ret;
		value = kv->value;
		if (!strcmp(kv->key, "addr_node")) {
			if (ctx->node_name)
				value = ctx->node_name;
		} else if (!strcmp(kv->key, "addr_traddr")) {
			if (traddr)
				value = traddr;
		} else if (!strcmp(kv->key, "addr_trsvcid")) {
			if (port > 0) {
				sprintf(portnum, "%d", port);
				value = portnum;
			}
		} else if (!strcmp(kv->key, "addr_origin")) {
			if (origin)
				value = origin;
		}
		ret = etcd_kv_new(ctx, key, value);
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_port(struct etcd_ctx *ctx, unsigned int id)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/addr_trtype",
		       ctx->prefix, id);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, NULL);
	free(key);
	return ret;
}

int etcd_set_port_attr(struct etcd_ctx *ctx, unsigned int id,
		       const char *attr, const char *value)
{
	char *key;
	int ret = -ENOENT, i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];

		if (!strcmp(kv->key, attr)) {
			ret = 0;
			break;
		}
	}
	if (ret < 0)
		return ret;

	ret = asprintf(&key, "%s/ports/%d/%s",
		       ctx->prefix, id, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_port_attr(struct etcd_ctx *ctx, unsigned int id,
		       const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/%s",
		       ctx->prefix, id, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	if (ret == -ENOENT) {
		int i;

		for (i = 0; i < NUM_PORT_ATTRS; i++) {
			struct key_value_template *kv = &port_template[i];

			if (!strcmp(kv->key, attr)) {
				if (value)
					*value = '\0';
				return 0;
			}
		}
	}
	return ret;
}

int etcd_del_port(struct etcd_ctx *ctx, unsigned int id)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d", ctx->prefix, id);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_count_ana_groups(struct etcd_ctx *ctx, int id, int *ngrps)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/ana_groups",
		       ctx->prefix, id);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, ngrps);
	free(key);
	return ret;
}

int etcd_fill_ana_groups(struct etcd_ctx *ctx, const char *port,
			 void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *p;
	int ret, key_offset, i;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, "ana_state")) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	return 0;
}

int etcd_add_ana_group(struct etcd_ctx *ctx, int portid,
		       int ana_grpid, int ana_state)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%d/ana_state",
		       ctx->prefix, portid, ana_grpid);
	if (ret < 0)
		return ret;
	switch(ana_state) {
	case NVME_ANA_OPTIMIZED:
		value = "optimized";
		break;
	case NVME_ANA_NONOPTIMIZED:
		value = "non-optimized";
		break;
	case NVME_ANA_INACCESSIBLE:
		value = "inaccessible";
		break;
	case NVME_ANA_PERSISTENT_LOSS:
		value = "persistent-loss";
		break;
	case NVME_ANA_CHANGE:
		value = "change";
		break;
	default:
		return -EINVAL;
	}
	ret = etcd_kv_new(ctx, key, value);
	free(key);
	return ret;
}

int etcd_get_ana_group(struct etcd_ctx *ctx, int portid,
		       const char *ana_grp, char *ana_state)
{
	int ret = -ENOENT;
	char *key;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%s/ana_state",
		       ctx->prefix, portid, ana_grp);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, ana_state);
	free(key);
	return ret;
}

int etcd_set_ana_group(struct etcd_ctx *ctx, int portid,
		       const char *ana_grp, char *ana_state)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%s/ana_state",
		       ctx->prefix, portid, ana_grp);
	if (ret < 0)
		return ret;

	if (strcmp(ana_state, "optimized") &&
	    strcmp(ana_state, "non-optimized") &&
	    strcmp(ana_state, "inaccessible") &&
	    strcmp(ana_state, "persistent-loss") &&
	    strcmp(ana_state, "change"))
		return -EINVAL;

	ret = etcd_kv_update(ctx, key, ana_state);
	free(key);
	return ret;
}

int etcd_del_ana_group(struct etcd_ctx *ctx, int portid, int ana_grpid)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%d/ana_state",
		       ctx->prefix, portid, ana_grpid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_SUBSYS_ATTRS 9
static struct key_value_template subsys_template[NUM_SUBSYS_ATTRS] = {
	{ .key = "attr_allow_any_host", .value = "1" },
	{ .key = "attr_firmware", .value = "" },
	{ .key = "attr_ieee_oui", .value = "851255" },
	{ .key = "attr_model", .value = "nofuse" },
	{ .key = "attr_serial", .value = "nofuse" },
	{ .key = "attr_version", .value = "2.0" },
	{ .key = "attr_type", .value = "3" },
	{ .key = "attr_qid_max", .value = "" },
	{ .key = "attr_pi_enable", .value = "0" },
};

int etcd_fill_subsys_dir(struct etcd_ctx *ctx, void *buf,
			 fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "subsystems", buf, filler);
}

int etcd_fill_subsys(struct etcd_ctx *ctx, const char *subsys,
		     void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kv = &subsys_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	filler(buf, "allowed_hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "namespaces", NULL, 0, FUSE_FILL_DIR_PLUS);
	return 0;
}

int etcd_add_subsys(struct etcd_ctx *ctx, const char *nqn, int type,
		    bool permanent)
{
	int ret, i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kvt = &subsys_template[i];
		struct etcd_kv kv;
		char *key;

		ret = asprintf(&key, "%s/subsystems/%s/%s",
			       ctx->prefix, nqn, kvt->key);
		if (ret < 0)
			return ret;
		kv.key = key;
		kv.ignore_lease = false;
		if (permanent)
			kv.lease = 0;
		else
			kv.lease = ctx->lease;
		if (!strcmp(kvt->key, "attr_type")) {
			char type_str[3];

			sprintf(type_str, "%d", type);
			ret = etcd_kv_new(ctx, key, type_str);
		} else if (!strcmp(kvt->key, "attr_firmware")) {
			kv.value = firmware_rev;
			ret = etcd_kv_put(ctx, &kv);
		} else {
			kv.value = kvt->value;
			ret = etcd_kv_put(ctx, &kv);
		}
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_subsys(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/attr_allow_any_host",
		       ctx->prefix, nqn);
	if (ret < 0)
		return false;
	printf("%s: key %s\n", __func__, key);
	ret = etcd_kv_get(ctx, key, NULL);
	printf("%s: ret %d\n", __func__, ret);
	free(key);
	return ret;
}

int etcd_set_subsys_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *attr, const char *value)
{
	char *key;
	int ret = -ENOENT, i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kv = &subsys_template[i];

		if (!strcmp(kv->key, attr)) {
			ret = 0;
			break;
		}
	}
	if (ret < 0)
		return ret;

	ret = asprintf(&key, "%s/subsystems/%s/%s",
		       ctx->prefix, subsysnqn, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_subsys_attr(struct etcd_ctx *ctx, const char *nqn,
			 const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	if (ret == -ENOENT) {
		int i;

		for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
			struct key_value_template *kv = &subsys_template[i];

			if (!strcmp(kv->key, attr)) {
				if (value)
					*value = '\0';
				return 0;
			}
		}
	}
	return ret;
}

int etcd_del_subsys(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s", ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_fill_subsys_port(struct etcd_ctx *ctx, int id,
			  void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val;
	int ret, num = 0, i;

	ret = asprintf(&key, "%s/ports/%d/subsystems",
		       ctx->prefix, id);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key))) {
			val = strrchr(kv->key, '/');
			if (val) {
				val++;
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				num++;
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	free(key);
	printf("%s: %d elements\n", __func__, num);
	return 0;
}

int etcd_add_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn, int id)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/subsystems/%s",
		       ctx->prefix, id, subsysnqn);
	if (ret < 0)
		return ret;
	ret = asprintf(&value, "../../../subsystems/%s", subsysnqn);
	if (ret < 0) {
		free(key);
		return ret;
	}
	ret = etcd_kv_new(ctx, key, value);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 int id, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/subsystems/%s",
		       ctx->prefix, id, subsysnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_del_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn, int id)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/subsystems/%s",
		       ctx->prefix, id, subsysnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_fill_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn,
			  void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val;
	int ret, num = 0, i;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key))) {
			val = strrchr(kv->key, '/');
			if (val) {
				val++;
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				num++;
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	free(key);
	printf("%s: %d elements\n", __func__, num);
	return 0;
}

int etcd_count_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn,
			   int *nhosts)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nhosts);
	free(key);
	return ret;
}

int etcd_add_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = asprintf(&value, "../../../hosts/%s", hostnqn);
	if (ret < 0) {
		free(key);
		return ret;
	}
	ret = etcd_kv_new(ctx, key, value);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_del_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_NS_ATTRS 7
static struct key_value_template ns_template[NUM_NS_ATTRS] = {
	{ .key = "device_eui64", .value = "" },
	{ .key = "device_nguid", .value = "" },
	{ .key = "device_uuid", .value = "" },
	{ .key = "device_path", .value = "" },
	{ .key = "device_node", .value = "" },
	{ .key = "ana_group_id", .value = "1" },
	{ .key = "enable", .value = "0" },
};

int etcd_fill_namespace_dir(struct etcd_ctx *ctx, const char *subsysnqn,
			    void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *p;
	int ret, key_offset, i;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, "device_uuid")) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	return 0;
}

int etcd_fill_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid,
			void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int etcd_count_namespaces(struct etcd_ctx *ctx, const char *subsysnqn, int *nns)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nns);
	free(key);
	return ret;
}

int etcd_add_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key;
	int ret, i;
	uuid_t uuid;
	char uuid_str[65], nguid_str[33], eui64_str[33];
	unsigned int nguid1, nguid2;

	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);

	memcpy(&nguid1, &uuid[8], 4);
	memcpy(&nguid2, &uuid[12], 4);
	sprintf(nguid_str, "%08x%08x%s",
		nguid1, nguid2, NOFUSE_NGUID_PREFIX);

	sprintf(eui64_str, "0efd37%hhx%08x",
		uuid[11], nguid2);

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];
		const char *value;

		ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
			       ctx->prefix, subsysnqn, nsid, kv->key);
		if (ret < 0)
			continue;

		if (!strcmp(kv->key, "device_nguid"))
			value = nguid_str;
		else if (!strcmp(kv->key, "device_eui64"))
			value = eui64_str;
		else if (!strcmp(kv->key, "device_uuid"))
			value = uuid_str;
		else if (!strcmp(kv->key, "device_node"))
			value = ctx->node_name;
		else
			value = kv->value;
		if (value)
			ret = etcd_kv_new(ctx, key, value);
		free(key);
	}
	return ret;
}

int etcd_test_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/enable",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, NULL);
	free(key);
	return ret;
}

int etcd_set_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr, const char *value)
{
	char *key;
	int ret = -ENOENT, i;

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];

		if (!strcmp(kv->key, attr)) {
			ret = 0;
			break;
		}
	}
	if (ret < 0)
		return ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
		       ctx->prefix, subsysnqn, nsid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
		       ctx->prefix, subsysnqn, nsid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	if (ret == -ENOENT) {
		int i;

		for (i = 0; i < NUM_NS_ATTRS; i++) {
			struct key_value_template *kv = &ns_template[i];

			if (!strcmp(kv->key, attr)) {
				if (value)
					*value = '\0';
				return 0;
			}
		}
	}
	return ret;
}

int etcd_set_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int ana_grpid)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/ana_group_id",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = asprintf(&value, "%d", ana_grpid);
	if (ret < 0) {
		free(key);
		return ret;
	}
	ret = etcd_kv_update(ctx, key, value);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int *ana_grpid)
{
	struct etcd_kv *kvs;
	int ret, i;
	char *key;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/ana_group_id",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strcmp(kv->key, "ana_group_id")) {
			unsigned long val;
			char *eptr = NULL;

			val = strtoul(kv->value, &eptr, 10);
			if (val == ULONG_MAX || kv->value == eptr)
				ret = -ERANGE;
			else {
				*ana_grpid = val;
				ret = 0;
			}
		}
		free((char *)kv->key);
		free((char *)kv->value);
	}
	free(kvs);
	return ret;
}

int etcd_del_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_count_subsys_port(struct etcd_ctx *ctx, int portid, int *nsubsys)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/subsystems",
		       ctx->prefix, portid);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nsubsys);
	free(key);
	return ret;
}

int etcd_get_cntlid(struct etcd_ctx *ctx, const char *subsysnqn, u16 *cntlid)
{
	return -ENOTSUP;
}

int etcd_host_disc_entries(const char *hostnqn, u8 *log, int log_len)
{
	return -ENOTSUP;
}

int etcd_host_genctr(const char *hostnqn, int *genctr)
{
	return -ENOTSUP;
}

int etcd_subsys_identify_ctrl(const char *subsysnqn,
			      struct nvme_id_ctrl *id)
{
	return -ENOTSUP;
}
