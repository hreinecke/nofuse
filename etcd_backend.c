#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <json-c/json.h>

#include "common.h"
#include "etcd_backend.h"
#include "etcd_client.h"
#include "firmware.h"

struct key_value_template {
	const char *key;
	const char *value;
};

static struct etcd_ctx *ctx;

int etcd_set_discovery_nqn(char *buf)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/discovery_nqn", ctx->prefix);
	if (ret < 0)
		return ret;

	ret = etcd_kv_put(ctx, key, buf, true);
	free(key);
	return ret;
}

int etcd_get_discovery_nqn(char *buf)
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

static int _count_key_range(char *key, int *num)
{
	struct json_object *resp;
	struct json_object_iterator its, ite;
	int val = 0;

	resp = etcd_kv_range(ctx, key);
	if (!resp)
		return -errno;

	its = json_object_iter_begin(resp);
	ite = json_object_iter_end(resp);
 
	while (!json_object_iter_equal(&its, &ite)) {
		val++;
		json_object_iter_next(&its);
	}
	json_object_put(resp);
	*num = val;
	return 0;
}

int etcd_count_root(const char *root, int *nlinks)
{
	struct json_object *resp;
	struct json_object_iterator its, ite;
	char *key, *attr;
	int ret, num = 0;

	ret = asprintf(&key, "%s/%s", ctx->prefix, root);
	if (ret < 0)
		return ret;
	resp = etcd_kv_range(ctx, key);
	free(key);
	if (!resp)
		return -errno;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_key";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_type";
	else if (!strcmp(root, "ports"))
		attr = "addr_traddr";
	else
		return -EINVAL;
			
	its = json_object_iter_begin(resp);
	ite = json_object_iter_end(resp);

	while (!json_object_iter_equal(&its, &ite)) {
		const char *k, *p;

		k = json_object_iter_peek_name(&its);
		p = strrchr(k, '/');
		if (p) {
			p++;
			if (!strcmp(p, attr))
				num++;
		}
		json_object_iter_next(&its);
	}
	printf("%s: root %s %d elements\n", __func__, root, num);
	json_object_put(resp);
	*nlinks = num;
	return 0;
}

int etcd_fill_root(const char *root, void *buf, fuse_fill_dir_t filler)
{
	struct json_object *resp;
	char *key, *val, *attr, *p;
	int ret, key_offset;

	ret = asprintf(&key, "%s/%s/", ctx->prefix, root);
	if (ret < 0)
		return ret;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_hash";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_type";
	else if (!strcmp(root, "ports"))
		attr = "addr_traddr";
	else
		return -EINVAL;

	key_offset = strlen(key);
	resp = etcd_kv_range(ctx, key);
	free(key);
	if (!resp)
		return -errno;

	json_object_object_foreach(resp, key_obj, val_obj) {
		p = strrchr(key_obj, '/');
		if (!p)
			continue;
		p++;
		if (!strcmp(p, attr)) {
			val = strdup(key_obj + key_offset);
			p = strchr(val, '/');
			if (p)
				*p = '\0';
			filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
			free(val);
		}
	}
	return 0;
}

#define NUM_HOST_ATTRS 4
static struct key_value_template host_template[NUM_HOST_ATTRS] = {
	{ .key = "dhchap_key", .value = "" },
	{ .key = "dhchap_hash", .value = "" },
	{ .key = "dhchap_dhgroup", .value = "" },
	{ .key = "dhchap_ctrl_key", .value = "" },
};

int etcd_fill_host_dir(void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root("hosts", buf, filler);
}

int etcd_fill_host(const char *nqn, void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_HOST_ATTRS; i++) {
		struct key_value_template *kv = &host_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int etcd_add_host(const char *nqn)
{
	int ret, i;

	for (i = 0; i < NUM_HOST_ATTRS; i++) {
		struct key_value_template *kv = &host_template[i];
		char *key;

		ret = asprintf(&key, "%s/hosts/%s/%s",
			       ctx->prefix, nqn, kv->key);
		if (ret < 0)
			return ret;
		ret = etcd_kv_put(ctx, key, kv->value, true);
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_get_host_attr(const char *nqn, const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_del_host(const char *nqn)
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

#define NUM_PORT_ATTRS 6
static struct key_value_template port_template[NUM_PORT_ATTRS] = {
	{ .key = "addr_trtype", .value = "tcp" },
	{ .key = "addr_adrfam", .value = "ipv4" },
	{ .key = "addr_traddr", .value = "" },
	{ .key = "addr_trsvcid", .value = "" },
	{ .key = "addr_treq", .value = "not specified" },
	{ .key = "addr_tsas", .value = "none" },
};

int etcd_fill_port_dir(void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root("ports", buf, filler);
}

int etcd_fill_port(unsigned int id, void *buf, fuse_fill_dir_t filler)
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

int etcd_add_port(unsigned int id)
{
	int ret, i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];
		char *key;

		ret = asprintf(&key, "%s/ports/%d/%s",
			       ctx->prefix, id, kv->key);
		if (ret < 0)
			return ret;
		ret = etcd_kv_put(ctx, key, kv->value, true);
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_set_port_attr(unsigned int id, const char *attr, const char *value)
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
	ret = etcd_kv_put(ctx, key, value, false);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_port_attr(unsigned int id, const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/%s",
		       ctx->prefix, id, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_del_port(unsigned int id)
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

int etcd_count_ana_groups(const char *port, int *ngrps)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/ana_groups",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	ret = _count_key_range(key, ngrps);
	free(key);
	return ret;
}

int etcd_fill_ana_groups(const char *port, void *buf, fuse_fill_dir_t filler)
{
	return -ENOTSUP;
}

int etcd_stat_ana_group(const char *port, const char *ana_grp,
			struct stat *stbuf)
{
	return -ENOTSUP;
}

int etcd_add_ana_group(int portid, int ana_grpid, int ana_state)
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
	ret = etcd_kv_put(ctx, key, value, true);
	free(key);
	return ret;
}

int etcd_get_ana_group(int portid, const char *ana_grp, int *ana_state)
{
	struct json_object *resp;
	int ret = -ENOENT;
	char *key;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%s/ana_state",
		       ctx->prefix, portid, ana_grp);
	if (ret < 0)
		return ret;
	resp = etcd_kv_range(ctx, key);
	free(key);
	if (!resp)
		return -errno;

	json_object_object_foreach(resp, key_obj, val_obj) {
		const char *value;

		if (!strcmp(key_obj, "ana_state")) {
			value = json_object_get_string(val_obj);
			if (!strcmp(value, "optimized")) {
				*ana_state = NVME_ANA_OPTIMIZED;
				ret = 0;
			} else if (!strcmp(value, "non-optimized")) {
				*ana_state = NVME_ANA_NONOPTIMIZED;
				ret = 0;
			} else if (!strcmp(value, "inaccessible")) {
				*ana_state = NVME_ANA_INACCESSIBLE;
				ret = 0;
			} else if (!strcmp(value, "persistent-loss")) {
				*ana_state = NVME_ANA_PERSISTENT_LOSS;
				ret = 0;
			} else if (!strcmp(value, "change")) {
				*ana_state = NVME_ANA_CHANGE;
				ret = 0;
			}
			break;
		}
	}
	json_object_put(resp);
	return ret;
}

int etcd_set_ana_group(int portid, const char *ana_grp, int ana_state)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/ana_groups/%s/ana_state",
		       ctx->prefix, portid, ana_grp);
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
	ret = etcd_kv_put(ctx, key, value, false);
	free(key);
	return ret;
}

int etcd_del_ana_group(int portid, int ana_grpid)
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

int etcd_fill_subsys_dir(void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root("subsystems", buf, filler);
}

int etcd_fill_subsys(const char *subsys, void *buf, fuse_fill_dir_t filler)
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

int etcd_add_subsys(const char *nqn, int type)
{
	int ret, i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kv = &subsys_template[i];
		char *key;

		ret = asprintf(&key, "%s/subsystems/%s/%s",
			       ctx->prefix, nqn, kv->key);
		if (ret < 0)
			return ret;
		if (!strcmp(kv->key, "attr_type")) {
			char type_str[3];

			sprintf(type_str, "%d", type);
			ret = etcd_kv_put(ctx, key, type_str, true);
		} else if (!strcmp(kv->key, "attr_firmware")) {
			ret = etcd_kv_put(ctx, key, firmware_rev, true);
		} else
			ret = etcd_kv_put(ctx, key, kv->value, true);
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_set_subsys_attr(const char *subsysnqn, const char *attr,
			 const char *value)
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
	ret = etcd_kv_put(ctx, key, value, false);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_subsys_attr(const char *nqn, const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_del_subsys(const char *nqn)
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

int etcd_fill_subsys_port(int id, void *buf, fuse_fill_dir_t filler)
{
	return -ENOTSUP;
}

int etcd_add_subsys_port(const char *subsysnqn, int id)
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
	ret = etcd_kv_put(ctx, key, value, true);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_stat_subsys_port(const char *subsysnqn, int id, struct stat *stbuf)
{
	return -ENOTSUP;
}

int etcd_del_subsys_port(const char *subsysnqn, int id)
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

int etcd_fill_host_subsys(const char *subsysnqn, void *buf,
			  fuse_fill_dir_t filler)
{
	return -ENOTSUP;
}

int etcd_count_host_subsys(const char *subsysnqn, int *nhosts)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(key, nhosts);
	free(key);
	return ret;
}

int etcd_add_host_subsys(const char *hostnqn, const char *subsysnqn)
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
	ret = etcd_kv_put(ctx, key, value, true);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			  struct stat *stbuf)
{
	return -ENOTSUP;
}

int etcd_del_host_subsys(const char *hostnqn, const char *subsysnqn)
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

#define NUM_NS_ATTRS 6
static struct key_value_template ns_template[NUM_NS_ATTRS] = {
	{ .key = "device_eui64", .value = "" },
	{ .key = "device_nguid", .value = "" },
	{ .key = "device_uuid", .value = "" },
	{ .key = "device_path", .value = "" },
	{ .key = "ana_group_id", .value = "1" },
	{ .key = "enable", .value = "0" },
};

int etcd_fill_namespace_dir(const char *subsysnqn,
			    void *buf, fuse_fill_dir_t filler)
{
	struct json_object *resp;
	char *key, *val, *p;
	int ret, key_offset;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	key_offset = strlen(key);
	resp = etcd_kv_range(ctx, key);
	free(key);
	if (!resp)
		return -errno;

	json_object_object_foreach(resp, key_obj, val_obj) {
		p = strrchr(key_obj, '/');
		if (!p)
			continue;
		p++;
		if (!strcmp(p, "device_uuid")) {
			val = strdup(key_obj + key_offset);
			p = strchr(val, '/');
			if (p)
				*p = '\0';
			filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
			free(val);
		}
	}
	return 0;
}

int etcd_fill_namespace(const char *subsysnqn, int nsid,
			void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int etcd_count_namespaces(const char *subsysnqn, int *nns)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(key, nns);
	free(key);
	return ret;
}

int etcd_add_namespace(const char *subsysnqn, int nsid)
{
	char *key;
	int ret;
	uuid_t uuid;
	char uuid_str[65], nguid_str[33], eui64_str[33];
	unsigned int nguid1, nguid2;

	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);
	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/device_uuid",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_put(ctx, key, uuid_str, true);
	free(key);
	if (ret < 0)
		return ret;

	memcpy(&nguid1, &uuid[8], 4);
	memcpy(&nguid2, &uuid[12], 4);
	sprintf(nguid_str, "%08x%08x%s",
		nguid1, nguid2, NOFUSE_NGUID_PREFIX);
	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/device_nguid",
		       ctx->prefix, subsysnqn, nsid);
	if (!ret) {
		ret = etcd_kv_put(ctx, key, nguid_str, true);
		free(key);
	}

	sprintf(eui64_str, "0efd37%hhx%08x",
		uuid[11], nguid2);
	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/device_eui64",
		       ctx->prefix, subsysnqn, nsid);
	if (!ret) {
		ret = etcd_kv_put(ctx, key, nguid_str, true);
		free(key);
	}
	return 0;
}

int etcd_set_namespace_attr(const char *subsysnqn, int nsid,
			    const char *attr, const char *value)
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
	ret = etcd_kv_put(ctx, key, value, false);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_namespace_attr(const char *subsysnqn, int nsid,
			    const char *attr, char *value)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
		       ctx->prefix, subsysnqn, nsid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value);
	free(key);
	return ret;
}

int etcd_set_namespace_anagrp(const char *subsysnqn, int nsid, int ana_grpid)
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
	ret = etcd_kv_put(ctx, key, value, false);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_namespace_anagrp(const char *subsysnqn, int nsid, int *ana_grpid)
{
	struct json_object *resp;
	int ret = -ENOENT;
	char *key;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/ana_group_id",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	resp = etcd_kv_range(ctx, key);
	free(key);
	if (!resp)
		return -errno;

	json_object_object_foreach(resp, key_obj, val_obj) {
		if (!strcmp(key_obj, "ana_group_id")) {
			*ana_grpid = json_object_get_int(val_obj);
			ret = 0;
			break;
		}
	}
	json_object_put(resp);
	return ret;
}

int etcd_del_namespace(const char *subsysnqn, int nsid)
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

int etcd_count_subsys_port(int portid, int *nsubsys)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%d/subsystems",
		       ctx->prefix, portid);
	if (ret < 0)
		return ret;

	ret = _count_key_range(key, nsubsys);
	free(key);
	return ret;
}

int etcd_get_cntlid(const char *subsysnqn, u16 *cntlid)
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

int etcd_backend_init(const char *prefix, bool debug)
{
	ctx = etcd_init();
	ctx->prefix = prefix;
	ctx->debug = debug;
	return etcd_lease_grant(ctx);
}

void etcd_backend_exit(void)
{
	etcd_lease_revoke(ctx);
	etcd_exit(ctx);
}
