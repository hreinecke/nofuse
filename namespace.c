#include <stdio.h>

#include "common.h"
#include "ops.h"
#include "etcd_backend.h"

LINKED_LIST(device_linked_list);

struct nofuse_namespace *find_namespace(const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;

	list_for_each_entry(ns, &device_linked_list, node) {
		if (!strcmp(ns->subsysnqn, subsysnqn) &&
		    ns->nsid == nsid)
			return ns;
	}
	return NULL;
}

int add_namespace(struct etcd_ctx *ctx, const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	int ret;

	ns = malloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;
	memset(ns, 0, sizeof(*ns));
	ns->fd = -1;
	strcpy(ns->subsysnqn, subsysnqn);
	ns->nsid = nsid;
	ret = etcd_add_namespace(ctx, subsysnqn, ns->nsid);
	if (ret < 0) {
		fprintf(stderr, "subsys %s failed to add nsid %d\n",
			subsysnqn, ns->nsid);
		free(ns);
		return ret;
	}
	INIT_LINKED_LIST(&ns->node);
	list_add_tail(&ns->node, &device_linked_list);
	printf("%s: subsys %s nsid %d\n", __func__, subsysnqn, nsid);
	return 0;
}

int enable_namespace(struct etcd_ctx *ctx, const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	char path[PATH_MAX + 1], *eptr = NULL;
	int ret = 0, size;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	ns = find_namespace(subsysnqn, nsid);
	if (!ns)
		return -ENOENT;

	ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid,
				      "device_path", path);
	if (ret < 0) {
		fprintf(stderr, "subsys %s nsid %d no device path, error %d\n",
			subsysnqn, nsid, ret);
		return ret;
	}
	size = strtoul(path, &eptr, 10);
	if (path != eptr) {
		ns->size = size * 1024 * 1024;
		ns->blksize = 4096;
		ns->ops = null_register_ops();
	} else {
		struct stat st;
		mode_t mode = O_RDWR | O_EXCL;

		if (stat(path, &st) < 0) {
			fprintf(stderr, "subsys %s nsid %d invalid path '%s'\n",
				subsysnqn, nsid, path);
			fflush(stderr);
			return -errno;
		}
		if (!(st.st_mode & S_IWUSR)) {
			mode = O_RDONLY;
			ns->readonly = true;
		}
		ns->fd = open(path, mode);
		if (ns->fd < 0) {
			fprintf(stderr, "subsys %s nsid %d invalid path '%s'\n",
				subsysnqn, nsid, path);
			fflush(stderr);
			return -errno;
		}
		ns->size = st.st_size;
		ns->blksize = st.st_blksize;
		ns->ops = uring_register_ops();
	}
	ret = etcd_set_namespace_attr(ctx, subsysnqn, nsid,
				      "device_enable", "1");
	if (ret < 0) {
		fprintf(stderr, "subsys %s nsid %d enable error %d\n",
			subsysnqn, nsid, ret);
		if (ns->fd > 0) {
			close(ns->fd);
			ns->fd = -1;
		}
		ns->size = 0;
		ns->blksize = 0;
		ns->ops = NULL;
	}
	printf("subsys %s nsid %d size %lu blksize %u\n",
	       subsysnqn, nsid, ns->size, ns->blksize);
	return ret;
}

int disable_namespace(struct etcd_ctx *ctx, const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	int ret;

	fprintf(stderr, "%s: subsys %s nsid %d\n",
		__func__, subsysnqn, nsid);
	ns = find_namespace(subsysnqn, nsid);
	if (!ns)
		return -ENOENT;
	ret = etcd_set_namespace_attr(ctx, subsysnqn, nsid,
				      "device_enable", "0");
	if (ret < 0)
		return ret;

	if (ns->fd > 0) {
		close(ns->fd);
		ns->fd = -1;
	}
	ns->size = 0;
	ns->blksize = 0;
	ns->ops = NULL;
	return 0;
}

int del_namespace(struct etcd_ctx *ctx, const char *subsysnqn, u32 nsid)
{
	struct nofuse_namespace *ns;
	int ret = -ENOENT;

	ns = find_namespace(subsysnqn, nsid);
	if (!ns)
		return ret;
	printf("%s: subsys %s nsid %d\n",
	       __func__, subsysnqn, nsid);
	ret = etcd_del_namespace(ctx, subsysnqn, ns->nsid);
	if (ret < 0)
		return ret;
	list_del(&ns->node);
	if (ns->fd > 0)
		close(ns->fd);
	free(ns);
	return 0;
}

int active_namespaces(struct etcd_ctx *ctx, const char *subsysnqn,
		      u8 *idlist, size_t idlen)
{
	struct nofuse_namespace *ns;
	u8 *id_ptr = idlist;

	list_for_each_entry(ns, &device_linked_list, node) {
		if (!strcmp(ns->subsysnqn, subsysnqn)) {
			u32 nsid = htole32(ns->nsid);
			memcpy(id_ptr, &nsid, sizeof(u32));
			*id_ptr += sizeof(u32);
		}
	}
	return 0;
}

int ana_log_entries(struct etcd_ctx *ctx, const char *subsysnqn,
		    const char *port, u8 *log, int log_len)
{
	struct nvme_ana_rsp_hdr *hdr = (struct nvme_ana_rsp_hdr *)log;
	struct nvme_ana_group_desc *grp_desc = hdr->entries;
	u8 *p;	
	int ret, ngrps = 0, grpid, desc_len = sizeof(*hdr);

	for (grpid = 1; grpid <= MAX_ANAGRPID; grpid++) {
		struct nofuse_namespace *ns;
		u32 nnsids = 0;
		char state[64], *eptr = NULL;
		unsigned long ana_state;

		memset(grp_desc, 0, sizeof(*grp_desc));

		ret = etcd_get_ana_group(ctx, port, grpid,
					 state);
		if (ret < 0)
			continue;
		ana_state = strtoul(state, &eptr, 10);
		if (state == eptr || ana_state == ULONG_MAX)
			continue;
		list_for_each_entry(ns, &device_linked_list, node) {
			int _grpid;

			if (strcmp(ns->subsysnqn, subsysnqn))
				continue;
			ret = etcd_get_namespace_anagrp(ctx, subsysnqn,
							ns->nsid, &_grpid);
			if (ret < 0 || _grpid != grpid)
				continue;
			nnsids++;
		}
		if (!nnsids)
			continue;
		grp_desc->nnsids = htole32(nnsids);
		grp_desc->grpid = htole16(grpid);
		grp_desc->state = ana_state;
		printf("%s: grpid %u %d nsids state %d\n",
		       __func__, grpid, nnsids, grp_desc->state);

		p = (u8 *)grp_desc->nsids;
		if (log_len - desc_len < sizeof(u32))
			break;
		list_for_each_entry(ns, &device_linked_list, node) {
			u32 nsid;
			int _grpid;

			if (strcmp(ns->subsysnqn, subsysnqn))
				continue;
			ret = etcd_get_namespace_anagrp(ctx, subsysnqn,
							ns->nsid, &_grpid);
			if (ret < 0 || _grpid != grpid)
				continue;
			nsid = htole32(ns->nsid);
			memcpy(p, &nsid, sizeof(u32));
			p += sizeof(u32);
			desc_len += sizeof(u32);
			if (log_len - desc_len < sizeof(u32))
				break;
		}
		ngrps++;
		if (log_len - desc_len < sizeof(struct nvme_ana_group_desc))
			break;
		grp_desc = (struct nvme_ana_group_desc *)p;
	}
	hdr->ngrps = htole16(ngrps);
	printf("%s: %d ana groups\n", __func__, ngrps);
	return desc_len;
}

