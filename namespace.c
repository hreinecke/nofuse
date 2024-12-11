#include <stdio.h>

#include "common.h"
#include "ops.h"
#ifdef NOFUSE_ETCD
#include "etcd_backend.h"
#else
#include "configdb.h"
#endif

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
#ifdef NOFUSE_ETCD
	ret = etcd_add_namespace(ctx, subsysnqn, ns->nsid);
#else
	ret = configdb_add_namespace(subsysnqn, ns->nsid);
#endif
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

#ifdef NOFUSE_ETCD
	ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid,
				      "device_path", path);
#else
	ret = configdb_get_namespace_attr(subsysnqn, nsid, "device_path", path);
#endif
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
#ifdef NOFUSE_ETCD
	ret = etcd_set_namespace_attr(ctx, subsysnqn, nsid,
				      "device_enable", "1");
#else
	ret = configdb_set_namespace_attr(subsysnqn, nsid,
				       "device_enable", "1");
#endif
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
#ifdef NOFUSE_ETCD
	ret = etcd_set_namespace_attr(ctx, subsysnqn, nsid,
				      "device_enable", "0");
#else
	ret = configdb_set_namespace_attr(subsysnqn, nsid,
				       "device_enable", "0");
#endif
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
#ifdef NOFUSE_ETCD
	ret = etcd_del_namespace(ctx, subsysnqn, ns->nsid);
#else
	ret = configdb_del_namespace(subsysnqn, ns->nsid);
#endif
	if (ret < 0)
		return ret;
	list_del(&ns->node);
	if (ns->fd > 0)
		close(ns->fd);
	free(ns);
	return 0;
}
