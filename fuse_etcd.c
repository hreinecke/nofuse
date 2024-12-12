/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * fuse_etcd.c
 * etcd fuse emulation for NVMe-over-TCP userspace daemon.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <ctype.h>

#include "common.h"
#ifdef NOFUSE_ETCD
#include "etcd_backend.h"
#else
#include "configdb.h"
#endif

bool fuse_debug;
bool etcd_debug;
bool curl_debug;

const char hosts_dir[] = "hosts";
const char ports_dir[] = "ports";
const char subsys_dir[] = "subsystems";

struct etcd_ctx *ctx;

#define fuse_info(f, x...)			\
	if (fuse_debug) {			\
		printf(f "\n", ##x);		\
		fflush(stdout);			\
	}

#define fuse_err(f, x...) \
	do { \
		fprintf(stderr, f "\n", ##x);	\
		fflush(stderr); \
	} while(0)

static void *nofuse_init(struct fuse_conn_info *conn,
			 struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static int host_getattr(char *hostnqn, struct stat *stbuf)
{
	int ret;
	char *attr, *p;

	ret = etcd_test_host(ctx, hostnqn);
	if (ret < 0)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	attr = p;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	ret = etcd_get_host_attr(ctx, hostnqn, attr, NULL);
	if (ret < 0)
		return -ENOENT;

	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int port_subsystems_getattr(unsigned int portid, const char *subsys,
				   struct stat *stbuf)
{
	int ret;
	const char *p;

	fuse_info("%s: port %d subsys %s", __func__,
		  portid, subsys);
	if (!subsys) {
		int num_subsys = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		ret = etcd_count_subsys_port(ctx, portid, &num_subsys);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_subsys;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	ret = etcd_get_subsys_port(ctx, subsys, portid, NULL);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFLNK | 0755;
	stbuf->st_nlink = 1;
	stbuf->st_size = PATH_MAX;
	return 0;
}

static int port_ana_groups_getattr(int portid, const char *ana_grp,
				   struct stat *stbuf)
{
	int ret;
	const char *p;

	if (!ana_grp) {
		int num_grps = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
		ret = etcd_count_ana_groups(ctx, portid, &num_grps);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_grps;
		return 0;
	}

	fuse_info("%s: port %d ana group %s",
		  __func__, portid, ana_grp);

	p = strtok(NULL, "/");
	if (p && strcmp(p, "ana_state"))
		return -ENOENT;

	ret = etcd_get_ana_group(ctx, portid, ana_grp, NULL);
	if (ret < 0)
		return ret;
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = 64;
	}
	return 0;
}

static int port_getattr(char *port, struct stat *stbuf)
{
	int portid;
	int ret;
	char *p, *attr, *eptr = NULL;;

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -ENOENT;
	ret = etcd_test_port(ctx, portid);
	if (ret < 0)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
		stbuf->st_size = 0;
		return 0;
	}

	attr = p;
	p = strtok(NULL, "/");

	if (!strcmp(attr, "subsystems"))
		return port_subsystems_getattr(portid, p, stbuf);
	if (!strcmp(attr, "ana_groups"))
		return port_ana_groups_getattr(portid, p, stbuf);

	if (p)
		return -ENOENT;

	if (!strcmp(attr, "referrals")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	if (strncmp(attr, "addr_", 5))
		return -ENOENT;

	ret = etcd_get_port_attr(ctx, portid, attr, NULL);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int subsys_allowed_hosts_getattr(const char *subsysnqn,
					const char *hostnqn,
					struct stat *stbuf)
{
	int ret;
	const char *p;

	if (!hostnqn) {
		int num_hosts = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		ret = etcd_count_host_subsys(ctx, subsysnqn, &num_hosts);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_hosts;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	fuse_info("%s: subsys %s host %s", __func__, subsysnqn, hostnqn);
	ret = etcd_get_host_subsys(ctx, hostnqn, subsysnqn, NULL);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFLNK | 0755;
	stbuf->st_nlink = 1;
	stbuf->st_size = PATH_MAX;
	return 0;
}

static int subsys_namespaces_getattr(const char *subsysnqn, const char *ns,
				     struct stat *stbuf)
{
	int ret;
	const char *attr, *p;
	char *eptr;
	u32 nsid;

	if (!ns) {
		int num_ns = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		ret = etcd_count_namespaces(ctx, subsysnqn, &num_ns);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_ns;
		return 0;
	}
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;
	ret = etcd_test_namespace(ctx, subsysnqn, nsid);
	if (ret)
		return -ENOENT;
	fuse_info("%s: subsys %s ns %u", __func__, subsysnqn, nsid);
	attr = strtok(NULL, "/");
	if (!attr) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	fuse_info("%s: subsys %s ns %u attr %s", __func__,
		  subsysnqn, nsid, attr);
	if (strcmp(attr, "ana_grpid")) {
		ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid, attr, NULL);
		if (ret < 0)
			return -ENOENT;
	}
	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int subsys_getattr(char *subsysnqn, struct stat *stbuf)
{
	char *p, *attr;
	int ret;

	ret = etcd_test_subsys(ctx, subsysnqn);
	if (ret < 0)
		return -ENOENT;

	p = strtok(NULL, "/");
	fuse_info("%s: subsys %s attr %s", __func__, subsysnqn, p);
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 4;
		return 0;
	}

	attr = p;
	p = strtok(NULL, "/");

	if (!strcmp(attr, "allowed_hosts"))
		return subsys_allowed_hosts_getattr(subsysnqn, p, stbuf);
	if (!strcmp(attr, "namespaces"))
		return subsys_namespaces_getattr(subsysnqn, p, stbuf);

	if (strncmp(attr, "attr_", 5))
		return -ENOENT;
	ret = etcd_get_subsys_attr(ctx, subsysnqn, attr, NULL);
	if (ret < 0)
		return -ENOENT;

	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int nofuse_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0;
	char *p = NULL, *root, *pathbuf;

	memset(stbuf, 0, sizeof(struct stat));
	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
		goto out_free;
	}

	p = strtok(NULL, "/");
	if (!p) {
		int nlinks = 0;

		if (!strcmp(root, "discovery_nqn") ||
		    !strcmp(root, "debug")) {
			stbuf->st_mode = S_IFREG | 0644;
			stbuf->st_nlink = 1;
			stbuf->st_size = 256;
			res = 0;
			goto out_free;
		}
		if (strcmp(root, hosts_dir) &&
		    strcmp(root, ports_dir) &&
		    strcmp(root, subsys_dir)) {
			res = -ENOENT;
			goto out_free;
		}
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		res = etcd_count_root(ctx, root, &nlinks);
		if (res)
			goto out_free;
		stbuf->st_nlink += nlinks;
		res = 0;
		goto out_free;
	}
	if (!strcmp(root, hosts_dir)) {
		res = host_getattr(p, stbuf);
	} else if (!strcmp(root, ports_dir)) {
		res = port_getattr(p, stbuf);
	} else if (!strcmp(root, subsys_dir)){
		res = subsys_getattr(p, stbuf);
	} else
		res = -ENOENT;

out_free:
	free(pathbuf);
	if (res < 0)
		fuse_info("%s: path %s error %d",
			  __func__, path, res);
	return res;
}

static int fill_host(const char *host,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p = host;

	if (!host) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_host_dir(ctx, buf, filler);
	}
	p = strtok(NULL, "/");
	if (!p) {
		fuse_info("%s: host %s", __func__, host);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_host(ctx, host, buf, filler);
	}
	return -ENOENT;
}

static int fill_port(const char *port,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p, *subdir;
	char *eptr = NULL;
	unsigned int portid;

	if (!port) {
		/* list contents of /ports */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_port_dir(ctx, buf, filler);
	}

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -ENOENT;
	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /ports/<portid> */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_port(ctx, portid, buf, filler);
	}
	subdir = p;
	p = strtok(NULL, "/");
	if (!strcmp(subdir, "subsystems")) {
		const char *subsys = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;

		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (subsys) {
			if (etcd_get_subsys_port(ctx, subsys, portid, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return etcd_fill_subsys_port(ctx, portid, buf, filler);
	}
	if (!strcmp(subdir, "ana_groups")) {
		const char *ana_grp = p;

		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		p = strtok(NULL, "/");
		if (p) {
			if (strcmp(p, "ana_state"))
				return -ENOENT;
			return 0;
		}
		if (!ana_grp)
			return etcd_fill_ana_groups(ctx, port, buf, filler);
		if (etcd_get_ana_group(ctx, portid, ana_grp, NULL) < 0)
			return -ENOENT;
		filler(buf, "ana_state", NULL, 0, FUSE_FILL_DIR_PLUS);
		return 0;
	}
	if (!strcmp(subdir, "referrals")) {
		if (p)
			return -ENOENT;
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return 0;
	}
	return -ENOENT;
}

static int fill_subsys(const char *subsys,
		       void *buf, fuse_fill_dir_t filler)
{
	const char *p, *subdir;

	if (!subsys) {
		/* list contents of /subsystems */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_subsys_dir(ctx, buf, filler);
	}
	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /subsystems/<subsys> */
		fuse_info("%s: subsys %s", __func__, subsys);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_subsys(ctx, subsys, buf, filler);
	}
	subdir = p;
	p = strtok(NULL, "/");
	if (!strcmp(subdir, "namespaces")) {
		const char *ns = p;
		char *eptr = NULL;
		u32 nsid;

		if (!ns) {
			filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
			filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
			return etcd_fill_namespace_dir(ctx, subsys,
						       buf, filler);
		}
		nsid = strtoul(ns, &eptr, 10);
		if (ns == eptr)
			return -EINVAL;
		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;

		fuse_info("%s: subsys %s ns %u", __func__, subsys, nsid);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return etcd_fill_namespace(ctx, subsys, nsid, buf, filler);
	}
	if (!strcmp(subdir, "allowed_hosts")) {
		const char *host = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		fuse_info("%s: subsys %s host %s", __func__, subsys, host);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (host) {
			if (etcd_get_host_subsys(ctx, host, subsys, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return etcd_fill_host_subsys(ctx, subsys, buf, filler);
	}
	return -ENOENT;
}

static int nofuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi,
			  enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;
	char *p, *root, *pathbuf;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, hosts_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, ports_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, subsys_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "discovery_nqn", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "debug", NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
		goto out_free;
	}

	p = strtok(NULL, "/");
	if (!strcmp(root, hosts_dir))
		ret = fill_host(p, buf, filler);
	else if (!strcmp(root, ports_dir))
		ret = fill_port(p, buf, filler);
	else if (!strcmp(root, subsys_dir))
		ret = fill_subsys(p, buf, filler);

out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int port_mkdir(char *s)
{
	char *port, *p, *eptr = NULL;
	int portid, ana_grpid;
	int ret;

	port = strtok_r(NULL, "/", &s);
	if (!port)
		return -ENOENT;

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -EINVAL;

	p = strtok(NULL, "/");
	if (!p) {
		ret = etcd_add_port(ctx, "nofuse", portid, NULL, 0);
		if (ret < 0) {
			fuse_err("%s: cannot add port %d, error %d",
				 __func__, portid, ret);
			return ret;
		}
		ret = etcd_add_ana_group(ctx, portid, 1, NVME_ANA_OPTIMIZED);
		if (ret < 0) {
			fuse_err("%s: cannot add group 1 to port %d, error %d\n",
				 __func__, portid, ret);
			etcd_del_port(ctx, portid);
		}
		return ret;
	}
	if (strcmp(p, "ana_groups"))
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p)
		return -ENOENT;
	eptr = NULL;
	ana_grpid = strtoul(p, &eptr, 10);
	if (p == eptr)
		return -ENOENT;
	fuse_info("%s: port %d ana group %d", __func__,
		  portid, ana_grpid);
	ret = etcd_add_ana_group(ctx, portid, ana_grpid,
			    ana_grpid == 1 ?
			    NVME_ANA_OPTIMIZED : NVME_ANA_INACCESSIBLE);
	if (ret < 0) {
		fuse_err("%s: cannot add ana group %d to "
			 "port %d, error %d", __func__,
			 portid, ana_grpid, ret);
		return ret;
	}
	return 0;
}

static int subsys_mkdir(char *s)
{
	char *subsysnqn, *p, *ns, *eptr = NULL;
	u32 nsid;

	subsysnqn = strtok_r(NULL, "/", &s);
	if (!subsysnqn)
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (!p) {
		char nqn[MAX_NQN_SIZE];
		int type = NVME_NQN_NVM, ret;

		ret = etcd_get_discovery_nqn(ctx, nqn);
		if (!ret && !strcmp(nqn, subsysnqn))
			type = NVME_NQN_CUR;

		printf("creating %s subsys %s\n",
		       type == NVME_NQN_NVM ? "nvm" : "cur",
		       subsysnqn);
		return etcd_add_subsys(ctx, subsysnqn, type);
	}

	if (strcmp(p, "namespaces"))
		return -ENOENT;

	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -ENOENT;

	ns = p;
	p = strtok_r(NULL, "/", &s);
	if (p)
		return -ENOENT;
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;

	return add_namespace(ctx, subsysnqn, nsid);
}

static int host_mkdir(char *s)
{
	char *hostnqn, *p;

	hostnqn = strtok_r(NULL, "/", &s);
	if (!hostnqn)
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (p)
		return -ENOENT;
	return etcd_add_host(ctx, hostnqn);
}

static int nofuse_mkdir(const char *path, mode_t mode)
{
	char *pathbuf, *root, *s;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok_r(pathbuf, "/", &s);
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		ret = port_mkdir(s);
	} else if (!strcmp(root, subsys_dir)) {
		ret = subsys_mkdir(s);
	} else if (!strcmp(root, hosts_dir)) {
		ret = host_mkdir(s);
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int port_rmdir(char *s)
{
	char *port, *p, *ana_grp, *eptr = NULL;
	unsigned int portid;
	int ana_grpid;

	port = strtok_r(NULL, "/", &s);
	if (!port)
		return -ENOENT;
	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -EINVAL;
	p = strtok_r(NULL, "/", &s);
	if (!p) {
		int ret;

		ret = etcd_del_ana_group(ctx, portid, 1);
		if (ret < 0) {
			fuse_err("%s: cannot remove group 1 from port %d, "
				 "error %d", __func__, portid, ret);
			return ret;
		}
		ret = etcd_del_port(ctx, portid);
		if (ret < 0) {
			fuse_err("%s: cannot remove port %d, error %d",
			       __func__, portid, ret);
			etcd_add_ana_group(ctx, portid, 1, NVME_ANA_OPTIMIZED);
		}
		return ret;
	}
	if (strcmp(p, "ana_groups"))
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -ENOENT;
	ana_grp = p;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;;
	ana_grpid = strtoul(ana_grp, &eptr, 10);
	if (ana_grp == eptr)
		return -EINVAL;
	fuse_info("%s: port %d ana group %d", __func__,
	       portid, ana_grpid);
	if (ana_grpid == 1)
		return -EACCES;
	return etcd_del_ana_group(ctx, portid, ana_grpid);
}

static int subsys_rmdir(char *s)
{
	char *subsysnqn, *p, *ns, *eptr = NULL;
	u32 nsid;

	subsysnqn = strtok_r(NULL, "/", &s);
	if (!subsysnqn)
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (!p) {
		printf("deleting subsys %s\n", subsysnqn);
		return etcd_del_subsys(ctx, subsysnqn);
	}
	if (strcmp(p, "namespaces"))
		return -ENOENT;

	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -ENOENT;
	ns = p;
	p = strtok_r(NULL, "/", &s);
	if (p)
		return -ENOENT;
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;
	return del_namespace(ctx, subsysnqn, nsid);
}

static int host_rmdir(char *s)
{
	char *hostnqn, *p;

	hostnqn = strtok_r(NULL, "/", &s);
	if (!hostnqn)
		return -ENOENT;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	return etcd_del_host(ctx, hostnqn);
}

static int nofuse_rmdir(const char *path)
{
	char *pathbuf, *root, *s;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok_r(pathbuf, "/", &s);
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		ret = port_rmdir(s);
	}
	if (!strcmp(root, subsys_dir)) {
		ret = subsys_rmdir(s);
	}
	if (!strcmp(root, hosts_dir)) {
		ret = host_rmdir(s);
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int parse_port_link(char *s, unsigned int *portid,
			   const char **subsys)
{
	const char *p, *port;
	char *eptr = NULL;
	unsigned int p_id;

	port = strtok_r(NULL, "/", &s);
	if (!port)
		return -ENOENT;
	p_id = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -EINVAL;
	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -ENOENT;
	if (strcmp(p, "subsystems"))
		return -ENOENT;
	*subsys = strtok_r(NULL, "/", &s);
	if (!*subsys)
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (p) {
		*subsys = NULL;
		return -ENOENT;
	}
	*portid = p_id;
	return 0;
}

static int parse_subsys_link(char *s, const char **subsys,
			     const char **host)
{
	const char *p;

	*subsys = strtok_r(NULL, "/", &s);
	if (!*subsys)
		return -ENOENT;
	p = strtok_r(NULL, "/", &s);
	if (!p || strcmp(p, "allowed_hosts")) {
		*subsys = NULL;
		return -ENOENT;
	}
	*host = strtok_r(NULL, "/", &s);
	if (!*host) {
		*subsys = NULL;
		return -ENOENT;
	}
	p = strtok_r(NULL, "/", &s);
	if (p) {
		*host = NULL;
		*subsys = NULL;
		return -ENOENT;
	}
	return 0;
}

static int nofuse_readlink(const char *path, char *buf, size_t len)
{
	char *s = NULL, *pathbuf;
	const char *root;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok_r(pathbuf, "/", &s);
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *subsys;
		unsigned int portid;

		ret = parse_port_link(s, &portid, &subsys);
		if (ret < 0)
			goto out_free;
		ret = etcd_get_subsys_port(ctx, subsys, portid, buf);
		if (ret < 0)
			goto out_free;
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = etcd_get_host_subsys(ctx, host, subsys, buf);
		if (ret < 0)
			goto out_free;
		ret = 0;
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int nofuse_symlink(const char *from, const char *to)
{
	char *s = NULL, *pathbuf;
	const char *root;
	int ret = -ENOENT;

	pathbuf = strdup(to);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s from %s",
	       __func__, pathbuf, from);
	root = strtok_r(pathbuf, "/", &s);
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *subsys;
		unsigned int portid;

		ret = parse_port_link(s, &portid, &subsys);
		if (ret < 0)
			goto out_free;
		fuse_info("%s: subsys %s portid %d",
		       __func__, subsys, portid);
		ret = etcd_add_subsys_port(ctx, subsys, portid);
		if (ret < 0) {
			fuse_err("%s: failed to add subsys, error %d",
			       __func__, ret);
			goto out_free;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = etcd_add_host_subsys(ctx, host, subsys);
		if (ret < 0)
			goto out_free;
		ret = 0;
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: from %s to %s error %d",
			 __func__, from, to, ret);
	return ret;
}

static int nofuse_unlink(const char *path)
{
	char *s = NULL, *pathbuf;
	const char *root;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s",
	       __func__, pathbuf);
	root = strtok_r(pathbuf, "/", &s);
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *subsys;
		unsigned int portid;

		ret = parse_port_link(s, &portid, &subsys);
		if (ret < 0)
			goto out_free;
		ret = etcd_del_subsys_port(ctx, subsys, portid);
		if (ret < 0)
			goto out_free;
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = etcd_del_host_subsys(ctx, host, subsys);
		if (ret < 0)
			goto out_free;
		ret = 0;
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int parse_namespace_attr(const char *p, u32 *nsid,
				const char **attr)
{
	const char *ns;
	char *eptr = NULL;

	*nsid = 0;
	*attr = NULL;
	if (!p)
		return -EINVAL;
	ns = p;
	p = strtok(NULL, "/");
	if (!p)
		return -EINVAL;
	*nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr) {
		*nsid = 0;
		return -EINVAL;
	}
	*attr = p;
	p = strtok(NULL, "/");
	if (p)
		return -EINVAL;
	return 0;
}

static int nofuse_open(const char *path, struct fuse_file_info *fi)
{
	const char *p, *root, *attr;
	char *pathbuf;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, path);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;

	if (!strcmp(root, hosts_dir))
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		if (!strcmp(root, "discovery_nqn") ||
		    !strcmp(root, "debug"))
			ret = 0;
		goto out_free;
	}
	if (!strcmp(root, ports_dir)) {
		const char *port = p;
		char *eptr = NULL;
		unsigned int portid;

		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		fuse_info("%s: port %d attr %s p %s", __func__,
		       portid, attr, p);
		if (!strcmp(attr, "ana_groups")) {
			const char *ana_grp = p;

			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;
			fuse_info("%s: port %d ana_grp %s attr %s", __func__,
			       portid, ana_grp, p);
			ret = etcd_get_ana_group(ctx, portid, ana_grp, NULL);
			if (ret < 0) {
				fuse_err("%s: port %d ana_grp %s error %d",
					 __func__, portid, ana_grp, ret);
				ret = -ENOENT;
			} else
				ret = 0;
			goto out_free;
		} else {
			ret = etcd_get_port_attr(ctx, portid, attr, NULL);
			if (ret < 0)
				ret = -ENOENT;
			goto out_free;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;
		u32 nsid;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		fuse_info("%s: subsys %s attr %s p %s", __func__,
		       subsysnqn, attr, p);
		if (!p) {
			ret = etcd_get_subsys_attr(ctx, subsysnqn, attr, NULL);
			if (ret < 0)
				ret = -ENOENT;
			goto out_free;
		} else if (strcmp(attr, "namespaces")) {
			ret = -ENOENT;
			goto out_free;
		}
		ret = parse_namespace_attr(p, &nsid, &attr);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
		if (!strcmp(attr, "ana_grpid")) {
			ret = etcd_get_namespace_anagrp(ctx, subsysnqn,
							nsid, NULL);
			goto out_free;
		}
		ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid,
					      attr, NULL);
		if (ret < 0)
			ret = -ENOENT;
		goto out_free;
	}
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		ret = -EACCES;
	else
		ret = 0;
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

struct value_map_t {
	int val;
	char *desc;
};

static int nofuse_read(const char *path, char *buf, size_t size, off_t offset,
		       struct fuse_file_info *fi)
{
	const char *p, *root, *attr;
	char *pathbuf;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;

	if (!strcmp(root, hosts_dir))
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		if (!strcmp(root, "discovery_nqn")) {
			ret = etcd_get_discovery_nqn(ctx, buf);
			if (ret < 0)
				goto out_free;
		} else if (!strcmp(root, "debug")) {
			sprintf(buf, "%ctcp,%ccmd,%cep,%cport,%cfuse,%cetcd,%ccurl",
				tcp_debug ? '+' : '-',
				cmd_debug ? '+' : '-',
				ep_debug ? '+' : '-',
				port_debug ? '+' : '-',
				fuse_debug ? '+' : '-',
				etcd_debug ? '+' : '-',
				curl_debug ? '+' : '-');
		} else
			goto out_free;
	} else if (!strcmp(root, ports_dir)) {
		const char *port = p;
		char *eptr = NULL;
		unsigned int portid;

		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;

		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;

		p = strtok(NULL, "/");
		fuse_info("%s: port %d attr %s p %s", __func__,
		       portid, attr, p);
		if (!strcmp(attr, "ana_groups")) {
			const char *ana_grp = p;

			if (!ana_grp)
				goto out_free;
			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;
			fuse_info("%s: port %s ana_grp %s", __func__,
			       port, ana_grp);
			ret = etcd_get_ana_group(ctx, portid, ana_grp, buf);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
		} else {
			ret = etcd_get_port_attr(ctx, portid, attr, buf);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;
		u32 nsid;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		fuse_info("%s: subsys %s attr %s p %s", __func__,
		       subsysnqn, attr, p);
		if (!p) {
			ret = etcd_get_subsys_attr(ctx, subsysnqn, attr, buf);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
			if (!strcmp(attr, "attr_type")) {
				if (!strcmp(buf, "1")) {
					strcpy(buf, "ref");
				} else if (!strcmp(buf, "2")) {
					strcpy(buf, "nvm");
				} else if (!strcmp(buf, "3")) {
					strcpy(buf, "cur");
				} else {
					strcpy(buf, "<unknown>");
				}
			}
		} else if (strcmp(attr, "namespaces")) {
			ret = -ENOENT;
			goto out_free;
		} else {
			ret = parse_namespace_attr(p, &nsid, &attr);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
			if (!strcmp(attr, "ana_grpid")) {
				int anagrp;

				ret = etcd_get_namespace_anagrp(ctx, subsysnqn,
								nsid, &anagrp);
				if (ret < 0) {
					ret = -ENOENT;
					goto out_free;
				}
				sprintf(buf, "%d", anagrp);
			} else {
				ret = etcd_get_namespace_attr(ctx, subsysnqn,
							      nsid, attr, buf);
				if (ret < 0) {
					ret = -ENOENT;
					goto out_free;
				}
			}
		}
	}
	if (strlen(buf))
		strcat(buf, "\n");
	ret = strlen(buf);
out_free:
	free(pathbuf);
	if (ret < 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int write_namespace(const char *subsysnqn, const char *p,
			   const char *buf, size_t len)
{
	int ret;
	u32 nsid;
	const char *attr;

	ret = parse_namespace_attr(p, &nsid, &attr);
	if (ret < 0)
		return -ENOENT;

	fuse_info("%s: subsys %s nsid %u attr %s value %s", __func__,
		  subsysnqn, nsid, attr, buf);

	if (!strcmp(attr, "ana_grpid")) {
		int ana_grp, new_ana_grp;
		char *eptr;

		ana_grp = strtoul(buf, &eptr, 10);
		if (buf == eptr)
			return -EINVAL;

		ret = etcd_set_namespace_anagrp(ctx, subsysnqn, nsid, ana_grp);
		if (ret < 0)
			return ret;
		ret = etcd_get_namespace_anagrp(ctx, subsysnqn, nsid,
						    &new_ana_grp);
		if (ret < 0)
			return ret;
		if (new_ana_grp != ana_grp)
			return -EINVAL;

		ret = len;
	} else if (!strcmp(attr, "enable")) {
		int enable;
		char *eptr = NULL;

		enable = strtoul(buf, &eptr, 10);
		if (buf == eptr)
			return -EINVAL;

		fuse_info("%s: enable %d", __func__, enable);
		if (enable == 1) {
			ret = enable_namespace(ctx, subsysnqn, nsid);
		} else if (enable == 0) {
			ret = disable_namespace(ctx, subsysnqn, nsid);
		} else {
			ret = -EINVAL;
		}
		if (ret < 0)
			return ret;
		ret = len;
	} else {
		fuse_info("%s: attr %s", __func__, attr);
		ret = etcd_set_namespace_attr(ctx, subsysnqn, nsid,
					      attr, buf);
		if (ret < 0)
			return ret;

		ret = len;
	}
	return ret;
}

static int nofuse_write(const char *path, const char *buf, size_t len,
			off_t offset, struct fuse_file_info *fi)
{
	const char *p, *root, *attr;
	char *pathbuf, *value, *ptr;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;

	value = malloc(strlen(buf) + 1);
	if (!value)
		return -ENOMEM;
	memset(value, 0, strlen(buf) + 1);
	strncpy(value, buf, len);
	ptr = value;

	while (ptr && *ptr) {
		if (*ptr == '\n') {
			*ptr = '\0';
			break;
		}
		ptr++;
	}
	fuse_info("%s: path %s buf %s len %ld off %ld", __func__,
	       pathbuf, value, len, offset);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;

	if (!strcmp(root, hosts_dir))
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		if (!strcmp(root, "discovery_nqn")) {
			ret = etcd_set_discovery_nqn(ctx, value);
			if (ret < 0)
				goto out_free;
		} else if (!strcmp(root, "debug")) {
			char level[17], onoff;
			bool enable;

			if (sscanf(value, "%c%16s", &onoff, level) != 2) {
				ret = -EINVAL;
				goto out_free;
			}
			if (onoff == '+')
				enable = true;
			else
				enable = false;
			if (!strcmp(level, "tcp")) {
				tcp_debug = enable;
			} else if (!strcmp(level, "cmd")) {
				cmd_debug = enable;
			} else if (!strcmp(level, "ep")) {
				ep_debug = enable;
			} else if (!strcmp(level, "port")) {
				port_debug = enable;
			} else if (!strcmp(level, "fuse")) {
				fuse_debug = enable;
			} else if (!strcmp(level, "etcd")) {
				etcd_debug = enable;
			} else if (!strcmp(level, "curl")) {
				curl_debug = enable;
			} else {
				ret = -EINVAL;
				goto out_free;
			}
		} else
			goto out_free;
		ret = len;
	} else if (!strcmp(root, ports_dir)) {
		const char *port = p;
		char *eptr = NULL;
		unsigned int portid;

		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;

		p = strtok(NULL, "/");
		fuse_info("%s: port %d attr %s p %s", __func__,
		       portid, attr, p);

		if (!strcmp(attr, "ana_groups")) {
			const char *ana_grp = p;

			if (!ana_grp)
				goto out_free;
			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;

			fuse_info("%s: port %s ana_grp %s state %s", __func__,
			       port, ana_grp, value);
			ret = etcd_set_ana_group(ctx, portid, ana_grp, value);
			if (ret < 0) {
				ret = -EINVAL;
				goto out_free;
			}
			ret = len;
		} else {
			ret = etcd_set_port_attr(ctx, portid, attr, value);
			if (ret < 0) {
				ret = -EINVAL;
				goto out_free;
			}
			ret = len;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		if (!p) {
			if (!strcmp(attr, "attr_type"))
				return -EPERM;
			ret = etcd_set_subsys_attr(ctx, subsysnqn, attr, value);
			if (ret < 0) {
				ret = -EINVAL;
				goto out_free;
			}
			ret = len;
		} else if (strcmp(attr, "namespaces")) {
			ret = -ENOENT;
			goto out_free;
		} else {
			ret = write_namespace(subsysnqn, p, value, len);
		}
	}
out_free:
	free(value);
	free(pathbuf);
	if (ret < 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static const struct fuse_operations nofuse_oper = {
	.init           = nofuse_init,
	.getattr	= nofuse_getattr,
	.readdir	= nofuse_readdir,
	.mkdir		= nofuse_mkdir,
	.rmdir		= nofuse_rmdir,
	.readlink	= nofuse_readlink,
	.symlink	= nofuse_symlink,
	.unlink		= nofuse_unlink,
	.open		= nofuse_open,
	.read		= nofuse_read,
	.write		= nofuse_write,
};

int run_fuse(struct fuse_args *args, struct etcd_ctx *ctx_in)
{
	int ret;

	ctx = ctx_in;
	fuse_debug = true;
	ret = fuse_main(args->argc, args->argv, &nofuse_oper, NULL);
	if (ret)
		fuse_err("fuse terminated with %d", ret);
	fuse_opt_free_args(args);
	return ret;
}
