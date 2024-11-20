/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * fuse.c
 * configfs fuse emulation for NVMe-over-TCP userspace daemon.
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
#include "configdb.h"

bool fuse_debug;

const char hosts_dir[] = "hosts";
const char ports_dir[] = "ports";
const char subsys_dir[] = "subsystems";

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

static int host_getattr(char *host, struct stat *stbuf)
{
	int ret;
	char *p;

	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;

	ret = configdb_stat_host(host, stbuf);
	if (ret < 0)
		return -ENOENT;

	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
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
		ret = configdb_count_subsys_port(portid, &num_subsys);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_subsys;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	ret = configdb_stat_subsys_port(subsys, portid, stbuf);
	if (ret < 0)
		fuse_err("%s: subsys %s portid %d stat error %d",
			 __func__, subsys, portid, ret);

	return ret;
}

static int port_ana_groups_getattr(const char *port, const char *ana_grp,
				   struct stat *stbuf)
{
	int ret;
	const char *p;

	if (!ana_grp) {
		int num_grps = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
		ret = configdb_count_ana_groups(port, &num_grps);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_grps;
		return 0;
	}

	fuse_info("%s: port %s ana group %s",
		  __func__, port, ana_grp);

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	if (strcmp(p, "ana_state"))
		return -ENOENT;
	ret = configdb_stat_ana_group(port, ana_grp, stbuf);
	if (ret < 0)
		return ret;
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
	ret = configdb_stat_port(portid, stbuf);
	if (ret)
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
		return port_ana_groups_getattr(port, p, stbuf);

	if (p)
		return -ENOENT;

	if (!strcmp(attr, "referrals")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	if (strncmp(attr, "addr_", 5))
		return -ENOENT;

	ret = configdb_get_port_attr(portid, attr, NULL);
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
		ret = configdb_count_host_subsys(subsysnqn, &num_hosts);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_hosts;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	fuse_info("%s: subsys %s host %s", __func__, subsysnqn, hostnqn);
	return configdb_stat_host_subsys(hostnqn, subsysnqn, stbuf);
}

static int subsys_namespaces_getattr(const char *subsysnqn, const char *ns,
				     struct stat *stbuf)
{
	int ret;
	const char *attr, *p;
	char *eptr;
	int nsid;

	if (!ns) {
		int num_ns = 0;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		ret = configdb_count_namespaces(subsysnqn, &num_ns);
		if (ret)
			return -ENOENT;
		stbuf->st_nlink += num_ns;
		return 0;
	}
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;
	ret = configdb_stat_namespace(subsysnqn, nsid, stbuf);
	if (ret)
		return -ENOENT;
	fuse_info("%s: subsys %s ns %d", __func__, subsysnqn, nsid);
	attr = strtok(NULL, "/");
	if (!attr) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	fuse_info("%s: subsys %s ns %d attr %s", __func__,
		  subsysnqn, nsid, attr);
	ret = configdb_get_namespace_attr(subsysnqn, nsid, attr, NULL);
	if (ret < 0)
		return -ENOENT;

	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int subsys_getattr(char *subsysnqn, struct stat *stbuf)
{
	char *p, *attr;
	int ret;

	ret = configdb_stat_subsys(subsysnqn, stbuf);
	if (ret)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 4;
		return 0;
	}
	fuse_info("%s: subsys %s attr %s", __func__, subsysnqn, p);

	attr = p;
	p = strtok(NULL, "/");

	if (!strcmp(attr, "allowed_hosts"))
		return subsys_allowed_hosts_getattr(subsysnqn, p, stbuf);
	if (!strcmp(attr, "namespaces"))
		return subsys_namespaces_getattr(subsysnqn, p, stbuf);

	if (strncmp(attr, "attr_", 5))
		return -ENOENT;
	ret = configdb_get_subsys_attr(subsysnqn, attr, NULL);
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
		res = configdb_count_table(root, &nlinks);
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

static int fill_host(const char *path,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p = path;

	if (p)
		return -ENOENT;

	return configdb_fill_host_dir(buf, filler);
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
		return configdb_fill_port_dir(buf, filler);
	}

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -ENOENT;
	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /ports/<portid> */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return configdb_fill_port(portid, buf, filler);
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
			if (configdb_stat_subsys_port(subsys, portid, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return configdb_fill_subsys_port(portid, buf, filler);
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
			return configdb_fill_ana_groups(port, buf, filler);
		if (configdb_stat_ana_group(port, ana_grp, NULL) < 0)
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
		return configdb_fill_subsys_dir(buf, filler);
	}
	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /subsystems/<subsys> */
		fuse_info("%s: subsys %s", __func__, subsys);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return configdb_fill_subsys(subsys, buf, filler);
	}
	subdir = p;
	p = strtok(NULL, "/");
	if (!strcmp(subdir, "namespaces")) {
		const char *ns = p;
		char *eptr = NULL;
		int nsid;

		if (!ns) {
			filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
			filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
			return configdb_fill_namespace_dir(subsys, buf, filler);
		}
		nsid = strtoul(ns, &eptr, 10);
		if (ns == eptr)
			return -EINVAL;
		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;

		fuse_info("%s: subsys %s ns %d", __func__, subsys, nsid);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return configdb_fill_namespace(subsys, nsid, buf, filler);
	}
	if (!strcmp(subdir, "allowed_hosts")) {
		const char *host = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (host) {
			if (configdb_stat_host_subsys(host, subsys, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return configdb_fill_host_subsys(subsys, buf, filler);
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

static int port_mkdir(const char *port)
{
	int ret;
	char *p, *eptr = NULL;
	int portid, ana_grpid;

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -EINVAL;

	p = strtok(NULL, "/");
	if (!p) {
		ret = add_port(portid, NULL, 0);
		if (ret < 0)
			fuse_err("%s: cannot add port %d, error %d",
				 __func__, portid, ret);
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
	ret = configdb_add_ana_group(portid, ana_grpid,
				     NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		fuse_err("%s: cannot add ana group %d to "
			 "port %d, error %d", __func__,
			 portid, ana_grpid, ret);
		return ret;
	}
	return 0;
}

static int subsys_mkdir(const char *subsysnqn)
{
	char *p, *ns, *eptr = NULL;
	int nsid;

	p = strtok(NULL, "/");
	if (!p)
		return add_subsys(subsysnqn);

	if (strcmp(p, "namespaces"))
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p)
		return -ENOENT;

	ns = p;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;

	return add_namespace(subsysnqn, nsid);
}

static int nofuse_mkdir(const char *path, mode_t mode)
{
	char *pathbuf, *root, *p;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	p = strtok(NULL, "/");
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		ret = port_mkdir(p);
	}
	if (!strcmp(root, subsys_dir)) {
		ret = subsys_mkdir(p);
	}
	if (!strcmp(root, hosts_dir)) {
		char *hostnqn = p;

		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_add_host(hostnqn);
	}
out_free:
	free(pathbuf);
	if (ret != 0)
		fuse_err("%s: path %s error %d",
			 __func__, path, ret);
	return ret;
}

static int port_rmdir(const char *port)
{
	char *p, *ana_grp, *eptr = NULL;
	unsigned int portid;
	int ana_grpid;

	portid = strtoul(port, &eptr, 10);
	if (port == eptr)
		return -EINVAL;
	p = strtok(NULL, "/");
	if (!p) {
		struct nofuse_port *port = find_port(portid);
		int ret;

		if (!port) {
			fuse_err("%s: port %d not found",
			       __func__, portid);
			return -ENOENT;
		}
		ret = del_port(port);
		if (ret < 0) {
			fuse_err("%s: cannot remove port %d, error %d",
			       __func__, portid, ret);
		}
		return ret;;
	}
	if (strcmp(p, "ana_groups"))
		return -ENOENT;
	p = strtok(NULL, "/");
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
	return configdb_del_ana_group(portid, ana_grpid);
}

static int subsys_rmdir(const char *subsysnqn)
{
	char *p, *ns, *eptr = NULL;
	int nsid;

	p = strtok(NULL, "/");
	if (!p) {
		struct nofuse_subsys *subsys = find_subsys(subsysnqn);
		if (!subsys)
			return -ENOENT;

		return del_subsys(subsys);
	}
	if (strcmp(p, "namespaces"))
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p)
		return -ENOENT;
	ns = p;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	nsid = strtoul(ns, &eptr, 10);
	if (ns == eptr)
		return -EINVAL;
	return del_namespace(subsysnqn, nsid);
}

static int nofuse_rmdir(const char *path)
{
	char *pathbuf, *root, *p;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	fuse_info("%s: path %s", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	p = strtok(NULL, "/");
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		ret = port_rmdir(p);
	}
	if (!strcmp(root, subsys_dir)) {
		ret = subsys_rmdir(p);
	}
	if (!strcmp(root, hosts_dir)) {
		const char *hostnqn = p;

		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_del_host(hostnqn);
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
		ret = configdb_stat_subsys_port(subsys, portid, NULL);
		if (ret < 0)
			goto out_free;
		sprintf(buf, "../../../subsystems/%s", subsys);
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = configdb_stat_host_subsys(host, subsys, NULL);
		if (ret < 0)
			goto out_free;
		sprintf(buf, "../../../hosts/%s", host);
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
		int subsysnum = 0;

		ret = parse_port_link(s, &portid, &subsys);
		if (ret < 0)
			goto out_free;
		fuse_info("%s: subsys %s portid %d",
		       __func__, subsys, portid);
		ret = configdb_add_subsys_port(subsys, portid);
		if (ret < 0) {
			fuse_err("%s: failed to add subsys, error %d",
			       __func__, ret);
			goto out_free;
		}
		ret = configdb_count_subsys_port(portid, &subsysnum);
		if (ret < 0) {
			configdb_del_subsys_port(subsys, portid);
			goto out_free;
		}
		if (subsysnum == 1) {
			struct nofuse_port *port = find_port(portid);

			if (!port) {
				fuse_err("%s: port %d not founde",
				       __func__, portid);
				configdb_del_subsys_port(subsys, portid);
				ret = -EINVAL;
				goto out_free;
			}
			ret = start_port(port);
			if (ret) {
				configdb_del_subsys_port(subsys, portid);
				goto out_free;
			}
		}
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = configdb_add_host_subsys(host, subsys);
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
		int subsysnum = 0;
		struct nofuse_port *port;

		ret = parse_port_link(s, &portid, &subsys);
		if (ret < 0)
			goto out_free;
		port = find_port(portid);
		if (!port) {
			fuse_err("%s: port %d not found",
			       __func__, portid);
			goto out_free;
		}
		ret = configdb_del_subsys_port(subsys, portid);
		if (ret < 0)
			goto out_free;
		terminate_queues(port, subsys);
		ret = configdb_count_subsys_port(portid, &subsysnum);
		if (ret < 0)
			goto out_free;
		fuse_info("%s: subsys %s portid %d num %d",
		       __func__, subsys, portid, subsysnum);
		if (subsysnum == 0) {
			ret = stop_port(port);
			if (ret) {
				fuse_err("%s: failed to stop port %d",
				   __func__, portid);
				configdb_add_subsys_port(subsys, portid);
				goto out_free;
			}
		}
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		ret = parse_subsys_link(s, &subsys, &host);
		if (ret < 0)
			goto out_free;
		ret = configdb_del_host_subsys(host, subsys);
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

static int parse_namespace_attr(const char *p, int *nsid,
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
			ret = configdb_get_ana_group(port, ana_grp, NULL);
			if (ret < 0) {
				fuse_err("%s: port %d ana_grp %s error %d",
					 __func__, portid, ana_grp, ret);
				ret = -ENOENT;
			} else
				ret = 0;
			goto out_free;
		} else {
			ret = configdb_get_port_attr(portid, attr, NULL);
			if (ret < 0)
				ret = -ENOENT;
			goto out_free;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;
		int nsid;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		fuse_info("%s: subsys %s attr %s p %s", __func__,
		       subsysnqn, attr, p);
		if (!p) {
			ret = configdb_get_subsys_attr(subsysnqn, attr, NULL);
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
			ret = configdb_get_namespace_anagrp(subsysnqn,
							 nsid, NULL);
			goto out_free;
		}
		ret = configdb_get_namespace_attr(subsysnqn, nsid,
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
	return ret;
}

struct value_map_t {
	int val;
	char *desc;
};

struct value_map_t ana_value_map[] =
{
	{ NVME_ANA_OPTIMIZED, "optimized" },
	{ NVME_ANA_NONOPTIMIZED, "non-optimized" },
	{ NVME_ANA_INACCESSIBLE, "inaccessible" },
	{ NVME_ANA_PERSISTENT_LOSS, "persistent-loss" },
	{ NVME_ANA_CHANGE, "change" },
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
			ret = configdb_get_discovery_nqn(buf);
			if (ret < 0)
				goto out_free;
		} else if (!strcmp(root, "debug")) {
			sprintf(buf, "%ctcp,%ccmd,%cep,%cport,%cfuse",
				tcp_debug ? '+' : '-',
				cmd_debug ? '+' : '-',
				ep_debug ? '+' : '-',
				port_debug ? '+' : '-',
				fuse_debug ? '+' : '-');
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
			int ana_state, i;

			if (!ana_grp)
				goto out_free;
			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;
			fuse_info("%s: port %s ana_grp %s", __func__,
			       port, ana_grp);
			ret = configdb_get_ana_group(port, ana_grp, &ana_state);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
			for (i = 0; i < 5; i++) {
				if (ana_value_map[i].val == ana_state) {
					strcpy(buf, ana_value_map[i].desc);
					break;
				}
			}
			ret = 0;
		} else {
			ret = configdb_get_port_attr(portid, attr, buf);
			if (ret < 0) {
				ret = -ENOENT;
				goto out_free;
			}
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;
		int nsid;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		fuse_info("%s: subsys %s attr %s p %s", __func__,
		       subsysnqn, attr, p);
		if (!p) {
			ret = configdb_get_subsys_attr(subsysnqn, attr, buf);
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

				ret = configdb_get_namespace_anagrp(subsysnqn,
								 nsid,
								 &anagrp);
				if (ret < 0) {
					ret = -ENOENT;
					goto out_free;
				}
				sprintf(buf, "%d", anagrp);
			} else {
				ret = configdb_get_namespace_attr(subsysnqn, nsid,
							       attr, buf);
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
	return ret;
}

static int write_namespace(const char *subsysnqn, const char *p,
			   const char *buf, size_t len)
{
	int ret, nsid;
	const char *attr;

	ret = parse_namespace_attr(p, &nsid, &attr);
	if (ret < 0)
		return -ENOENT;

	fuse_info("%s: subsys %s nsid %d attr %s value %s", __func__,
	       subsysnqn, nsid, attr, buf);

	if (!strcmp(attr, "ana_grpid")) {
		int ana_grp, new_ana_grp;
		char *eptr;

		ana_grp = strtoul(buf, &eptr, 10);
		if (buf == eptr)
			return -EINVAL;

		ret = configdb_set_namespace_anagrp(subsysnqn, nsid, ana_grp);
		if (ret < 0)
			return ret;
		ret = configdb_get_namespace_anagrp(subsysnqn, nsid,
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
			ret = enable_namespace(subsysnqn, nsid);
		} else if (enable == 0) {
			ret = disable_namespace(subsysnqn, nsid);
		} else {
			ret = -EINVAL;
		}
		if (ret < 0)
			return ret;
		ret = len;
	} else {
		fuse_info("%s: attr %s", __func__, attr);
		ret = configdb_set_namespace_attr(subsysnqn, nsid,
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
			ret = configdb_set_discovery_nqn(value);
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
			int ana_state = 0, i;

			if (!ana_grp)
				goto out_free;
			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;

			for (i = 0; i < 5; i++) {
				if (!strncmp(ana_value_map[i].desc, value,
					     strlen(ana_value_map[i].desc))) {
					ana_state = ana_value_map[i].val;
					break;
				}
			}
			if (ana_state == 0) {
				ret = -EINVAL;
				goto out_free;
			}
			fuse_info("%s: port %s ana_grp %s state %d", __func__,
			       port, ana_grp, ana_state);
			ret = configdb_set_ana_group(port, ana_grp, ana_state);
			if (ret < 0) {
				ret = -EINVAL;
				goto out_free;
			}
			ret = len;
		} else {
			ret = configdb_set_port_attr(portid, attr, value);
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
			ret = configdb_set_subsys_attr(subsysnqn, attr, value);
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

int run_fuse(struct fuse_args *args)
{
	int ret;

	ret = fuse_main(args->argc, args->argv, &nofuse_oper, NULL);
	if (ret)
		fuse_err("fuse terminated with %d", ret);
	fuse_opt_free_args(args);
	return ret;
}
