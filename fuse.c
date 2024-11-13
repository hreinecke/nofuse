
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

const char hosts_dir[] = "hosts";
const char ports_dir[] = "ports";
const char subsys_dir[] = "subsystems";

enum dir_type {
	TYPE_NONE,
	TYPE_ROOT,
	TYPE_HOST_DIR,		/* hosts */
	TYPE_HOST,		/* hosts/<host> */
	TYPE_PORT_DIR,		/* ports */
	TYPE_PORT,		/* ports/<port> */
	TYPE_PORT_ATTR,		/* ports/<port>/addr_<attr> */
	TYPE_PORT_SUBSYS_DIR,	/* ports/<port>/subsystems */
	TYPE_PORT_SUBSYS,	/* ports/<port>/subsystems/<subsys> */
	TYPE_SUBSYS_DIR,	/* subsystems */
	TYPE_SUBSYS,		/* subsystems/<subsys> */
	TYPE_SUBSYS_ATTR,	/* subsystems/<subsys>/attr_<attr> */
	TYPE_SUBSYS_HOSTS_DIR,	/* subsystems/<subsys>/allowed_hosts */
	TYPE_SUBSYS_HOST,	/* subsystems/<subsys>/allowed_hosts/<host> */
};

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

	ret = configdb_stat_host(host, stbuf);
	if (ret < 0)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;
	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
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

	if (!strcmp(attr, "subsystems")) {
		const char *subsys = p;

		printf("%s: port %d subsys %s\n", __func__,
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
		printf("%s: port %d subsys %s\n", __func__, portid, subsys);
		return configdb_stat_subsys_port(subsys, portid, stbuf);
	}
	if (!strcmp(attr, "ana_groups")) {
		const char *ana_grp = p;

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

		printf("%s: port %s ana group %s\n",
		       __func__, port, ana_grp);
		ret = configdb_stat_ana_group(port, ana_grp, stbuf);
		if (ret < 0)
			return ret;

		p = strtok(NULL, "/");
		if (!p) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			return 0;
		}
		if (strcmp(p, "ana_state"))
			return -ENOENT;
		return 0;
	}
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
	printf("%s: subsys %s attr %s\n", __func__, subsysnqn, p);

	attr = p;
	p = strtok(NULL, "/");

	if (!strcmp(attr, "allowed_hosts")) {
		const char *hostnqn = p;

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
		printf("%s: subsys %s host %s\n", __func__, subsysnqn, hostnqn);
		return configdb_stat_host_subsys(hostnqn, subsysnqn, stbuf);
	}

	if (!strcmp(attr, "namespaces")) {
		const char *ns = p;
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
		printf("%s: subsys %s ns %d\n", __func__, subsysnqn, nsid);
		attr = strtok(NULL, "/");
		if (!attr) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			return 0;
		}
		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		printf("%s: subsys %s ns %d attr %s\n", __func__,
		       subsysnqn, nsid, attr);
		ret = configdb_get_namespace_attr(subsysnqn, nsid, attr, NULL);
		if (ret < 0)
			return -ENOENT;
		goto found;
	}

	if (strncmp(attr, "attr_", 5))
		return -ENOENT;
	ret = configdb_get_subsys_attr(subsysnqn, attr, NULL);
	if (ret < 0)
		return -ENOENT;
found:
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
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
		goto out_free;
	}

	p = strtok(NULL, "/");
	if (!p) {
		int nlinks = 0;

		if (!strcmp(root, "discovery_nqn")) {
			stbuf->st_mode = S_IFREG | 0644;
			stbuf->st_nlink = 1;
			stbuf->st_size = 256;
			res = 0;
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
		printf("%s: subsys %s\n", __func__, subsys);
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

		printf("%s: subsys %s ns %d\n", __func__, subsys, nsid);
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
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, hosts_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, ports_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, subsys_dir, NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "discovery_nqn", NULL, 0, FUSE_FILL_DIR_PLUS);
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
	return ret;
}

static int nofuse_mkdir(const char *path, mode_t mode)
{
	char *pathbuf, *root, *p;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	p = strtok(NULL, "/");
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		char *port = p, *eptr = NULL;
		int portid, ana_grpid;

		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		p = strtok(NULL, "/");
		if (!p) {
			ret = add_iface(portid, NULL, 0);
			if (ret < 0)
				printf("%s: cannot add port %d, error %d\n",
				       __func__, portid, ret);
			goto out_free;
		}
		if (strcmp(p, "ana_groups"))
			goto out_free;
		p = strtok(NULL, "/");
		if (!p)
			goto out_free;
		eptr = NULL;
		ana_grpid = strtoul(p, &eptr, 10);
		if (p == eptr)
			goto out_free;
		printf("%s: port %d ana group %d\n", __func__,
		       portid, ana_grpid);
		ret = configdb_add_ana_group(portid, ana_grpid,
					  NVME_ANA_OPTIMIZED);
		if (ret < 0) {
			printf("%s: cannot add ana group %d to "
			       "port %d, error %d\n", __func__,
			       portid, ana_grpid, ret);
			ret = -ENOENT;
			goto out_free;
		}
	}
	if (!strcmp(root, subsys_dir)) {
		char *subsysnqn = p, *ns, *eptr = NULL;
		int nsid;

		p = strtok(NULL, "/");
		if (!p) {
			ret = add_subsys(subsysnqn, NVME_NQN_NVM);
			goto out_free;
		}
		if (strcmp(p, "namespaces"))
			goto out_free;
		p = strtok(NULL, "/");
		if (!p)
			goto out_free;
		ns = p;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		nsid = strtoul(ns, &eptr, 10);
		if (ns == eptr) {
			ret = -EINVAL;
			goto out_free;
		}
		ret = add_namespace(subsysnqn, nsid);
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
	return ret;
}

static int nofuse_rmdir(const char *path)
{
	char *pathbuf, *root, *p;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	p = strtok(NULL, "/");
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		char *port = p, *ana_grpid, *eptr = NULL;
		unsigned int portid;

		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		p = strtok(NULL, "/");
		if (!p) {
			ret = del_iface(portid);
			if (ret < 0) {
				printf("%s: cannot remove port %d, error %d\n",
				       __func__, portid, ret);
			}
			goto out_free;
		}
		if (strcmp(p, "ana_groups"))
			goto out_free;
		p = strtok(NULL, "/");
		if (!p)
			goto out_free;
		ana_grpid = p;
		printf("%s: port %s ana group %s\n", __func__,
		       port, ana_grpid);
		if (!strcmp(ana_grpid, "1")) {
			ret = -EACCES;
			goto out_free;
		}
		ret = configdb_del_ana_group(port, ana_grpid);
		if (ret < 0) {
			printf("%s: cannot remove ana group %s from "
			       "port %s, error %d\n", __func__,
			       ana_grpid, port, ret);
			ret = -ENOENT;
			goto out_free;
		}
	}
	if (!strcmp(root, subsys_dir)) {
		char *subsysnqn = p, *ns, *eptr = NULL;
		int nsid;

		p = strtok(NULL, "/");
		if (!p) {
			ret = free_subsys(subsysnqn);
			goto out_free;
		}
		if (strcmp(p, "namespaces"))
			goto out_free;
		p = strtok(NULL, "/");
		if (!p)
			goto out_free;
		ns = p;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		nsid = strtoul(ns, &eptr, 10);
		if (ns == eptr) {
			ret = -EINVAL;
			goto out_free;
		}
		ret = del_namespace(subsysnqn, nsid);
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
	return ret;
}

static int nofuse_readlink(const char *path, char *buf, size_t len)
{
	char *p, *pathbuf, *root, *attr;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *port, *subsys;
		char *eptr = NULL;
		int portid;

		port = strtok(NULL, "/");
		if (!port)
			goto out_free;
		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "subsystems"))
			goto out_free;
		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_stat_subsys_port(subsys, portid, NULL);
		if (ret < 0)
			goto out_free;
		sprintf(buf, "../../../subsystems/%s", subsys);
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "allowed_hosts"))
			goto out_free;
		host = strtok(NULL, "/");
		if (!host)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_stat_host_subsys(host, subsys, NULL);
		if (ret < 0)
			goto out_free;
		sprintf(buf, "../../../hosts/%s", host);
		ret = 0;
	}
out_free:
	free(pathbuf);
	return ret;
}

static int nofuse_symlink(const char *from, const char *to)
{
	char *p, *pathbuf, *root, *attr;
	int ret = -ENOENT;

	pathbuf = strdup(to);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s from %s\n",
	       __func__, pathbuf, from);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *port, *subsys;
		char *eptr = NULL;
		int portid, subsysnum = 0;

		port = strtok(NULL, "/");
		if (!port)
			goto out_free;
		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "subsystems"))
			goto out_free;
		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		printf("%s: subsys %s portid %d\n",
		       __func__, subsys, portid);
		ret = configdb_add_subsys_port(subsys, portid);
		if (ret < 0)
			goto out_free;
		ret = configdb_count_subsys_port(portid, &subsysnum);
		if (ret < 0) {
			configdb_del_subsys_port(subsys, portid);
			goto out_free;
		}
		if (subsysnum == 1) {
			ret = start_iface(portid);
			if (ret) {
				configdb_del_subsys_port(subsys, portid);
				goto out_free;
			}
		}
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "allowed_hosts"))
			goto out_free;
		host = strtok(NULL, "/");
		if (!host)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_add_host_subsys(host, subsys);
		if (ret < 0)
			goto out_free;
		ret = 0;
	}
out_free:
	free(pathbuf);
	return ret;
}

static int nofuse_unlink(const char *path)
{
	char *p, *pathbuf, *root, *attr;
	int ret = -ENOENT;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s\n",
	       __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *port, *subsys;
		char *eptr = NULL;
		int portid, subsysnum = 0;

		port = strtok(NULL, "/");
		if (!port)
			goto out_free;
		portid = strtoul(port, &eptr, 10);
		if (port == eptr)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "subsystems"))
			goto out_free;
		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		printf("%s: subsys %s portid %d\n",
		       __func__, subsys, portid);
		ret = configdb_count_subsys_port(portid, &subsysnum);
		if (ret < 0)
			goto out_free;
		ret = configdb_del_subsys_port(subsys, portid);
		if (ret < 0)
			goto out_free;
		if (subsysnum == 1) {
			ret = stop_iface(portid);
			if (ret)
				goto out_free;
		}
		ret = 0;
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsys, *host;

		subsys = strtok(NULL, "/");
		if (!subsys)
			goto out_free;
		attr = strtok(NULL, "/");
		if (!attr)
			goto out_free;
		if (strcmp(attr, "allowed_hosts"))
			goto out_free;
		host = strtok(NULL, "/");
		if (!host)
			goto out_free;
		p = strtok(NULL, "/");
		if (p)
			goto out_free;
		ret = configdb_del_host_subsys(host, subsys);
		if (ret < 0)
			goto out_free;
		ret = 0;
	}
out_free:
	free(pathbuf);
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
	printf("%s: path %s\n", __func__, path);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;

	if (!strcmp(root, hosts_dir))
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		if (!strcmp(root, "discovery_nqn"))
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
		printf("%s: port %d attr %s p %s\n", __func__,
		       portid, attr, p);
		if (!strcmp(attr, "ana_groups")) {
			const char *ana_grp = p;

			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;
			printf("%s: port %d ana_grp %s attr %s\n", __func__,
			       portid, ana_grp, p);
			ret = configdb_get_ana_group(port, ana_grp, NULL);
			if (ret < 0) {
				printf("%s: error %d\n", __func__, ret);
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
		printf("%s: subsys %s attr %s p %s\n", __func__,
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
		if (strcmp(root, "discovery_nqn"))
			goto out_free;
		ret = configdb_get_discovery_nqn(buf);
		if (ret < 0)
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
		printf("%s: port %d attr %s p %s\n", __func__,
		       portid, attr, p);
		if (!strcmp(attr, "ana_groups")) {
			const char *ana_grp = p;
			int ana_state, i;

			if (!ana_grp)
				goto out_free;
			p = strtok(NULL, "/");
			if (!p || strcmp(p, "ana_state"))
				goto out_free;
			printf("%s: port %s ana_grp %s\n", __func__,
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
		printf("%s: subsys %s attr %s p %s\n", __func__,
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

	printf("%s: subsys %s nsid %d attr %s value %s\n", __func__,
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

		printf("%s: enable %d\n", __func__, enable);
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
		printf("%s: attr %s\n", __func__, attr);
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
	memset(value, 0, strlen(buf));
	strncpy(value, buf, len);
	ptr = value;

	while (ptr && *ptr) {
		if (*ptr == '\n') {
			*ptr = '\0';
			break;
		}
		ptr++;
	}
	printf("%s: path %s buf %s len %ld off %ld\n", __func__,
	       pathbuf, value, len, offset);
	root = strtok(pathbuf, "/");
	if (!root)
		goto out_free;

	if (!strcmp(root, hosts_dir))
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		if (strcmp(root, "discovery_nqn"))
			goto out_free;
		ret = configdb_set_discovery_nqn(value);
		if (ret < 0)
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
		printf("%s: port %d attr %s p %s\n", __func__,
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
				if (!strncmp(ana_value_map[i].desc, buf,
					     strlen(ana_value_map[i].desc))) {
					ana_state = ana_value_map[i].val;
					break;
				}
			}
			if (ana_state == 0) {
				ret = -EINVAL;
				goto out_free;
			}
			printf("%s: port %s ana_grp %s state %d\n", __func__,
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
			ret = write_namespace(subsysnqn, p, buf, len);
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
		fprintf(stderr, "fuse terminated with %d\n", ret);
	fuse_opt_free_args(args);
	return ret;
}
