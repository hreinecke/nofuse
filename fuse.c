
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#include "common.h"
#include "inode.h"

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

struct inode_table_t {
	enum dir_type type;
	enum dir_type next;
	const char *table;
};

static void *nofuse_init(struct fuse_conn_info *conn,
			 struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static int port_getattr(char *port, int parent_ino,
			struct stat *stbuf)
{
	int ret;
	char *p, *attr;

	ret = inode_stat_port(port, stbuf);
	if (ret)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
		return 0;
	}

	attr = p;
	p = strtok(NULL, "/");

	if (!strcmp(attr, "subsystems")) {
		const char *subsys = p;

		printf("%s: port %s subsys %s\n", __func__,
		       port, subsys);
		if (!subsys) {
			int num_subsys = 0;

			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			ret = inode_count_subsys_port(port, &num_subsys);
			if (ret)
				return -ENOENT;
			stbuf->st_nlink += num_subsys;
			return 0;
		}
		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		printf("%s: port %s subsys %s\n", __func__, port, subsys);
		return inode_stat_subsys_port(subsys, port, stbuf);
	}
	if (!strcmp(attr, "ana_groups")) {
		const char *ana_grp = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		if (!ana_grp) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 3;
			return 0;
		}
		if (strcmp(ana_grp, "1"))
			return -ENOENT;
		stbuf->st_mode = S_IFLNK | 0755;
		stbuf->st_nlink = 1;
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

	ret = inode_get_port_attr(port, attr, NULL);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int subsys_getattr(char *subsysnqn, int parent_ino,
			  struct stat *stbuf)
{
	char *p, *attr;
	int ret;

	ret = inode_stat_subsys(subsysnqn, stbuf);
	if (ret)
		return -ENOENT;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
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
			ret = inode_count_host_subsys(subsysnqn, &num_hosts);
			if (ret)
				return -ENOENT;
			stbuf->st_nlink += num_hosts;
			return 0;
		}
		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		printf("%s: subsys %s host %s\n", __func__, subsysnqn, hostnqn);
		return inode_stat_host_subsys(hostnqn, subsysnqn, stbuf);
	}

	if (!strcmp(attr, "namespaces")) {
		const char *ns = p;

		if (!ns) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			return 0;
		}
		printf("%s: subsys %s ns %s\n", __func__, subsysnqn, ns);
		return -ENOENT;
	}

	if (strncmp(attr, "attr_", 5))
		return -ENOENT;
	ret = inode_get_subsys_attr(subsysnqn, attr, NULL);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	return 0;
}

static int nofuse_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0, inode;
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
	inode = inode_get_root(root);
	if (inode < 0) {
		res = -ENOENT;
		goto out_free;
	}

	p = strtok(NULL, "/");
	if (!p) {
		int nlinks;

		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		nlinks = inode_find_links(root, inode);
		if (nlinks < 0)
			res = -ENOENT;
		else {
			printf("%s: tbl %s links %d\n",
			       __func__, root, nlinks);
			stbuf->st_nlink += nlinks;
		}
		goto out_free;
	}
	if (!strcmp(root, hosts_dir)) {
		res = inode_get_host_ino(p, &inode);
		if (res < 0) {
			res = -ENOENT;
			goto out_free;
		}
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		res = 0;
		goto out_free;
	} else if (!strcmp(root, ports_dir)) {
		res = port_getattr(p, inode, stbuf);
	} else if (!strcmp(root, subsys_dir)){
		res = subsys_getattr(p, inode, stbuf);
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

	return inode_fill_host_dir(buf, filler);
}

static int fill_port(int parent_ino, const char *port,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p, *subdir;

	if (!port) {
		/* list contents of /ports */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return inode_fill_port_dir(buf, filler);
	}

	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /ports/<portid> */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return inode_fill_port(port, buf, filler);
	}
	subdir = p;
	p = strtok(NULL, "/");
	if (!strcmp(subdir, "subsystems")) {
		const char *subsys = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;

		printf("%s: port %s subsys %s\n", __func__, port, subsys);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (subsys) {
			if (inode_stat_subsys_port(subsys, port, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return inode_fill_subsys_port(port, buf, filler);
	}
	if (!strcmp(subdir, "ana_groups")) {
		const char *ana_grp = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (ana_grp)
			printf("%s: port %s ana_grp %s\n", __func__,
			       port, ana_grp);
		else
			filler(buf, "1", NULL, 0, FUSE_FILL_DIR_PLUS);
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

static int fill_subsys(int parent_ino, const char *subsys,
		       void *buf, fuse_fill_dir_t filler)
{
	const char *p, *subdir;

	if (!subsys) {
		/* list contents of /subsystems */
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return inode_fill_subsys_dir(buf, filler);
	}
	p = strtok(NULL, "/");
	if (!p) {
		/* list contents of /subsystems/<subsys> */
		printf("%s: subsys %s\n", __func__, subsys);
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return inode_fill_subsys(subsys, buf, filler);
	}
	subdir = p;
	p = strtok(NULL, "/");
	if (!strcmp(subdir, "namespaces")) {
		const char *ns = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;

		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (ns)
			printf("%s: subsys %s ns %s\n", __func__, subsys, ns);
		return 0;
	}
	if (!strcmp(subdir, "allowed_hosts")) {
		const char *host = p;

		p = strtok(NULL, "/");
		if (p)
			return -ENOENT;
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (host) {
			if (inode_stat_host_subsys(host, subsys, NULL) < 0)
				return -ENOENT;
			return 0;
		}
		return inode_fill_host_subsys(subsys, buf, filler);
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
	int ret = -ENOENT, inode;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	printf("%s: path %s\n", __func__, pathbuf);
	root = strtok(pathbuf, "/");
	if (!root) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		inode_fill_root(buf, filler);
		ret = 0;
		goto out_free;
	}
	inode = inode_get_root(root);
	if (inode < 0)
		goto out_free;

	p = strtok(NULL, "/");
	if (!strcmp(root, hosts_dir))
		ret = fill_host(p, buf, filler);
	else if (!strcmp(root, ports_dir))
		ret = fill_port(inode, p, buf, filler);
	else if (!strcmp(root, subsys_dir))
		ret = fill_subsys(inode, p, buf, filler);

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

		port = strtok(NULL, "/");
		if (!port)
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
		sprintf(buf, "../../../hosts/%s", host);
		ret = 0;
	}
out_free:
	free(pathbuf);
	return ret;
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
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *portid = p;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		if (p) {
			ret = -ENOENT;
			goto out_free;
		}
		ret = inode_get_port_attr(portid, attr, NULL);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		if (p) {
			ret = -ENOENT;
			goto out_free;
		}

		ret = inode_get_subsys_attr(subsysnqn, attr, NULL);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
	}
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		ret = -EACCES;
	else
		ret = 0;
out_free:
	free(pathbuf);
	return ret;
}

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
	if (!p)
		goto out_free;
	if (!strcmp(root, ports_dir)) {
		const char *portid = p;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		if (p) {
			ret = -ENOENT;
			goto out_free;
		}
		ret = inode_get_port_attr(portid, attr, buf);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
	} else if (!strcmp(root, subsys_dir)) {
		const char *subsysnqn = p;

		p = strtok(NULL, "/");
		if (!p)
			goto out_free;

		attr = p;
		p = strtok(NULL, "/");
		if (p) {
			ret = -ENOENT;
			goto out_free;
		}

		ret = inode_get_subsys_attr(subsysnqn, attr, buf);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
	}
	if (strlen(buf))
		strcat(buf, "\n");
	ret = strlen(buf);
out_free:
	free(pathbuf);
	return ret;
}

static const struct fuse_operations nofuse_oper = {
	.init           = nofuse_init,
	.getattr	= nofuse_getattr,
	.readdir	= nofuse_readdir,
	.readlink	= nofuse_readlink,
	.open		= nofuse_open,
	.read		= nofuse_read,
};

int run_fuse(struct fuse_args *args)
{
	int ret;

	ret = fuse_main(args->argc, args->argv, &nofuse_oper, ctx);
	if (ret)
		fprintf(stderr, "fuse terminated with %d\n", ret);
	fuse_opt_free_args(args);
	return ret;
}
