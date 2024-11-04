
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
	if (p)
		return -ENOENT;

	if (!strcmp(attr, "ana_groups") ||
	    !strcmp(attr, "referrals") ||
	    !strcmp(attr, "subsystems")) {
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

	attr = p;
	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;

	if (!strcmp(attr, "allowed_hosts") ||
	    !strcmp(attr, "namespaces")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
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
	root = strtok(pathbuf, "/");
	printf("%s: %s %s\n", __func__, pathbuf, root);
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

	printf("%s: root %s\n", __func__, root);
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
	if (p)
		return -ENOENT;
	if (!strcmp(subdir, "ana_groups") ||
	    !strcmp(subdir, "referrals") ||
	    !strcmp(subdir, "subsystems")) {
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
	if (p)
		return -ENOENT;
	if (!strcmp(subdir, "namespaces") ||
	    !strcmp(subdir, "allowed_hosts")) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		return 0;
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

static int nofuse_open(const char *path, struct fuse_file_info *fi)
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
		ret = inode_get_port_attr(portid, attr, NULL);
		if (ret < 0) {
			ret = -ENOENT;
			goto out_free;
		}
	} else if (!strcmp(root, hosts_dir)) {
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
