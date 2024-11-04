
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#include "common.h"

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

static const char *select_attr(const char *attrs[], int num_attrs,
			       const char *path)
{
	int i;
	const char *p = path;

	if (strlen(p) && *p == '/')
		p++;
	for (i = 0; i < num_attrs; i++) {
		if (!strncmp(attrs[i], p, strlen(attrs[i]))) {
			p += strlen(attrs[i]);
			if (strlen(p) && *p == '/')
				p++;
			if (strlen(p))
				continue;
			return attrs[i];
		}
	}
	return NULL;
}

static enum dir_type next_dir_type(const char *e, enum dir_type cur, void **p)
{
	enum dir_type next = TYPE_NONE;
	struct host_iface *iface = NULL;
	struct nofuse_subsys *subsys = NULL;

	switch (cur) {
	case TYPE_ROOT:
		if (!strcmp(e, "hosts")) {
			next = TYPE_HOST_DIR;
		} else if (!strcmp(e, "ports")) {
			next = TYPE_PORT_DIR;
		} else if (!strcmp(e, "subsystems")) {
			next = TYPE_SUBSYS_DIR;
		}
		break;
	case TYPE_HOST_DIR:
		if (ctx->hostnqn && !strcmp(ctx->hostnqn, e)) {
			next = TYPE_HOST;
			*p = ctx;
		}
		break;
	case TYPE_PORT_DIR:
		list_for_each_entry(iface, &iface_linked_list, node) {
			char portname[16];

			sprintf(portname, "%d", iface->port.port_id);
			if (!strcmp(portname, e)) {
				next = TYPE_PORT;
				*p = iface;
				break;
			}
		}
		break;
	case TYPE_SUBSYS_DIR:
		list_for_each_entry(subsys, &subsys_linked_list, node) {
			if (!strcmp(subsys->nqn, e)) {
				next = TYPE_SUBSYS;
				*p = subsys;
				break;
			}
		}
		break;
	default:
		break;
	}
	return next;
}

#define NUM_PORT_ATTRS 6

static const char *port_attrs[NUM_PORT_ATTRS] = {
	"addr_adrfam",
	"addr_traddr",
	"addr_treq",
	"addr_trsvcid",
	"addr_trtype",
	"addr_tsas",
};

static int port_getattr(struct host_iface *iface, char *path,
			struct stat *stbuf)
{
	int res = -ENOENT;
	char *p = path;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		res = 0;
	} else {
		const char *attr = select_attr(port_attrs, NUM_PORT_ATTRS, p);

		if (attr) {
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			stbuf->st_size = 256;
			res = 0;
		}
	}
	return res;
}

#define NUM_SUBSYS_ATTRS 7

static const char *subsys_attrs[NUM_SUBSYS_ATTRS] = {
	"attr_allow_any_host",
	"attr_firmware",
	"attr_ieee_oui",
	"attr_model",
	"attr_qid_max",
	"attr_serial",
	"attr_version",
};

static int subsys_getattr(struct nofuse_subsys *subsys, char *path,
			  struct stat *stbuf)
{
	int res = -ENOENT;
	char *p = path;

	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		res = 0;
	} else {
		const char *attr = select_attr(subsys_attrs,
					       NUM_SUBSYS_ATTRS, p);

		if (attr) {
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			stbuf->st_size = 256;
			res = 0;
		}
	}
	return res;
}

static int nofuse_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0;
	char *p = NULL, *pathbuf;
	enum dir_type type;
	void *s;

	memset(stbuf, 0, sizeof(struct stat));
	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	p = strtok(pathbuf, "/");
	printf("%s: %s %s\n", __func__, pathbuf, p);
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
		goto out_free;
	}

	type = next_dir_type(p, TYPE_ROOT, NULL);
	if (type == TYPE_NONE) {
		res = -ENOENT;
		goto out_free;
	}
	printf("%s: type %d %p\n", __func__, type, p);
	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		if (type == TYPE_HOST_DIR) {
			if (ctx->hostnqn)
				stbuf->st_nlink++;
		} else if (type == TYPE_PORT_DIR) {
			struct host_iface *iface;

			list_for_each_entry(iface, &iface_linked_list, node)
				stbuf->st_nlink++;
		} else {
			struct nofuse_subsys *subsys;

			list_for_each_entry(subsys, &subsys_linked_list, node)
				stbuf->st_nlink++;
		}
		goto out_free;
	}
	type = next_dir_type(p, type, &s);
	if (type == TYPE_NONE) {
		res = -ENOENT;
		goto out_free;
	}

	printf("%s: type %d %p\n", __func__, type, p);
	p = strtok(NULL, "/");
	if (!p) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (type == TYPE_PORT) {
		struct host_iface *iface = s;

		res = port_getattr(iface, p, stbuf);
	} else if (type == TYPE_SUBSYS) {
		struct nofuse_subsys *subsys = s;

		res = subsys_getattr(subsys, p, stbuf);
	} else
		res = -ENOENT;

out_free:
	free(pathbuf);
	return res;
}

static int fill_port(struct host_iface *iface, const char *path,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p = path;
	int i;

	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;

	filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		filler(buf, port_attrs[i], NULL,
		       0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

static int fill_subsys(struct nofuse_subsys *subsys, const char *path,
		       void *buf, fuse_fill_dir_t filler)
{
	const char *p = path;
	int i;

	p = strtok(NULL, "/");
	if (p)
		return -ENOENT;

	filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		filler(buf, subsys_attrs[i], NULL,
		       0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

static int nofuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi,
			  enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;
	char *p, *pathbuf;
	int ret = -ENOENT;
	enum dir_type type;
	struct host_iface *iface;
	struct nofuse_subsys *subsys;
	void *s;

	pathbuf = strdup(path);
	if (!pathbuf)
		return -ENOMEM;
	p = strtok(pathbuf, "/");
	if (!p) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "ports", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
		goto out_free;
	}
	type = next_dir_type(p, TYPE_ROOT, NULL);
	if (type == TYPE_NONE)
		goto out_free;

	p = strtok(NULL, "/");
	if (!p) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		switch (type) {
		case TYPE_HOST_DIR:
			if (ctx->hostnqn)
				filler(buf, ctx->hostnqn, NULL,
				       0, FUSE_FILL_DIR_PLUS);
			ret = 0;
			break;
		case TYPE_PORT_DIR:
			list_for_each_entry(iface, &iface_linked_list, node) {
				char portname[16];

				sprintf(portname, "%d", iface->port.port_id);
				filler(buf, portname, NULL,
				       0, FUSE_FILL_DIR_PLUS);
			}
			ret = 0;
			break;
		case TYPE_SUBSYS_DIR:
			list_for_each_entry(subsys, &subsys_linked_list, node) {
				filler(buf, subsys->nqn, NULL,
				       0, FUSE_FILL_DIR_PLUS);
			}
			ret = 0;
			break;
		default:
			break;
		}
		goto out_free;
	}
	type = next_dir_type(p, type, &s);
	if (type == TYPE_NONE)
		goto out_free;

	switch (type) {
	case TYPE_PORT:
		ret = fill_port((struct host_iface *)s, p, buf, filler);
		break;
	case TYPE_SUBSYS:
		ret = fill_subsys((struct nofuse_subsys *)s, p, buf, filler);
		break;
	default:
		break;
	}
out_free:
	free(pathbuf);
	return ret;
}

static int attr_open(const char *path, const char **attrs, int num_attrs,
		     struct fuse_file_info *fi)
{
	const char *p = path;
	const char *attr;

	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p))
		return -ENOENT;
	attr = select_attr(attrs, num_attrs, p);
	if (!attr)
		return -ENOENT;
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;
	return 0;
}

static int nofuse_open(const char *path, struct fuse_file_info *fi)
{
	const char *p = path;
	int ret = -ENOENT;

	if (!strncmp(path, "/subsystems", 11)) {
		struct nofuse_subsys *subsys;

		p += 11;
		if (strlen(p) && *p == '/')
			p++;
		list_for_each_entry(subsys, &subsys_linked_list, node) {
			if (!strncmp(subsys->nqn, p,
				     strlen(subsys->nqn))) {
				p += strlen(subsys->nqn);
				ret = attr_open(p, subsys_attrs,
						NUM_SUBSYS_ATTRS, fi);
				break;
			}
		}
	} else if (!strncmp(path, "/ports", 6)) {
		struct host_iface *iface;

		p += 6;
		if (strlen(p) && *p == '/')
			p++;
		list_for_each_entry(iface, &iface_linked_list, node) {
			char portname[16];

			sprintf(portname, "%d", iface->port.port_id);
			if (!strncmp(p, portname, strlen(portname))) {
				p += strlen(portname);
				ret = attr_open(p, port_attrs,
						NUM_PORT_ATTRS, fi);
				break;
			}
		}
	}
	return ret;
}

static int nofuse_read(const char *path, char *buf, size_t size, off_t offset,
		       struct fuse_file_info *fi)
{
	const char *p = path;
	int ret = -ENOENT;

	if (!strncmp(path, "/subsystems", 11)) {
		struct nofuse_subsys *subsys;

		p += 11;
		if (strlen(p) && *p == '/')
			p++;
		list_for_each_entry(subsys, &subsys_linked_list, node) {
			const char *attr;

			if (strncmp(subsys->nqn, p,
				    strlen(subsys->nqn)))
				continue;

			p += strlen(subsys->nqn);
			attr = select_attr(subsys_attrs,
					   NUM_SUBSYS_ATTRS, p);
			if (!attr)
				return ret;
			if (!strcmp(attr, "attr_allow_any_host")) {
				sprintf(buf, "%d\n", subsys->allow_any);
				return 2;
			} else {
				return 0;
			}
		}
	} else if (!strncmp(path, "/ports", 6)) {
		struct host_iface *iface;

		p += 6;
		if (strlen(p) && *p == '/')
			p++;
		list_for_each_entry(iface, &iface_linked_list, node) {
			const char *attr;
			char portname[16];

			sprintf(portname, "%d", iface->port.port_id);
			if (strncmp(p, portname, strlen(portname)))
				continue;

			p += strlen(portname);
			attr = select_attr(port_attrs,
					   NUM_PORT_ATTRS, p);
			if (!attr)
				return ret;
			memset(buf, 0, size);
			if (!strcmp(attr, "addr_adrfam")) {
				strcpy(buf, iface->port.adrfam);
			} else if (!strcmp(attr, "addr_traddr")) {
				strcpy(buf, iface->port.traddr);
			} else if (!strcmp(attr, "addr_trsvcid")) {
				strcpy(buf, iface->port.trsvcid);
			} else if (!strcmp(attr, "addr_trtype")) {
				strcpy(buf, iface->port.trtype);
			} else if (!strcmp(attr, "addr_tsas")) {
				strcpy(buf, "none");
			} else if (!strcmp(attr, "addr_treq")) {
				strcpy(buf, "not specified");
			}
			if (strlen(buf))
				strcat(buf, "\n");
			return strlen(buf);
		}
	}
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
