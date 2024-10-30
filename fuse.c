
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#include "common.h"

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

#define NUM_PORT_ATTRS 6

static const char *port_attrs[NUM_PORT_ATTRS] = {
	"addr_adrfam",
	"addr_traddr",
	"addr_treq",
	"addr_trsvcid",
	"addr_trtype",
	"addr_tsas",
};

static int port_getattr(struct host_iface *iface, const char *path,
			struct stat *stbuf)
{
	int res = -ENOENT;
	const char *p = path;

	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p)) {
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

static int subsys_getattr(struct subsystem *subsys, const char *path,
			  struct stat *stbuf)
{
	int res = -ENOENT;
	const char *p = path;

	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p)) {
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
	const char *p;

	memset(stbuf, 0, sizeof(struct stat));
	if (!strcmp(path, "/")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 5;
	} else if (!strncmp(path, "/hosts", 6)) {
		p = path + 6;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			if (ctx->hostnqn)
				stbuf->st_nlink++;
		} else if (ctx->hostnqn && !strcmp(p, ctx->hostnqn)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else
			res = -ENOENT;
	} else if (!strncmp(path, "/ports", 6)) {
		struct host_iface *iface;

		p = path + 6;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			list_for_each_entry(iface, &iface_linked_list, node)
				stbuf->st_nlink++;
		} else {
			res = -ENOENT;
			list_for_each_entry(iface, &iface_linked_list, node) {
				char portname[16];

				sprintf(portname, "%d", iface->portid);
				if (!strncmp(p, portname, strlen(portname))) {
					p += strlen(portname);
					if (strlen(p) && *p != '/')
						continue;
					res = port_getattr(iface, p, stbuf);
					break;
				}
			}
		}
	} else if (!strncmp(path, "/subsystems", 11)) {
		struct subsystem *subsys;

		p = path + 11;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			list_for_each_entry(subsys, &subsys_linked_list, node)
				stbuf->st_nlink++;
		} else {
			res = -ENOENT;
			list_for_each_entry(subsys, &subsys_linked_list, node) {
				if (!strncmp(p, subsys->nqn,
					     strlen(subsys->nqn))) {
					p += strlen(subsys->nqn);
					if (strlen(p) && *p != '/')
						continue;
					res = subsys_getattr(subsys, p, stbuf);
					break;
				}
			}
		}
	} else
		res = -ENOENT;

	return res;
}

static int fill_port(struct host_iface *iface, const char *path,
		     void *buf, fuse_fill_dir_t filler)
{
	const char *p = path;
	int ret = -ENOENT, i;

	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p)) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		for (i = 0; i < NUM_PORT_ATTRS; i++) {
			filler(buf, port_attrs[i], NULL,
			       0, FUSE_FILL_DIR_PLUS);
		}
		ret = 0;
	}
	return ret;
}

static int fill_subsys(struct subsystem *subsys, const char *path,
		       void *buf, fuse_fill_dir_t filler)
{
	const char *p = path;
	int ret = -ENOENT, i;

	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p)) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
			filler(buf, subsys_attrs[i], NULL,
			       0, FUSE_FILL_DIR_PLUS);
		}
		ret = 0;
	}
	return ret;
}

static int nofuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi,
			  enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;
	const char *p;
	int ret = -ENOENT;

	if (!strcmp(path, "/")) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "ports", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
	} else if (!strcmp(path, "/hosts")) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (ctx->hostnqn)
			filler(buf, ctx->hostnqn, NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
	} else if (!strncmp(path, "/ports", 6)) {
		struct host_iface *iface;

		p = path + 6;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
			filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
			list_for_each_entry(iface, &iface_linked_list, node) {
				char portname[16];

				sprintf(portname, "%d", iface->portid);
				filler(buf, portname, NULL,
				       0, FUSE_FILL_DIR_PLUS);
			}
			ret = 0;
		} else {
			list_for_each_entry(iface, &iface_linked_list, node) {
				char portname[16];

				sprintf(portname, "%d", iface->portid);
				if (!strncmp(portname, p,
					     strlen(portname))) {
					p += strlen(portname);
					if (strlen(p) && *p != '/')
						continue;
					ret = fill_port(iface, p,
							buf, filler);
					break;
				}
			}
		}
	} else if (!strncmp(path, "/subsystems", 11)) {
		struct subsystem *subsys;

		p = path + 11;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
			filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
			list_for_each_entry(subsys, &subsys_linked_list, node) {
				filler(buf, subsys->nqn, NULL, 0, FUSE_FILL_DIR_PLUS);
			}
			ret = 0;
		} else {
			list_for_each_entry(subsys, &subsys_linked_list, node) {
				if (!strncmp(subsys->nqn, p,
					     strlen(subsys->nqn))) {
					p += strlen(subsys->nqn);
					if (strlen(p) && *p != '/')
						continue;
					ret = fill_subsys(subsys, p,
							  buf, filler);
					break;
				}
			}
		}
	}
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
		struct subsystem *subsys;

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

			sprintf(portname, "%d", iface->portid);
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
		struct subsystem *subsys;

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

			sprintf(portname, "%d", iface->portid);
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
