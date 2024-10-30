
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

#define NUM_PORT_ATTRS 6

static char *port_attrs[NUM_PORT_ATTRS] = {
	"addr_adrfam",
	"addr_traddr",
	"addr_treq",
	"addr_trsvcid"
	"addr_trtype",
	"addr_tsas",
};

static int port_getattr(struct host_iface *iface, const char *path,
			struct stat *stbuf)
{
	int res = -ENOENT;
	const char *p = path;

	printf("%s %s\n", __func__, path);
	if (strlen(p) && *p == '/')
		p++;
	if (!strlen(p)) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		res = 0;
	} else {
		int i;

		for (i = 0; i < NUM_PORT_ATTRS; i++) {
			if (!strcmp(port_attrs[i], p)) {
				stbuf->st_mode = S_IFREG | 0444;
				stbuf->st_nlink = 1;
				stbuf->st_size = 0;
				res = 0;
			}
		}
	}
	return res;
}

#define NUM_SUBSYS_ATTRS 7

static char *subsys_attrs[NUM_SUBSYS_ATTRS] = {
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
		int i;

		for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
			if (!strcmp(subsys_attrs[i], p)) {
				stbuf->st_mode = S_IFREG | 0444;
				stbuf->st_nlink = 1;
				stbuf->st_size = 0;
				res = 0;
			}
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

static int nofuse_open(const char *path, struct fuse_file_info *fi)
{
	return -ENOENT;
}

static int nofuse_read(const char *path, char *buf, size_t size, off_t offset,
		       struct fuse_file_info *fi)
{
	(void) fi;

	printf("read %s\n", path);
	return -ENOENT;
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
