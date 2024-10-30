
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

static int nofuse_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0;
	const char *p;

	memset(stbuf, 0, sizeof(struct stat));
	if (!strcmp(path, "/")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (!strncmp(path, "/hosts", 6)) {
		p = path + 6;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else if (ctx->hostnqn && !strcmp(p, ctx->hostnqn)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else
			res = -ENOENT;
	} else if (!strncmp(path, "/ports", 6)) {
		p = path + 6;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else {
			struct host_iface *iface;

			res = -ENOENT;
			list_for_each_entry(iface, &iface_linked_list, node) {
				char portname[16];

				sprintf(portname, "%d", iface->portid);
				if (!strcmp(p, portname)) {
					stbuf->st_mode = S_IFDIR | 0755;
					stbuf->st_nlink = 2;
					res = 0;
					break;
				}
			}
		}
	} else if (!strncmp(path, "/subsystems", 11)) {
		p = path + 11;
		if (strlen(p) && *p == '/')
			p++;
		if (!strlen(p)) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else {
			struct subsystem *subsys;

			res = -ENOENT;
			list_for_each_entry(subsys, &subsys_linked_list, node) {
				if (!strcmp(p, subsys->nqn)) {
					stbuf->st_mode = S_IFDIR | 0755;
					stbuf->st_nlink = 2;
					res = 0;
					break;
				}
			}
		}
	} else
		res = -ENOENT;

	return res;
}

static int nofuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi,
			  enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (!strcmp(path, "/")) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "ports", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
	} else if (!strcmp(path, "/hosts")) {
		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		if (ctx->hostnqn)
			filler(buf, ctx->hostnqn, NULL, 0, FUSE_FILL_DIR_PLUS);
	} else if (!strcmp(path, "/ports")) {
		struct host_iface *iface;

		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		list_for_each_entry(iface, &iface_linked_list, node) {
			char portname[16];

			sprintf(portname, "%d", iface->portid);
			filler(buf, portname, NULL, 0, FUSE_FILL_DIR_PLUS);
		}
	} else if (!strcmp(path, "/subsystems")) {
		struct subsystem *subsys;

		filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
		list_for_each_entry(subsys, &subsys_linked_list, node) {
			filler(buf, subsys->nqn, NULL, 0, FUSE_FILL_DIR_PLUS);
		}
	} else
		return -ENOENT;
	return 0;
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
