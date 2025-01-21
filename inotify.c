/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * inotify.c
 * inotify watcher for nvmet configfs
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 *
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/inotify.h>

#include "common.h"
#include "utils.h"
#include "etcd_client.h"
#include "etcd_backend.h"
#include "nvmetd.h"

#define INOTIFY_BUFFER_SIZE 4096

LINKED_LIST(dir_watcher_list);

#define NUM_WATCHER_TYPES 25

enum watcher_type {
	TYPE_UNKNOWN,
	TYPE_ROOT,
	TYPE_HOST_DIR,		/* hosts */
	TYPE_HOST,		/* hosts/<host> */
	TYPE_HOST_ATTR,		/* hosts/<host>/<attr> */
	TYPE_PORT_DIR,		/* ports */
	TYPE_PORT,		/* ports/<port> */
	TYPE_PORT_ATTR,		/* ports/<port>/<attr> */
	TYPE_PORT_ANA_DIR,	/* ports/<port>/ana_groups */
	TYPE_PORT_ANA,		/* ports/<port>/ana_groups/<anagrp> */
	TYPE_PORT_ANA_ATTR,	/* ports/<port>/ana_groups/<anagrp>/<attr> */
	TYPE_PORT_REF_DIR,	/* ports/<port>/referrals */
	TYPE_PORT_REF,		/* ports/<port>/referrals/<traddr> */
	TYPE_PORT_SUBSYS_DIR,	/* ports/<port>/subsystems */
	TYPE_PORT_SUBSYS,	/* ports/<port>/subsystems/<subsys> */
	TYPE_SUBSYS_DIR,	/* subsystems */
	TYPE_SUBSYS,		/* subsystems/<subsys> */
	TYPE_SUBSYS_ATTR,	/* subsystems/<subsys>/<attr> */
	TYPE_SUBSYS_HOST_DIR,	/* subsystems/<subsys>/allowed_hosts */
	TYPE_SUBSYS_HOST,	/* subsystems/<subsys>/allowed_hosts/<host> */
	TYPE_SUBSYS_PT_DIR,	/* subsystems/<subsys>/passthru */
	TYPE_SUBSYS_PT_ATTR,	/* subsystems/<subsys>/passthru/<attr> */
	TYPE_SUBSYS_NS_DIR,	/* subsystems/<subsys>/namespaces */
	TYPE_SUBSYS_NS,		/* subsystems/<subsys>/namespaces/<nsid> */
	TYPE_SUBSYS_NS_ATTR	/* subsystems/<subsys>/namespaces/<nsid>/<attr> */
};

struct watcher_flags_t {
	enum watcher_type type;
	const char *name;
	int flags;
};

struct watcher_flags_t watcher_flags[NUM_WATCHER_TYPES] = {
	{ .type = TYPE_UNKNOWN, .name = "unknown", .flags = 0 },
	{ .type = TYPE_ROOT, .name = "root", .flags = 0 },
	{ .type = TYPE_HOST_DIR, .name = "host_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_HOST, .name = "host", .flags = IN_MODIFY },
	{ .type = TYPE_HOST_ATTR, .name = "host_attr", .flags = 0 },
	{ .type = TYPE_PORT_DIR, .name = "port_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_PORT, .name = "port", .flags = IN_MODIFY },
	{ .type = TYPE_PORT_ATTR, .name = "port_attr", .flags = 0 },
	{ .type = TYPE_PORT_ANA_DIR, .name = "port_ana_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_PORT_ANA, .name = "port_ana", .flags = IN_MODIFY },
	{ .type = TYPE_PORT_ANA_ATTR, .name = "port_ana_attr", .flags = 0 },
	{ .type = TYPE_PORT_SUBSYS_DIR, .name = "port_subsys_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_PORT_SUBSYS, .name = "port_subsys",
	  .flags = IN_DELETE_SELF },
	{ .type = TYPE_PORT_REF_DIR, .name = "port_ref",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_PORT_REF, .name = "referrals",
	  .flags = IN_MODIFY },
	{ .type = TYPE_SUBSYS_DIR, .name = "subsys_dir",
	  .flags = IN_CREATE | IN_DELETE},
	{ .type = TYPE_SUBSYS, .name = "subsys", .flags = IN_MODIFY },
	{ .type = TYPE_SUBSYS_ATTR, .name = "subsys_attr", .flags = 0 },
	{ .type = TYPE_SUBSYS_HOST_DIR, .name = "subsys_host_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_SUBSYS_HOST, .name = "subsys_host",
	  .flags = IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_PT_DIR, .name = "passthru_dir",
	  .flags = IN_CREATE | IN_DELETE },
	{ .type = TYPE_SUBSYS_PT_ATTR, .name = "passthru_attr", .flags = 0 },
	{ .type = TYPE_SUBSYS_NS_DIR, .name = "subsys_ns_dir",
	  .flags = IN_CREATE },
	{ .type = TYPE_SUBSYS_NS, .name = "subsys_ns",
	  .flags = IN_MODIFY | IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_NS_ATTR, .name = "subsys_attr", .flags = 0 },
};

struct dir_watcher {
	struct watcher_ctx *ctx;
	struct linked_list entry;
	enum watcher_type type;
	const char *type_name;
	int flags;
	int wd;
	char dirname[FILENAME_MAX];
};

static int get_flags(enum watcher_type type, const char **name)
{
	int i, flags = 0;

	for (i = 0; i < NUM_WATCHER_TYPES; i++) {
		if (watcher_flags[i].type == type) {
			flags = watcher_flags[i].flags;
			*name = watcher_flags[i].name;
			break;
		}
	}
	return flags;
}

static struct dir_watcher *add_watch(struct dir_watcher *watcher)
{
	struct dir_watcher *tmp;
	const char *p;

	INIT_LINKED_LIST(&watcher->entry);
	list_for_each_entry(tmp, &dir_watcher_list, entry) {
		if (tmp->type != watcher->type)
			continue;
		if (strcmp(tmp->dirname, watcher->dirname))
			continue;
		return tmp;
	}
	watcher->wd = inotify_add_watch(watcher->ctx->inotify_fd,
					watcher->dirname, watcher->flags);
	if (watcher->wd < 0) {
		fprintf(stderr,
			"failed to add inotify watch to '%s', error %d\n",
			watcher->dirname, errno);
		return watcher;
	}
	if (inotify_debug) {
		p = watcher->dirname + strlen(watcher->ctx->configfs) + 1;
		printf("add inotify watch %d type %s (%d) flags %d to %s\n",
		       watcher->wd, watcher->type_name, watcher->type,
		       watcher->flags, p);
	}
	list_add(&watcher->entry, &dir_watcher_list);
	return 0;
}

static int remove_watch(struct dir_watcher *watcher)
{
	int ret;
	const char *p;

	ret = inotify_rm_watch(watcher->ctx->inotify_fd, watcher->wd);
	if (ret < 0)
		fprintf(stderr, "Failed to remove inotify watch on '%s'\n",
			watcher->dirname);
	if (inotify_debug) {
		p = watcher->dirname + strlen(watcher->ctx->configfs) + 1;
		printf("remove inotify watch %d type %s (%d) from '%s'\n",
		       watcher->wd, watcher->type_name,
		       watcher->type, p);
	}
	list_del_init(&watcher->entry);
	return ret;
}

static struct dir_watcher *
allocate_watch(struct watcher_ctx *ctx, const char *dirname,
	       const char *filename, enum watcher_type type,
	       const char *type_name, int flags)
{
	struct dir_watcher *watcher, *tmp;

	watcher = malloc(sizeof(struct dir_watcher));
	if (!watcher) {
		fprintf(stderr, "Failed to allocate dirwatch\n");
		errno = ENOMEM;
		return NULL;
	}
	strcpy(watcher->dirname, dirname);
	strcat(watcher->dirname, "/");
	strcat(watcher->dirname, filename);
	watcher->type = type;
	watcher->type_name = type_name;
	watcher->ctx = ctx;
	watcher->flags = flags;
	tmp = add_watch(watcher);
	if (tmp) {
		if (tmp == watcher)
			free(watcher);
		errno = EAGAIN;
		watcher = NULL;
	}
	return watcher;
}

enum watcher_type next_type(enum watcher_type type, const char *file)
{
	enum watcher_type next_type = TYPE_UNKNOWN;

	if (!file)
		return next_type;

	switch (type) {
	case TYPE_ROOT:
		if (!strcmp(file, "hosts")) {
			next_type = TYPE_HOST_DIR;
		} else if (!strcmp(file, "ports")) {
			next_type = TYPE_PORT_DIR;
		} else {
			next_type = TYPE_SUBSYS_DIR;
		}
		break;
	case TYPE_HOST_DIR:
		next_type = TYPE_HOST;
		break;
	case TYPE_HOST:
		next_type = TYPE_HOST_ATTR;
		break;
	case TYPE_PORT_DIR:
		next_type = TYPE_PORT;
		break;
	case TYPE_PORT:
		if (!strcmp(file, "subsystems")) {
			next_type = TYPE_PORT_SUBSYS_DIR;
		} else if (!strcmp(file, "ana_groups")) {
			next_type = TYPE_PORT_ANA_DIR;
		} else if (!strcmp(file, "referrals")) {
			next_type = TYPE_PORT_REF_DIR;
		} else {
			next_type = TYPE_PORT_ATTR;
		}
		break;
	case TYPE_PORT_SUBSYS_DIR:
		next_type = TYPE_PORT_SUBSYS;
		break;
	case TYPE_PORT_ANA_DIR:
		next_type = TYPE_PORT_ANA;
		break;
	case TYPE_PORT_ANA:
		next_type = TYPE_PORT_ANA_ATTR;
		break;
	case TYPE_PORT_REF_DIR:
		next_type = TYPE_PORT_REF;
		break;
	case TYPE_SUBSYS_DIR:
		next_type = TYPE_SUBSYS;
		break;
	case TYPE_SUBSYS:
		if (!strcmp(file, "allowed_hosts")) {
			next_type = TYPE_SUBSYS_HOST_DIR;
		} else if (!strcmp(file, "namespaces")) {
			next_type = TYPE_SUBSYS_NS_DIR;
		} else if (!strcmp(file, "passthru")) {
			next_type = TYPE_SUBSYS_PT_DIR;
		} else {
			next_type = TYPE_SUBSYS_ATTR;
		}
		break;
	case TYPE_SUBSYS_HOST_DIR:
		next_type = TYPE_SUBSYS_HOST;
		break;
	case TYPE_SUBSYS_PT_DIR:
		next_type = TYPE_SUBSYS_PT_ATTR;
		break;
	case TYPE_SUBSYS_NS_DIR:
		next_type = TYPE_SUBSYS_NS;
		break;
	case TYPE_SUBSYS_NS:
		next_type = TYPE_SUBSYS_NS_ATTR;
		break;
	default:
		break;
	}
	return next_type;
}

static int read_attr(char *attr_path, char *value, size_t value_len)
{
	int fd, len;
	char *p;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -1;
	}
	len = read(fd, value, value_len);
	if (len < 0)
		memset(value, 0, value_len);
	else {
		p = &value[len - 1];
		if (*p == '\n')
			*p = '\0';
	}
	close(fd);
	return len;
}

static char *path_to_key(struct watcher_ctx *ctx, const char *path)
{
	const char *attr = path + strlen(ctx->configfs) + 1;
	char *key;
	int ret;

	if (!strncmp(attr, "ports/", 6)) {
		char *node_name = ctx->etcd->node_name;
		const char *suffix = attr + 6;

		if (!node_name)
			node_name = "localhost";
		ret = asprintf(&key, "%s/ports/%s:%s",
			       ctx->etcd->prefix, node_name, suffix);
	} else {
		ret = asprintf(&key, "%s/%s",
			       ctx->etcd->prefix, attr);
	}
	if (ret < 0)
		return NULL;
	return key;
}

static int update_value(struct watcher_ctx *ctx,
			const char *dirname, const char *name,
			enum watcher_type type, bool create)
{
	char *pathname, value[PATH_MAX + 1], *t, *key;
	int ret;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	if (type == TYPE_SUBSYS_HOST || type == TYPE_PORT_SUBSYS) {
		t = "link";
		ret = readlink(pathname, value, sizeof(value));
	} else if (type == TYPE_SUBSYS_NS &&
		   !strcmp(name, "device_path") &&
		   ctx->etcd->node_name) {
		char *tmp = strdup(value);

		t = "attr";
		/*
		 * Prefix the device path with the node name to
		 * indicate on which node the namespace resides.
		 */
		sprintf(value, "%s:%s", ctx->etcd->node_name, tmp);
		free(tmp);
	} else {
		t = "attr";
		ret = read_attr(pathname, value, sizeof(value));
	}
	key = path_to_key(ctx, pathname);
	if (!key) {
		free(pathname);
		return -ENOMEM;
	}
	if (inotify_debug)
		printf("%s: %s %s key %s value '%s'\n", __func__,
		       create ? "create" : "update", t, key, value);
	if (ret > 0) {
		if (create)
			ret = etcd_kv_new(ctx->etcd, key, value);
		else
			ret = etcd_kv_update(ctx->etcd, key, value);
		if (ret < 0)
			fprintf(stderr, "%s: %s key %s %s error %d\n",
				__func__, t, key,
				create ? "create" : "update", ret);
	} else {
		fprintf(stderr, "%s: %s %s value error %d\n",
			__func__, t, key, ret);
	}
	free(key);
	free(pathname);
	return ret;
}

static enum watcher_type
mark_file(struct watcher_ctx *ctx, const char *dirname,
	  const char *filename, enum watcher_type type,
	  bool isdir, bool create)
{
	enum watcher_type new_type;
	struct dir_watcher *wd;
	const char *type_name, *p;
	int flags = 0;

	new_type = next_type(type, filename);
	if (new_type == TYPE_UNKNOWN) {
		fprintf(stderr, "%s/%s: unknown next type for %d\n",
			dirname, filename, type);
		return new_type;
	}
	flags = get_flags(new_type, &type_name);
	if (flags > 0) {
		wd = allocate_watch(ctx, dirname, filename,
				    new_type, type_name, flags);
		if (!wd) {
			fprintf(stderr, "%s/%s: failed to allocate watcher\n",
				dirname, filename);
			return TYPE_UNKNOWN;
		}
		/* Insert 'addr_node' attribute */
		if (new_type == TYPE_PORT && ctx->etcd->node_name) {
			int ret;
			char *key;

			ret = asprintf(&key, "%s/ports/%s:%s/addr_node",
				       ctx->etcd->prefix,
				       ctx->etcd->node_name, filename);
			if (ret > 0) {
				if (inotify_debug)
					printf("%s: add key %s value '%s'\n",
					       __func__, key, ctx->etcd->node_name);
				etcd_kv_new(ctx->etcd, key,
					    ctx->etcd->node_name);
				free(key);
			}
			ret = asprintf(&key, "%s/ports/%s:%s/addr_origin",
				       ctx->etcd->prefix,
				       ctx->etcd->node_name, filename);
			if (ret > 0) {
				if (inotify_debug)
					printf("%s: add key %s value '%s'\n",
					       __func__, key, ctx->etcd->node_name);
				etcd_kv_new(ctx->etcd, key, "nvmet");
				free(key);
			}
		}
	} else {
		if (new_type == TYPE_UNKNOWN || type == TYPE_ROOT) {
			if (inotify_debug) {
				p = dirname + strlen(ctx->configfs) + 1;
				printf("skip inotify type %s (%d) flags %d on %s/%s\n",
				       type_name, new_type, flags, p, filename);
			}
		} else {
			update_value(ctx, dirname, filename, new_type, create);
		}
	}
	return new_type;
}

int mark_inotify(struct watcher_ctx *ctx, const char *dir,
		 const char *file, enum watcher_type type, bool create)
{
	char dirname[PATH_MAX + 1];
	enum watcher_type new_type;
	DIR *sd;
	struct dirent *se;

	if (inotify_debug)
		printf("%s: %s dir %s type %d file %s\n",
		       __func__, create ? "create" : "update", dir, type, file);

	strcpy(dirname, dir);
	if (file) {
		strcat(dirname, "/");
		strcat(dirname, file);
	}

	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		return -1;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (inotify_debug)
			printf("%s: checking %s %s\n",
			       __func__, dirname, se->d_name);
		new_type = mark_file(ctx, dirname, se->d_name, type,
				     se->d_type == DT_DIR, create);
		if (new_type == TYPE_UNKNOWN)
			continue;
		if (se->d_type == DT_DIR) {
			mark_inotify(ctx, dirname, se->d_name,
				     new_type, create);
		}
	}
	closedir(sd);
	return 0;
}

static void unmark_inotify(struct watcher_ctx *ctx, struct dir_watcher *self,
			   const char *dirname)
{
	struct dir_watcher *watcher, *tmp_watch;

	list_for_each_entry_safe(watcher, tmp_watch, &dir_watcher_list, entry) {
		if (self && watcher == self)
			continue;
		if (!strncmp(watcher->dirname, dirname, strlen(dirname))) {
			remove_watch(watcher);
			free(watcher);
		}
	}
}

static void
display_inotify_event(struct inotify_event *ev)
{
	if (!inotify_debug)
		return;
	printf("inotify wd = %d; ", ev->wd);
	if (ev->cookie > 0)
		printf("cookie = %4d; ", ev->cookie);

	printf("mask = ");

	if (ev->mask & IN_ISDIR)
		printf("IN_ISDIR ");

	if (ev->mask & IN_CREATE)
		printf("IN_CREATE ");

	if (ev->mask & IN_DELETE)
		printf("IN_DELETE ");

	if (ev->mask & IN_DELETE_SELF)
		printf("IN_DELETE_SELF ");

	if (ev->mask & IN_MODIFY)
		printf("IN_MODIFY ");

	if (ev->mask & IN_MOVE_SELF)
		printf("IN_MOVE_SELF ");
	if (ev->mask & IN_MOVED_FROM)
		printf("IN_MOVED_FROM ");
	if (ev->mask & IN_MOVED_TO)
		printf("IN_MOVED_TO ");

	if (ev->mask & IN_IGNORED)
		printf("IN_IGNORED ");
	if (ev->mask & IN_Q_OVERFLOW)
		printf("IN_Q_OVERFLOW ");
	if (ev->mask & IN_UNMOUNT)
		printf("IN_UNMOUNT ");

	if (ev->len > 0)
		printf("name = %s", ev->name);
	printf("\n");
}

int process_inotify_event(char *iev_buf, int iev_len)
{
	struct inotify_event *ev;
	struct dir_watcher *tmp_watcher, *watcher = NULL;
	char subdir[FILENAME_MAX + 1];
	int ev_len, ret;

	ev = (struct inotify_event *)iev_buf;
	display_inotify_event(ev);
	ev_len = sizeof(struct inotify_event) + ev->len;
	if (ev->mask & IN_IGNORED)
		return ev_len;

	list_for_each_entry(tmp_watcher, &dir_watcher_list, entry) {
		if (tmp_watcher->wd == ev->wd) {
			watcher = tmp_watcher;
			break;
		}
	}
	if (!watcher) {
		if (inotify_debug)
			printf("No watcher for wd %d\n", ev->wd);
		return ev_len;
	}
	if (ev->mask & IN_CREATE) {
		enum watcher_type new_type;

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (inotify_debug) {
			if (ev->mask & IN_ISDIR)
				printf("mkdir %s\n", subdir);
			else
				printf("link %s\n", subdir);
		}
		new_type = mark_file(watcher->ctx, watcher->dirname,
				     ev->name, watcher->type,
				     (ev->mask & IN_ISDIR), true);
		if (new_type != TYPE_UNKNOWN && (ev->mask & IN_ISDIR))
			mark_inotify(watcher->ctx, watcher->dirname,
				     ev->name, new_type, true);
	} else if (ev->mask & IN_DELETE_SELF) {
		if (inotify_debug)
			printf("rmdir %s type %d\n",
			       watcher->dirname, watcher->type);
		unmark_inotify(watcher->ctx, watcher, watcher->dirname);
	} else if (ev->mask & IN_DELETE) {
		char subdir[FILENAME_MAX + 1];
		char *key;

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (inotify_debug) {
			if (ev->mask & IN_ISDIR)
				printf("rmdir %s\n", subdir);
			else
				printf("unlink %s\n", subdir);
		}
		unmark_inotify(watcher->ctx, NULL, subdir);
		key = path_to_key(watcher->ctx, subdir);
		if (inotify_debug)
			printf("%s: delete key %s\n",
			       __func__, key);
		ret = etcd_kv_delete(watcher->ctx->etcd, key);
		if (ret)
			fprintf(stderr, "%s: delete key %s error %d\n",
				__func__, key, ret);
		free(key);
	} else if (ev->mask & IN_MODIFY) {
		int ret, ifd = watcher->ctx->inotify_fd;
		enum watcher_type new_type;

		if (inotify_debug)
			printf("write %s %s\n", watcher->dirname, ev->name);

		ret = inotify_rm_watch(ifd, watcher->wd);
		if (ret < 0) {
			fprintf(stderr,
				"failed to disable inotify watch on '%s'\n",
				watcher->dirname);
			return ev_len;
		}
		watcher->wd = -1;
		new_type = next_type(watcher->type, ev->name);
		update_value(watcher->ctx, watcher->dirname, ev->name,
			     new_type, false);
		watcher->wd = inotify_add_watch(ifd, watcher->dirname,
						watcher->flags);
		if (watcher->wd < 0) {
			fprintf(stderr,
				"cannot enable inotify watch on '%s'\n",
				watcher->dirname);
			remove_watch(watcher);
			free(watcher);
		}
	}
	return ev_len;
}

int start_inotify(struct watcher_ctx *ctx)
{
	int ret;

	ctx->inotify_fd = inotify_init();
	if (ctx->inotify_fd < 0) {
		fprintf(stderr, "inotify_init() failed, error %d\n", errno);
		return -errno;
	}

	ret = mark_inotify(ctx, ctx->configfs, NULL, TYPE_ROOT, true);
	if (ret < 0) {
		close(ctx->inotify_fd);
		ctx->inotify_fd = -1;
	}
	return ret;
}

void stop_inotify(struct watcher_ctx *ctx)
{
	struct dir_watcher *watcher, *tmp_watch;

	list_for_each_entry_safe(watcher, tmp_watch, &dir_watcher_list, entry) {
		remove_watch(watcher);
		free(watcher);
	}
	close(ctx->inotify_fd);
	ctx->inotify_fd = -1;
}

void *inotify_loop(void *arg)
{
	struct watcher_ctx *ctx = arg;
	fd_set rfd;
	struct timeval tmo;
	char event_buffer[INOTIFY_BUFFER_SIZE]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));

	while (!stopped) {
		int rlen, ret;
		char *iev_buf;

		ret = etcd_lease_keepalive(ctx->etcd);
		if (ret < 0) {
			fprintf(stderr,
				"failed to update lease, error %d\n", ret);
			break;
		}

		FD_ZERO(&rfd);
		FD_SET(ctx->inotify_fd, &rfd);
		tmo.tv_sec = ctx->etcd->ttl / 2;
		tmo.tv_usec = 0;
		ret = select(ctx->inotify_fd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "select returned %d", errno);
			break;
		}
		if (ret == 0) {
			/* Select timeout, refresh lease */
			continue;
		}
		if (!FD_ISSET(ctx->inotify_fd, &rfd)) {
			fprintf(stderr,
				"select returned for invalid fd");
			continue;
		}
		rlen = read(ctx->inotify_fd, event_buffer, INOTIFY_BUFFER_SIZE);
		if (rlen < 0) {
			fprintf(stderr, "error %d on reading inotify event",
				errno);
			continue;
		}
		for (iev_buf = event_buffer;
		     iev_buf < event_buffer + rlen; ) {
			int iev_len;

			iev_len = process_inotify_event(iev_buf,
							event_buffer + rlen - iev_buf);
			if (iev_len < 0) {
				fprintf(stderr, "Failed to process inotify\n");
				break;
			}
			iev_buf += iev_len;
		}
	}

	pthread_exit(NULL);
	return NULL;
}
