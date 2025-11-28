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
#include <ctype.h>
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
#include "configfs.h"
#include "etcd_client.h"
#include "etcd_backend.h"
#include "nvmetd.h"

#define INOTIFY_BUFFER_SIZE 4096

LINKED_LIST(dir_watcher_list);

struct dir_watcher {
	struct watcher_ctx *ctx;
	struct linked_list entry;
	int flags;
	int wd;
	char dirname[FILENAME_MAX];
};

static struct dir_watcher *add_watch(struct dir_watcher *watcher)
{
	struct dir_watcher *tmp;
	const char *p;

	INIT_LINKED_LIST(&watcher->entry);
	list_for_each_entry(tmp, &dir_watcher_list, entry) {
		if (strcmp(tmp->dirname, watcher->dirname))
			continue;
		return tmp;
	}
	watcher->wd = inotify_add_watch(watcher->ctx->inotify_fd,
					watcher->dirname, watcher->flags);
	if (watcher->wd < 0) {
		fprintf(stderr,
			"%s: failed to add inotify watch to '%s', error %d\n",
			__func__, watcher->dirname, errno);
		return watcher;
	}
	if (inotify_debug) {
		p = watcher->dirname + strlen(watcher->ctx->etcd->configfs) + 1;
		printf("%s: add inotify watch %d flags %d to %s\n",
		       __func__, watcher->wd, watcher->flags, p);
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
		p = watcher->dirname + strlen(watcher->ctx->etcd->configfs) + 1;
		printf("remove inotify watch %d from '%s'\n",
		       watcher->wd, p);
	}
	list_del_init(&watcher->entry);
	return ret;
}

static struct dir_watcher *
allocate_watch(struct watcher_ctx *ctx, const char *dirname,
	       const char *filename, unsigned int flags)
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

static char *path_to_key(struct watcher_ctx *ctx, const char *path)
{
	const char *attr = path + strlen(ctx->etcd->configfs) + 1;
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
			const char *dirname, const char *name)
{
	struct stat st;
	char *pathname, value[1024], old[1024], *key;
	int ret;

	memset(value, 0, sizeof(value));
	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return ret;
	ret = lstat(pathname, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: attr %s error %d\n",
			__func__, pathname, errno);
		free(pathname);
		return -errno;
	}
	if (!(st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
		printf("%s: skip attr %s, not readable\n",
		       __func__, pathname);
		free(pathname);
		return 0;
	}
	if ((st.st_mode & S_IFMT) == S_IFLNK) {
		ret = readlink(pathname, value, sizeof(value));
	} else if ((st.st_mode & S_IFMT) == S_IFREG) {
		if (!strcmp(name, "addr_origin")) {
			printf("%s: skip attr %s, internal only\n",
			       __func__, pathname);
			free(pathname);
			return 0;
		}
		ret = read_attr(pathname, value, sizeof(value));
		if (ret > 0 && strlen(value) && !strcmp(name, "device_path")) {
			char *node_name = ctx->etcd->node_name;
			char *tmp = strdup(value);

			if (!node_name)
				node_name = "localhost";

			/*
			 * Prefix the device path with the node name to
			 * indicate on which node the namespace resides.
			 */
			sprintf(value, "%s:%s", ctx->etcd->node_name, tmp);
			free(tmp);
		}
	} else {
		if ((st.st_mode & S_IFMT) != S_IFDIR)
			fprintf(stderr, "%s: skip unhandled attr %s mode %x\n",
				__func__, pathname, (st.st_mode & S_IFMT));
		free(pathname);
		return 0;
	}
	key = path_to_key(ctx, pathname);
	if (!key) {
		free(pathname);
		return -ENOMEM;
	}
	if (ret < 0) {
		fprintf(stderr, "%s: %s value error %d\n",
			__func__, key, ret);
		goto out_free;
	}

	memset(old, 0, sizeof(old));
	ret = etcd_kv_get(ctx->etcd, key, old);
	if (ret < 0) {
		if (ret != -ENOENT) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
			goto out_free;
		}
		if (inotify_debug)
			printf("%s: upload key %s value '%s'\n", __func__,
			       key, value);

		ret = etcd_kv_store(ctx->etcd, key, value);
		if (ret < 0) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
		}
	} else if (strcmp(old, value)) {
		if (inotify_debug)
			printf("%s: update key %s value '%s'\n", __func__,
			       key, value);

		ret = etcd_kv_update(ctx->etcd, key, value);
		if (ret < 0)
			fprintf(stderr, "%s: key %s update error %d\n",
				__func__, key, ret);
	}
out_free:
	free(key);
	free(pathname);
	return ret;
}

static int mark_file(struct watcher_ctx *ctx, const char *dirname,
		     const char *filename, unsigned int type)
{
	struct dir_watcher *wd;
	int flags = 0, ret = 0;

	switch (type) {
	case DT_DIR:
		flags = IN_CREATE | IN_DELETE | IN_MODIFY;
		break;
	case DT_LNK:
		flags = IN_DELETE_SELF;
		break;
	case DT_REG:
		flags = 0;
		break;
	default:
		fprintf(stderr, "%s/%s: unknown type %d\n",
			dirname, filename, type);
		return -EINVAL;
	}
	if (flags) {
		wd = allocate_watch(ctx, dirname, filename, flags);
		if (!wd) {
			fprintf(stderr, "%s/%s: failed to allocate watcher\n",
				dirname, filename);
			return -EINVAL;
		}
	}
	ret = update_value(ctx, dirname, filename);
	return ret;
}

int mark_inotify(struct watcher_ctx *ctx, const char *dir,
		 const char *file)
{
	char *dirname;
	DIR *sd;
	struct dirent *se;
	int ret;

	if (file) {
		ret = asprintf(&dirname, "%s/%s", dir, file);
		if (ret < 0)
			return -ENOMEM;
	} else {
		dirname = (char *)dir;
	}
	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		if (dirname != dir)
			free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (inotify_debug) {
			char *type_name;

			if (se->d_type == DT_DIR)
				type_name = "dir";
			else if (se->d_type == DT_LNK)
				type_name = "link";
			else if (se->d_type == DT_REG)
				type_name = "file";
			else
				type_name = "unknown";
			printf("%s: checking %s %s %s\n",
			       __func__, type_name, dirname, se->d_name);
		}
		if (!strcmp(se->d_name, "passthru"))
			continue;

		ret = mark_file(ctx, dirname, se->d_name, se->d_type);
		if (ret < 0)
			break;

		if (se->d_type == DT_DIR) {
			ret = mark_inotify(ctx, dirname, se->d_name);
			if (ret < 0)
				break;
		}
	}
	closedir(sd);
	if (dirname != dir)
		free(dirname);
	return ret;
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
		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (inotify_debug) {
			if (ev->mask & IN_ISDIR)
				printf("mkdir %s\n", subdir);
			else
				printf("link %s\n", subdir);
		}
		ret = mark_file(watcher->ctx, watcher->dirname, ev->name,
				(ev->mask & IN_ISDIR) ? DT_DIR : DT_LNK);
		if (ev->mask & IN_ISDIR)
			mark_inotify(watcher->ctx, watcher->dirname,
				     ev->name);
	} else if (ev->mask & IN_DELETE_SELF) {
		if (inotify_debug)
			printf("unlink %s\n", watcher->dirname);
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
		if (inotify_debug)
			printf("write %s %s\n", watcher->dirname, ev->name);
		update_value(watcher->ctx, watcher->dirname, ev->name);
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

	ret = mark_inotify(ctx, ctx->etcd->configfs, NULL);
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
