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

int debug_inotify = 1;
LINKED_LIST(dir_watcher_list);

#define NUM_WATCHER_TYPES 21

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
	TYPE_PORT_SUBSYS_DIR,	/* ports/<port>/subsystems */
	TYPE_PORT_SUBSYS,	/* ports/<port>/subsystems/<subsys> */
	TYPE_SUBSYS_DIR,	/* subsystems */
	TYPE_SUBSYS,		/* subsystems/<subsys> */
	TYPE_SUBSYS_ATTR,	/* subsystems/<subsys>/<attr> */
	TYPE_SUBSYS_HOST_DIR,	/* subsystems/<subsys>/allowed_hosts */
	TYPE_SUBSYS_HOST,	/* subsystems/<subsys>/allowed_hosts/<host> */
	TYPE_SUBSYS_NS_DIR,	/* subsystems/<subsys>/namespaces */
	TYPE_SUBSYS_NS,		/* subsystems/<subsys>/namespaces/<nsid> */
	TYPE_SUBSYS_NS_ATTR	/* subsystems/<subsys>/namespaces/<nsid>/<attr> */
};

struct watcher_flags_t {
	enum watcher_type type;
	int flags;
};

struct watcher_flags_t watcher_flags[NUM_WATCHER_TYPES] = {
	{ .type = TYPE_UNKNOWN, .flags = 0 },
	{ .type = TYPE_ROOT, .flags = 0 },
	{ .type = TYPE_HOST_DIR, .flags = IN_CREATE },
	{ .type = TYPE_HOST, .flags = IN_DELETE_SELF },
	{ .type = TYPE_HOST_ATTR, .flags = IN_MODIFY },
	{ .type = TYPE_PORT_DIR, .flags = IN_CREATE },
	{ .type = TYPE_PORT, .flags = IN_DELETE_SELF },
	{ .type = TYPE_PORT_ATTR, .flags = IN_MODIFY },
	{ .type = TYPE_PORT_ANA_DIR, .flags = IN_CREATE },
	{ .type = TYPE_PORT_ANA, .flags = IN_DELETE_SELF },
	{ .type = TYPE_PORT_ANA_ATTR, .flags = IN_MODIFY },
	{ .type = TYPE_PORT_SUBSYS_DIR, .flags = IN_CREATE },
	{ .type = TYPE_PORT_SUBSYS, .flags = IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_DIR, .flags = IN_CREATE },
	{ .type = TYPE_SUBSYS, .flags = IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_ATTR, .flags = IN_MODIFY },
	{ .type = TYPE_SUBSYS_HOST_DIR, .flags = IN_CREATE },
	{ .type = TYPE_SUBSYS_HOST, .flags = IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_NS_DIR, .flags = IN_CREATE },
	{ .type = TYPE_SUBSYS_NS, .flags = IN_DELETE_SELF },
	{ .type = TYPE_SUBSYS_NS_ATTR, .flags = IN_MODIFY },
};

struct dir_watcher {
	struct watcher_ctx *ctx;
	struct linked_list entry;
	enum watcher_type type;
	int wd;
	char dirname[FILENAME_MAX];
};

static int get_flags(enum watcher_type type)
{
	int i, flags = 0;

	for (i = 0; i < NUM_WATCHER_TYPES; i++) {
		if (watcher_flags[i].type == type) {
			flags = watcher_flags[i].flags;
			break;
		}
	}
	return flags;
}

static struct dir_watcher *add_watch(struct dir_watcher *watcher, int flags)
{
	struct dir_watcher *tmp;

	INIT_LINKED_LIST(&watcher->entry);
	list_for_each_entry(tmp, &dir_watcher_list, entry) {
		if (tmp->type != watcher->type)
			continue;
		if (strcmp(tmp->dirname, watcher->dirname))
			continue;
		return tmp;
	}
	watcher->wd = inotify_add_watch(watcher->ctx->inotify_fd,
					watcher->dirname, flags);
	if (watcher->wd < 0) {
		fprintf(stderr,
			"failed to add inotify watch to '%s', error %d\n",
			watcher->dirname, errno);
		return watcher;
	}
	if (inotify_debug)
		printf("add inotify watch %d type %d to %s\n",
		       watcher->wd, watcher->type, watcher->dirname);
	list_add(&watcher->entry, &dir_watcher_list);
	return 0;
}

static int remove_watch(struct dir_watcher *watcher)
{
	int ret;

	ret = inotify_rm_watch(watcher->ctx->inotify_fd, watcher->wd);
	if (ret < 0)
		fprintf(stderr, "Failed to remove inotify watch on '%s'\n",
			watcher->dirname);
	if (inotify_debug)
		printf("remove inotify watch %d type %d from '%s'\n",
		       watcher->wd, watcher->type, watcher->dirname);
	list_del_init(&watcher->entry);
	return ret;
}

static int allocate_watch(struct watcher_ctx *ctx, char *dirname,
			  char *filename, enum watcher_type type, int flags)
{
	struct dir_watcher *watcher, *tmp;

	watcher = malloc(sizeof(struct dir_watcher));
	if (!watcher) {
		fprintf(stderr, "Failed to allocate dirwatch\n");
		return -ENOMEM;
	}
	strcpy(watcher->dirname, dirname);
	strcat(watcher->dirname, "/");
	strcat(watcher->dirname, filename);
	watcher->type = type;
	watcher->ctx = ctx;
	tmp = add_watch(watcher, flags);
	if (tmp) {
		if (tmp == watcher)
			free(watcher);
		return -EAGAIN;
	}
 	return 0;
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
	case TYPE_SUBSYS_DIR:
		next_type = TYPE_SUBSYS;
		break;
	case TYPE_SUBSYS:
		if (!strcmp(file, "allowed_hosts")) {
			next_type = TYPE_SUBSYS_HOST_DIR;
		} else if (!strcmp(file, "namespaces")) {
			next_type = TYPE_SUBSYS_NS_DIR;
		} else {
			next_type = TYPE_SUBSYS_ATTR;
		}
		break;
	case TYPE_SUBSYS_HOST_DIR:
		next_type = TYPE_SUBSYS_HOST;
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

int mark_inotify(struct watcher_ctx *ctx, const char *dir,
		 enum watcher_type type, const char *file)
{
	char dirname[PATH_MAX + 1];
	DIR *sd;
	struct dirent *se;
	int flags = 0, new_type;

	if (inotify_debug)
		printf("%s: dir %s type %d file %s\n",
		       __func__, dir, type, file);

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
		new_type = next_type(type, se->d_name);
		if (new_type == TYPE_UNKNOWN) {
			fprintf(stderr, "%s/%s: unknown next type for %d\n",
				dirname, se->d_name, type);
			continue;
		}
		flags = get_flags(new_type);
		printf("%s: checking dir %s file %s flags %d\n",
		       __func__, dirname, se->d_name, flags);
		if (flags > 0)
			allocate_watch(ctx, dirname, se->d_name,
				       new_type, flags);
		if (se->d_type == DT_DIR) {
			mark_inotify(ctx, dirname, new_type, se->d_name);
		}
	}
	closedir(sd);
	return 0;
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
	int ev_len;

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
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (inotify_debug) {
			if (ev->mask & IN_ISDIR)
				printf("mkdir %s\n", subdir);
			else
				printf("link %s\n", subdir);
		}
		switch(watcher->type) {
		default:
			fprintf(stderr, "Unhandled create type %d\n",
				watcher->type);
			break;
		}
	} else if (ev->mask & IN_DELETE_SELF) {
		if (inotify_debug)
			printf("rmdir %s type %d\n",
			       watcher->dirname, watcher->type);

		/* Watcher is already removed */
		list_del_init(&watcher->entry);
		free(watcher);
	} else if (ev->mask & IN_DELETE) {
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (inotify_debug) {
			if (ev->mask & IN_ISDIR)
				printf("rmdir %s\n", subdir);
			else
				printf("unlink %s\n", subdir);
		}
		list_for_each_entry(tmp_watcher, &dir_watcher_list, entry) {
			if (strcmp(tmp_watcher->dirname, subdir))
				continue;
			watcher = tmp_watcher;
		}
		if (watcher) {
			remove_watch(watcher);
			switch(watcher->type) {
			default:
				fprintf(stderr, "Unhandled delete type %d\n",
					watcher->type);
				free(watcher);
				break;
			}
		}
	} else if (ev->mask & IN_MODIFY) {
		if (inotify_debug)
			printf("write %s %s\n", watcher->dirname, ev->name);

		switch (watcher->type) {
		default:
			fprintf(stderr, "unhandled modify type %d\n",
				watcher->type);
			free(watcher);
			break;
		}
	}
	return ev_len;
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

int start_inotify(struct watcher_ctx *ctx)
{
	ctx->inotify_fd = inotify_init();
	if (ctx->inotify_fd < 0) {
		fprintf(stderr, "inotify_init() failed, error %d\n", errno);
		return -errno;
	}

	return mark_inotify(ctx, ctx->pathname, TYPE_ROOT, NULL);
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
