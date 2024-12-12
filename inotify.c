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

#define INOTIFY_BUFFER_SIZE 4096

int debug_inotify = 1;
LINKED_LIST(dir_watcher_list);

int debug_inotify;

static int inotify_fd;
static pthread_t inotify_thread;

enum watcher_type {
	TYPE_ROOT,
	TYPE_HOST_DIR,		/* hosts */
	TYPE_HOST,		/* hosts/<host> */
	TYPE_HOST_ATTR,		/* hosts/<host>/<attr> */
	TYPE_PORT_DIR,		/* ports */
	TYPE_PORT,		/* ports/<port> */
	TYPE_PORT_ATTR,		/* ports/<port>/<attr> */
	TYPE_PORT_ANA_DIR,	/* ports/<port>/ana_groups */
	TYPE_PORT_ANA,		/* ports/<port>/ana_groups/<anagrp> */
	TYPE_PORT_SUBSYS_DIR,	/* ports/<port>/subsystems */
	TYPE_PORT_SUBSYS,	/* ports/<port>/subsystems/<subsys> */
	TYPE_SUBSYS_DIR,	/* subsystems */
	TYPE_SUBSYS,		/* subsystems/<subsys> */
	TYPE_SUBSYS_ATTR,	/* subsystems/<subsys>/<attr> */
	TYPE_SUBSYS_HOST_DIR,	/* subsystems/<subsys>/allowed_hosts */
	TYPE_SUBSYS_HOST,	/* subsystems/<subsys>/allowed_hosts/<host> */
	TYPE_SUBSYS_NS_DIR,	/* subsystems/<subsys>/namespaces */
	TYPE_SUBSYS_NS,		/* subsystems/<subsys>/namespaces/<nsid> */
};

struct dir_watcher {
	struct linked_list entry;
	enum watcher_type type;
	int wd;
	char dirname[FILENAME_MAX];
};

/* TYPE_PORT */
struct port_wather {
	struct dir_watcher watcher;
	struct nofuse_port *port;
};

/* TYPE_PORT_SUBSYS */
struct port_subsys_watcher {
	struct dir_watcher watcher;
	struct nofuse_port *port;
	char subsysnqn[256];
};

/* TYPE_SUBSYS_HOST */
struct subsys_host_watcher {
	struct dir_watcher watcher;
	char subsysnqn[256];
	char hostnqn[256];
};

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
	watcher->wd = inotify_add_watch(inotify_fd, watcher->dirname,
					flags);
	if (watcher->wd < 0) {
		fprintf(stderr,
			"failed to add inotify watch to '%s', error %d\n",
			watcher->dirname, errno);
		return watcher;
	}
	if (debug_inotify)
		printf("add inotify watch %d type %d to %s\n",
		       watcher->wd, watcher->type, watcher->dirname);
	list_add(&watcher->entry, &dir_watcher_list);
	return 0;
}

static int remove_watch(struct dir_watcher *watcher)
{
	int ret;

	ret = inotify_rm_watch(inotify_fd, watcher->wd);
	if (ret < 0)
		fprintf(stderr, "Failed to remove inotify watch on '%s'\n",
			watcher->dirname);
	if (debug_inotify)
		printf("remove inotify watch %d type %d from '%s'\n",
		       watcher->wd, watcher->type, watcher->dirname);
	list_del_init(&watcher->entry);
	return ret;
}

static int watch_directory(char *dirname, enum watcher_type type, int flags)
{
	struct dir_watcher *watcher, *tmp;

	watcher = malloc(sizeof(struct dir_watcher));
	if (!watcher) {
		fprintf(stderr, "Failed to allocate dirwatch\n");
		return -1;
	}
	strcpy(watcher->dirname, dirname);
	watcher->type = type;
	tmp = add_watch(watcher, flags);
	if (tmp) {
		if (tmp == watcher)
			free(watcher);
		return -1;
	}
 	return 0;
}

#if 0
static int read_attr(char *attr_path, char *value)
{
	int fd, len;
	char *p;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -1;
	}
	len = read(fd, value, 256);
	if (len < 0)
		memset(value, 0, 256);
	else {
		p = &value[len - 1];
		if (*p == '\n')
			*p = '\0';
	}
	close(fd);
	return len;
}

static void watch_port_attr(char *port_dir, char *attr)
{
	char watch_dir[PATH_MAX + 1], value[256], *port, *eptr = NULL;
	unsigned long portid;
	int ret;

	port = strrchr(port_dir, '/');
	if (!port)
		return;
	port++;
	portid = strtoul(port, &eptr, 10);
	if (portid == ULONG_MAX || port == eptr)
		return;
	
	strcpy(watch_dir, port_dir);
	strcat(watch_dir, "/");
	strcat(watch_dir, attr);

	ret = read_attr(watch_dir, value);
	if (ret < 0)
		return;
	etcd_set_port_attr(portid, attr, value);

	watch_directory(watch_dir, TYPE_PORT_ATTR, IN_MODIFY);
}

static void watch_port_subsys(char *port_subsys_dir, char *subsysnqn)
{
	char watch_dir[PATH_MAX + 1], *p, *port, *eptr = NULL;
	unsigned long portid;

	strcpy(watch_dir, port_subsys_dir);
	strcat(watch_dir, "/");
	strcat(watch_dir, subsysnqn);
	watch_directory(watch_dir, TYPE_PORT_SUBSYS, IN_DELETE_SELF);

	strcpy(watch_dir, port_subsys_dir);
	p = strrchr(watch_dir, '/');
	if (p)
		*p = '\0';
	port = strrchr(watch_dir, '/');
	if (!port)
		return;
	portid = strtoul(port, &eptr, 10);
	if (portid == ULONG_MAX || port == eptr)
		return;
	etcd_add_subsys_port(subsysnqn, portid);
}
	
static void watch_port(char *ports_dir, char *port)
{
	char subsys_dir[PATH_MAX + 1], *eptr = NULL;
	DIR *sd;
	struct dirent *se;
	unsigned long portid;

	portid = strtoul(port, &eptr, 10);
	if (portid == ULONG_MAX || port == eptr)
		return;

	strcpy(subsys_dir, ports_dir);
	strcat(subsys_dir, "/");
	strcat(subsys_dir, port);
	watch_directory(subsys_dir, TYPE_PORT, IN_DELETE_SELF);

	add_port(portid, NULL, 0);

	sd = opendir(subsys_dir);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", subsys_dir);
		return;
	}
	while ((se = readdir(sd))) {
		if (!strncmp(se->d_name, "addr_", 5)) {
			watch_port_attr(subsys_dir, se->d_name);
		}
	}

	strcat(subsys_dir, "/subsystems");
	watch_directory(subsys_dir, TYPE_PORT_SUBSYS_DIR,
			IN_CREATE | IN_DELETE | IN_DELETE_SELF);

	sd = opendir(subsys_dir);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", subsys_dir);
		return;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		watch_port_subsys(subsys_dir, se->d_name);
	}
	closedir(sd);
}

static void watch_subsys_hosts(char *hosts_dir, char *hostnqn)
{
	char watch_dir[PATH_MAX + 1], *p, *subsysnqn;

	strcpy(watch_dir, hosts_dir);
	strcat(watch_dir, "/");
	strcat(watch_dir, hostnqn);

	watch_directory(watch_dir, TYPE_SUBSYS_HOST, IN_DELETE_SELF);

	strcpy(watch_dir, hosts_dir);
	p = strrchr(watch_dir, '/');
	if (p)
		*p = '\0';
	subsysnqn = strrchr(watch_dir, '/');
	if (subsysnqn)
		subsysnqn++;
	etcd_add_host_subsys(hostnqn, subsysnqn);
}

static void watch_subsys_allow_any(char *subsys_dir, char *subnqn)
{
	char watch_dir[PATH_MAX + 1];
	char allow_any[256];
	int ret;

	sprintf(watch_dir, "%s/%s/attr_allow_any_host",
		subsys_dir, subnqn);

	watch_directory(watch_dir, TYPE_SUBSYS, IN_MODIFY);

	ret = read_attr(watch_dir, allow_any);
	if (ret < 0)
		return;
	etcd_set_subsys_attr(subnqn, "attr_allow_any", allow_any);
}

static void watch_subsys(char *subsys_dir, char *subsysnqn)
{
	char hosts_dir[PATH_MAX + 1];
	DIR *hd;
	struct dirent *he;
	int ret;

	ret = add_subsys(subsysnqn, NVME_NQN_NVM);
	if (ret < 0) {
		fprintf(stderr, "failed to add subsys %s\n",
			subsysnqn);
		return;
	}
	watch_subsys_allow_any(subsys_dir, subsysnqn);

	sprintf(hosts_dir, "%s/%s/allowed_hosts",
		subsys_dir, subsysnqn);
	watch_directory(hosts_dir, TYPE_SUBSYS_HOST_DIR,
			IN_CREATE | IN_DELETE | IN_DELETE_SELF);
	hd = opendir(hosts_dir);
	if (!hd) {
		fprintf(stderr, "Cannot open %s\n", hosts_dir);
		return;
	}
	while ((he = readdir(hd))) {
		if (!strcmp(he->d_name, ".") ||
		    !strcmp(he->d_name, ".."))
			continue;
		watch_subsys_hosts(hosts_dir, he->d_name);
	}
	closedir(hd);
}
#endif

enum watcher_type next_type(enum watcher_type type, const char *file)
{
	enum watcher_type next_type;

	if (!file)
		return 0;

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
	default:
		break;
	}
	return next_type;
}

int watch_dir(const char *dir, enum watcher_type type, const char *file)
{
	char dirname[PATH_MAX + 1];
	DIR *sd;
	struct dirent *se;

	strcpy(dirname, dir);
	strcat(dirname, "/");
	strcat(dirname, file);
	watch_directory(dirname, type,
			IN_CREATE | IN_DELETE_SELF);

	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		return -1;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		type = next_type(type, se->d_name);
		if (se->d_type == DT_DIR)
			watch_dir(dirname, type, se->d_name);
		else
			watch_directory(dirname, type, IN_MODIFY);

	}
	closedir(sd);
	return 0;
}

static void
display_inotify_event(struct inotify_event *ev)
{
	if (!debug_inotify)
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
		if (debug_inotify)
			printf("No watcher for wd %d\n", ev->wd);
		return ev_len;
	}
	if (ev->mask & IN_CREATE) {
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (debug_inotify) {
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
		if (debug_inotify)
			printf("rmdir %s type %d\n",
			       watcher->dirname, watcher->type);

		/* Watcher is already removed */
		list_del_init(&watcher->entry);
		free(watcher);
	} else if (ev->mask & IN_DELETE) {
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
		if (debug_inotify) {
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
		if (debug_inotify)
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

void cleanup_watcher(void *arg)
{
	struct dir_watcher *watcher, *tmp_watch;

    	list_for_each_entry_safe(watcher, tmp_watch, &dir_watcher_list, entry) {
		remove_watch(watcher);
		free(watcher);
	}
}

static void inotify_loop(void)
{
	fd_set rfd;
	struct timeval tmo;
	int ttl = 10;
	char event_buffer[INOTIFY_BUFFER_SIZE]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));

	for (;;) {
		int rlen, ret;
		char *iev_buf;

		FD_ZERO(&rfd);
		FD_SET(inotify_fd, &rfd);
		tmo.tv_sec = ttl / 5;
		tmo.tv_usec = 0;
		ret = select(inotify_fd + 1, &rfd, NULL, NULL, &tmo);
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
		if (!FD_ISSET(inotify_fd, &rfd)) {
			fprintf(stderr,
				"select returned for invalid fd");
			continue;
		}
		rlen = read(inotify_fd, event_buffer, INOTIFY_BUFFER_SIZE);
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
}

static void cleanup_inotify(void *arg)
{
	close(inotify_fd);
}

static void *run_inotify(void *arg)
{
	sigset_t set;

	inotify_fd = inotify_init();
	if (inotify_fd < 0) {
		fprintf(stderr, "Could not setup inotify, error %d\n", errno);
		pthread_exit(NULL);
		return NULL;
	}
	pthread_cleanup_push(cleanup_inotify, NULL)

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	watch_dir("/sys/kernel/config", TYPE_ROOT, "nvmet");

	pthread_cleanup_push(cleanup_watcher, NULL);
	
	inotify_loop();

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(NULL);
	return NULL;
}

int start_inotify(void)
{
	pthread_attr_t pthread_attr;
	int ret;

	if (inotify_thread)
		return 0;

	printf("%s: starting", __func__);
	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&inotify_thread, &pthread_attr,
			     run_inotify, NULL);
	if (ret) {
		inotify_thread = 0;
		fprintf(stderr, "failed to start inotify thread");
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

void stop_inotify(void)
{
	if (!inotify_thread)
		return;

	pthread_cancel(inotify_thread);
	pthread_join(inotify_thread, NULL);
	inotify_thread = 0;
}
