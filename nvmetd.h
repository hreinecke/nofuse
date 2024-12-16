#ifndef _NVMETD_H
#define _NVMETD_H

extern bool inotify_debug;

struct watcher_ctx {
	pthread_mutex_t etcd_mutex;
	struct etcd_ctx *etcd;
	char *pathname;
	int path_fd;
	int inotify_fd;
};

void *inotify_loop(void *arg);

#endif /* _NVMETD_H */
