#ifndef _NVMETD_H
#define _NVMETD_H

extern bool inotify_debug;

struct watcher_ctx {
	struct etcd_ctx *etcd;
	int path_fd;
	int inotify_fd;
};

void *inotify_loop(void *arg);
int start_inotify(struct watcher_ctx *ctx);
void stop_inotify(struct watcher_ctx *ctx);

#endif /* _NVMETD_H */
