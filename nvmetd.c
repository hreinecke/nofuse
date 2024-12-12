/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nvmetd.c
 * Fanotify watcher for nvmet configfs
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>

int stopped = 0;
sigset_t mask;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait = PTHREAD_COND_INITIALIZER;

struct watcher_ctx {
	char *pathname;
	int fanotify_fd;
};

static void *signal_handler(void *arg)
{
	int ret, signo;

	for (;;) {
		ret = sigwait(&mask, &signo);
		if (ret != 0) {
			fprintf(stderr, "sigwait failed with %d\n", ret);
			break;
		}
		printf("signal %d, terminating\n", signo);
		pthread_mutex_lock(&lock);
		stopped = 1;
		pthread_mutex_unlock(&lock);
		pthread_cond_signal(&wait);
		return NULL;
	}
	pthread_exit(NULL);
	return NULL;
}

static int get_fname(int fd, char *fname)
{
	int len;
	char buf[FILENAME_MAX];

	sprintf(buf, "/proc/self/fd/%d", fd); /* link to local path name */
	len = readlink(buf, fname, FILENAME_MAX-1);
	if (len <= 0) {
		fname[0] = '\0';
	} else {
		fname[len] = '\0';
	}
	return len;
}

static void *watch_fanotify(void * arg)
{
	struct watcher_ctx *ctx = arg;
	fd_set rfd;
	struct timeval tmo;
	char buf[4096];

	while (!stopped) {
		struct fanotify_event_metadata *fa;
		struct stat st;
		char pathname[PATH_MAX];
		int rlen, ret;

		FD_ZERO(&rfd);
		FD_SET(ctx->fanotify_fd, &rfd);
		tmo.tv_sec = 5;
		tmo.tv_usec = 0;
		ret = select(ctx->fanotify_fd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "select returned %d\n", errno);
			break;
		}
		if (ret == 0) {
			printf("select timeout\n");
			continue;
		}
		if (!FD_ISSET(ctx->fanotify_fd, &rfd)) {
			fprintf(stderr, "select returned for invalid fd\n");
			continue;
		}
		rlen = read(ctx->fanotify_fd, buf, sizeof(buf));
		if (rlen < 0) {
			fprintf(stderr,
				"error %d on reading fanotify event\n", errno);
			continue;
		}

		fa = (struct fanotify_event_metadata *)&buf;
		for (; FAN_EVENT_OK(fa, rlen); FAN_EVENT_NEXT(fa, rlen)) {
			struct fanotify_response resp;

			if (fstat(fa->fd, &st) < 0) {
				fprintf(stderr,
					"stat() failed, error %d\n", errno);
				continue;
			}
			resp.fd = fa->fd;
			resp.fd = FAN_DENY;

			if ((st.st_mode & S_IFMT) == S_IFDIR) {
				fprintf(stderr, "directory, allow access\n");
				resp.response = FAN_ALLOW;
			}
			if (get_fname(fa->fd, pathname) < 0) {
				fprintf(stderr,
					"cannot retrieve filename, allow access\n");
				resp.response = FAN_ALLOW;
			}

			printf("fanotify event: mask 0x%02lX, fd %d (%s), pid %d\n",
			       (unsigned long) fa->mask, fa->fd,
			       pathname, fa->pid);
			if (fa->pid == getpid()) {
				/* Avoid deadlocking */
				printf("Identical PID, allowing access\n");
				resp.response = FAN_ALLOW;
			}

			if (write(ctx->fanotify_fd, &resp, sizeof(resp)) < 0) {
				fprintf(stderr, "failed write response, error %d\n",
					errno);
			}
		}
	}
	if (!stopped) {
		pthread_mutex_lock(&lock);
		stopped = 1;
		pthread_mutex_unlock(&lock);
		pthread_cond_signal(&wait);
	}
	pthread_exit(NULL);
	return NULL;
}

int monitor_configfs(struct watcher_ctx *ctx)
{
	int ret;

	ret = fanotify_mark(ctx->fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			    FAN_OPEN_PERM|FAN_ACCESS_PERM|FAN_ONDIR,
			    AT_FDCWD, ctx->pathname);
	if (ret < 0) {
		fprintf(stderr, "failed to add fanotify mark "
			"to %s, error %d\n", ctx->pathname, errno);
		ret = -errno;
	}
	return ret;
}

int main(int argc, char **argv)
{
	static pthread_t watcher_thr, signal_thr;
	sigset_t oldmask;
	struct watcher_ctx *ctx;
	int ret = 0;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		exit(1);

	memset(ctx, 0, sizeof(*ctx));
	ctx->pathname = strdup("/sys/kernel/config/nvmet");

	ctx->fanotify_fd = fanotify_init(FAN_CLASS_PRE_CONTENT, O_RDWR);
	if (ctx->fanotify_fd < 0) {
		fprintf(stderr, "fanotify_init() failed, error %d\n", errno);
		free(ctx->pathname);
		free(ctx);
		exit(1);
	}

	ret = monitor_configfs(ctx);
	if (ret < 0)
		goto out_free;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	ret = pthread_create(&signal_thr, NULL, signal_handler, 0);
	if (ret) {
		fprintf(stderr, "cannot start signal handler\n");
		goto out_restore;
	}

	ret = pthread_create(&watcher_thr, NULL, watch_fanotify, ctx);
	if (ret) {
		watcher_thr = 0;
		fprintf(stderr, "failed to start etcd watcher, error %d\n",
			ret);
		goto out_cancel;
	}

	pthread_mutex_lock(&lock);
	while (!stopped)
		pthread_cond_wait(&wait, &lock);
	pthread_mutex_unlock(&lock);

	printf("cancelling watcher\n");
	pthread_cancel(watcher_thr);

	printf("waiting for watcher to terminate\n");
	pthread_join(watcher_thr, NULL);

out_cancel:
	pthread_cancel(signal_thr);
	pthread_join(signal_thr, NULL);

out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
out_free:
	close(ctx->fanotify_fd);
	free(ctx->pathname);
	free(ctx);

	return ret ? 1 : 0;
}
