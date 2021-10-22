#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#include "common.h"
#include "ops.h"

void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	ep->ops->destroy_endpoint(ep);

	ep->state = DISCONNECTED;
}

int start_pseudo_target(struct host_iface *iface)
{
	int ret;

	iface->ops = tcp_register_ops();
	if (!iface->ops)
		return -EINVAL;

	ret = iface->ops->init_listener(iface);
	if (ret < 0) {
		print_err("iface %s init_listener failed",
			iface->address);
		return ret;
	}
	iface->listenfd = ret;
	return 0;
}

int run_pseudo_target(struct endpoint *ep, int id)
{
	int			 ret;

	ret = ep->ops->create_endpoint(ep, id);
	if (ret) {
		print_errno("Failed to create endpoint", ret);
		return ret;
	}

retry:
	ret = ep->ops->accept_connection(ep);
	if (ret) {
		if (ret == -EAGAIN)
			goto retry;

		print_errno("accept() failed for endpoint", ret);
		return ret;
	}

	ep->state = CONNECTED;
	return 0;
}

static struct io_uring_sqe *endpoint_submit_poll(struct endpoint *ep)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		print_err("endpoint %d: failed to get poll sqe", ep->qid);
		return NULL;
	}

	io_uring_prep_poll_add(sqe, ep->sockfd, POLLIN);
	io_uring_sqe_set_data(sqe, sqe);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		print_err("endpoint %d: submit poll sqe failed, error %d",
			  ep->qid, ret);
		return NULL;
	}
	return sqe;
}

static void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	struct io_uring_sqe *poll_sqe = NULL;
	sigset_t set;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = io_uring_queue_init(32, &ep->uring, 0);
	if (ret) {
		print_err("endpoint %d: error %d creating uring",
			  ep->qid, ret);
		goto out_disconnect;
	}

	while (!stopped) {
		struct io_uring_cqe *cqe;

		if (!poll_sqe) {
			poll_sqe = endpoint_submit_poll(ep);
			if (!poll_sqe)
				break;
		}

		ret = io_uring_wait_cqe(&ep->uring, &cqe);
		if (ret < 0) {
			print_err("ctrl %d qid %d wait cqe error %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret);
			break;
		}
		io_uring_cqe_seen(&ep->uring, cqe);
		if (io_uring_cqe_get_data(cqe) == poll_sqe) {
			poll_sqe = NULL;
			ret = ep->ops->read_msg(ep);
			if (!ret) {
				ret = ep->ops->handle_msg(ep);
				if (!ret && ep->ctrl) {
					ep->kato_countdown = ep->ctrl->kato;
					continue;
				}
				print_info("ctrl %d qid %d handle msg error %d",
					   ep->ctrl ? ep->ctrl->cntlid : -1,
					   ep->qid, ret);
			}
		} else {
			struct ep_qe *qe = io_uring_cqe_get_data(cqe);
			if (!qe) {
				print_err("ctrl %d qid %d empty cqe",
					  ep->ctrl ? ep->ctrl->cntlid : -1,
					  ep->qid);
				ret = -EAGAIN;
			}
			ret = qe->ns->ops->ns_handle_qe(ep, qe, cqe->res);
		}
		if (ret == -EAGAIN)
			if (--ep->kato_countdown > 0)
				continue;
		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			print_info("ctrl %d qid %d connection closed",
				   ep->ctrl ? ep->ctrl->cntlid : -1,
				   ep->qid);
			break;
		}
		if (ret < 0) {
			print_err("ctrl %d qid %d error %d retry %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret, ep->kato_countdown);
			break;
		}
	}
	io_uring_queue_exit(&ep->uring);

out_disconnect:
	disconnect_endpoint(ep, !stopped);

	print_info("ctrl %d qid %d %s",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   stopped ? "stopped" : "disconnected");
	pthread_exit(NULL);

	return NULL;
}

static struct endpoint *enqueue_endpoint(int id, struct host_iface *iface)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(struct endpoint));
	if (!ep) {
		print_err("no memory");
		close(id);
		return NULL;
	}

	memset(ep, 0, sizeof(struct endpoint));

	ep->ops = iface->ops;
	ep->iface = iface;
	ep->kato_countdown = RETRY_COUNT;
	ep->kato_interval = KATO_INTERVAL;
	ep->maxh2cdata = 0x10000;
	ep->qid = -1;

	ret = run_pseudo_target(ep, id);
	if (ret) {
		print_errno("run_pseudo_target failed", ret);
		goto out;
	}

	pthread_mutex_lock(&iface->ep_mutex);
	list_add(&ep->node, &iface->ep_list);
	pthread_mutex_unlock(&iface->ep_mutex);
	return ep;
out:
	free(ep);
	close(id);
	return NULL;
}

void *run_host_interface(void *arg)
{
	struct host_iface *iface = arg;
	struct endpoint *ep, *_ep;
	sigset_t set;
	int id;
	pthread_attr_t pthread_attr;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = start_pseudo_target(iface);
	if (ret) {
		print_err("failed to start pseudo target, error %d", ret);
		pthread_exit(NULL);
		return NULL;
	}

	signal(SIGTERM, SIG_IGN);

	while (!stopped) {
		id = iface->ops->wait_for_connection(iface);

		if (stopped)
			break;

		if (id < 0) {
			if (id != -EAGAIN)
				print_errno("Host connection failed", id);
			continue;
		}
		ep = enqueue_endpoint(id, iface);
		if (!ep)
			continue;

		pthread_attr_init(&pthread_attr);

		ret = pthread_create(&ep->pthread, &pthread_attr,
				     endpoint_thread, ep);
		if (ret) {
			ep->pthread = 0;
			print_err("failed to start endpoint thread");
			print_errno("pthread_create failed", ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	print_info("iface %d: destroy listener", iface->portid);

	iface->ops->destroy_listener(iface);
	pthread_mutex_lock(&iface->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &iface->ep_list, node) {
		if (ep->pthread) {
			pthread_join(ep->pthread, NULL);
		}
		list_del(&ep->node);
		free(ep);
	}
	pthread_mutex_unlock(&iface->ep_mutex);
	pthread_exit(NULL);
	return NULL;
}
