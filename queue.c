/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * queue.c
 * connection handling for NVMe-over-TCP userspace daemon.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#include "common.h"
#include "ops.h"
#include "configdb.h"

LINKED_LIST(ctrl_linked_list);
pthread_mutex_t ctrl_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static int nvmf_ctrl_id = 1;

int connect_queue(struct nofuse_queue *ep, u16 cntlid,
		  const char *hostnqn, const char *subsysnqn)
{
	struct nofuse_ctrl *ctrl;
	char nqn[MAX_NQN_SIZE + 1];
	int ret = 0;

	if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		ret = configdb_get_discovery_nqn(nqn);
		if (ret < 0)
			strcpy(nqn, subsysnqn);
	} else
		strcpy(nqn, subsysnqn);

	pthread_mutex_lock(&ctrl_list_mutex);
	if (ep->qid > 0) {
		list_for_each_entry(ctrl, &ctrl_linked_list, node) {
			if (strcmp(hostnqn, ctrl->hostnqn) ||
			    strcmp(nqn, ctrl->subsysnqn) ||
			    ctrl->cntlid != cntlid)
				continue;
			ep->ctrl = ctrl;
			ctrl->num_queues++;
			break;
		}
		if (!ep->ctrl) {
			ep_err(ep, "qid %d invalid cntlid %d",
			       ep->qid, cntlid);
			ret = -ENOENT;
		}
		goto out_unlock;
	}

	if (configdb_check_allowed_host(hostnqn, nqn, ep->port->portid) <= 0) {
		ep_err(ep, "rejecting host NQN '%s' for subsys '%s'",
		       hostnqn, nqn);
		ret = -EPERM;
		goto out_unlock;
	}
	ep_info(ep, "Allocating new controller '%s' for '%s'",
		hostnqn, nqn);
	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl) {
		ep_err(ep, "Out of memory allocating controller");
		ret = -ENOMEM;
		goto out_unlock;
	}
	memset(ctrl, 0, sizeof(*ctrl));
	cntlid = nvmf_ctrl_id++;
	ret = configdb_add_ctrl(nqn, cntlid);
	if (ret < 0) {
		ep_err(ep, "error registering cntlid %d", cntlid);
		free(ctrl);
		goto out_unlock;
	}
	strcpy(ctrl->hostnqn, hostnqn);
	strcpy(ctrl->subsysnqn, nqn);
	ctrl->max_queues = NVMF_NUM_QUEUES;
	ep->ctrl = ctrl;
	ctrl->ep = ep;
	ctrl->num_queues = 1;
	ctrl->cntlid = cntlid;
	ctrl->kato_countdown = RETRY_COUNT;
	INIT_LINKED_LIST(&ctrl->node);
	list_add(&ctrl->node, &ctrl_linked_list);
out_unlock:
	pthread_mutex_unlock(&ctrl_list_mutex);
	return ret;
}

static void disconnect_queue(struct nofuse_queue *ep)
{
	struct nofuse_ctrl *ctrl = ep->ctrl;

	ep->ops->destroy_queue(ep);

	ep->state = DISCONNECTED;
	if (!ctrl)
		return;

	ctrl_info(ep, "disconnect queue");
	pthread_mutex_lock(&ctrl_list_mutex);
	ctrl->num_queues--;
	ep->ctrl = NULL;
	if (!ctrl->num_queues) {
		printf("ctrl %u qid %d: deleting controller\n",
		       ctrl->cntlid, ep->qid);
		configdb_del_ctrl(ctrl->subsysnqn, ctrl->cntlid);
		list_del(&ctrl->node);
		free(ctrl);
	}
	pthread_mutex_unlock(&ctrl_list_mutex);
}

static int start_queue(struct nofuse_queue *ep, int conn)
{
	int ret;

	ret = ep->ops->create_queue(ep, conn);
	if (ret) {
		fprintf(stderr, "ep %d: Failed to create queue, error %d",
			conn, ret);
		return ret;
	}

retry:
	ret = ep->ops->accept_connection(ep);
	if (ret) {
		if (ret == -EAGAIN)
			goto retry;

		ep_err(ep, "accept() failed with error %d", ret);
		return ret;
	}

	ep->state = CONNECTED;
	return 0;
}

static struct io_uring_sqe *queue_submit_poll(struct nofuse_queue *ep,
					      int poll_flags)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		ep_err(ep, "qid %d failed to get poll sqe", ep->qid);
		return NULL;
	}

	io_uring_prep_poll_add(sqe, ep->sockfd, poll_flags);
	io_uring_sqe_set_data(sqe, ep);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		ep_err(ep, "qid %d submit poll sqe failed, error %d",
		       ep->qid, ret);
		return NULL;
	}
	return sqe;
}

static int queue_submit_cancel(struct nofuse_queue *ep)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		ep_err(ep, "qid %d failed to get poll sqe", ep->qid);
		return -ENOMEM;
	}

	io_uring_prep_cancel(sqe, ep, 0);
	io_uring_sqe_set_data(sqe, NULL);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		ep_err(ep, "qid %d submit cancel failed, error %d",
		       ep->qid, ret);
		return ret;
	}
	return 0;
}

static int queue_submit_aen(struct nofuse_queue *ep)
{
	struct io_uring_sqe *sqe;
	struct ep_qe *qe;
	int ret;

	qe = ep->ops->get_aen(ep);
	if (!qe) {
		ep_info(ep, "qid %d no aen request", ep->qid);
		return 0;
	}
	qe->opcode = nvme_admin_async_event;
	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		ep_err(ep, "qid %d failed to get nop sqe", ep->qid);
		return 0;
	}

	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data(sqe, qe);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		ep_err(ep, "qid %d submit nop failed, error %d",
		       ep->qid, ret);
		return ret;
	}
	return 0;
}

static void pop_disconnect(void *arg)
{
	struct nofuse_queue *ep = arg;

	disconnect_queue(ep);
}

static void pop_uring_exit(void *arg)
{
	struct nofuse_queue *ep = arg;

	io_uring_queue_exit(&ep->uring);
}

static void pop_free(void *arg)
{
	struct nofuse_queue *ep = arg;
	struct nofuse_port *port = ep->port;

	if (!port) {
		ep_err(ep, "no port set");
		return;
	}
	ep_info(ep, "destroy queue");
	pthread_mutex_lock(&port->ep_mutex);
	list_del(&ep->node);
	pthread_mutex_unlock(&port->ep_mutex);
	free(ep);
}

void *queue_thread(void *arg)
{
	struct nofuse_queue *ep = arg;
	struct io_uring_sqe *pollin_sqe = NULL;
	sigset_t set;
	int ret;

	pthread_cleanup_push(pop_free, ep);

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	pthread_cleanup_push(pop_disconnect, ep);

	ret = io_uring_queue_init(32, &ep->uring, 0);
	if (ret) {
		ep_err(ep, "qid %d error %d creating uring",
		       ep->qid, ret);
		goto out_disconnect;
	}

	pthread_cleanup_push(pop_uring_exit, ep);

	while (ep->state == CONNECTED) {
		struct io_uring_cqe *cqe;
		struct __kernel_timespec ts = {
			.tv_sec = (ep->kato_interval / 1000),
			.tv_nsec = (ep->kato_interval % 1000) * 1000 * 1000,
		};
		void *cqe_data;

		if (!pollin_sqe) {
			pollin_sqe = queue_submit_poll(ep, POLLIN);
			if (!pollin_sqe)
				break;
		}

		ret = io_uring_wait_cqe_timeout(&ep->uring, &cqe, &ts);
		if (ret < 0)
			goto skip_cqe;

		io_uring_cqe_seen(&ep->uring, cqe);
		cqe_data = io_uring_cqe_get_data(cqe);
		if (cqe_data == ep) {
			ret = cqe->res;
			if (ret < 0) {
				ctrl_err(ep, "poll error %d", ret);
				break;
			}
			if (ret & POLLERR) {
				ret = -ENODATA;
				ctrl_info(ep, "poll conn closed");
				break;
			}
			pollin_sqe = NULL;
			if (ep->recv_state == RECV_PDU) {
				ret = ep->ops->read_msg(ep);
				if (!ret && ep->ctrl)
					kato_reset_counter(ep->ctrl);
			}
			if (!ret && ep->recv_state == HANDLE_PDU) {
				ret = ep->ops->handle_msg(ep);
				if (!ret) {
					ep->recv_pdu_len = 0;
					ep->recv_state = RECV_PDU;
				}
			}
		} else if (cqe_data) {
			struct ep_qe *qe = cqe_data;
			if (qe->opcode == nvme_admin_async_event) {
				ret = ep->ops->handle_aen(ep, qe);
				if (!ret && aen_pending(ep->ctrl))
					ret = queue_submit_aen(ep);
			} else
				ret = handle_data(ep, qe, cqe->res);
		} else {
			ctrl_err(ep, "cancel cqe");
		}
	skip_cqe:
		if (ret == -EAGAIN || ret == -ETIME) {
			if (!ep->ctrl) {
				ep_err(ep, "qid %d no controller timeout",
				       ep->qid);
			} else {
				if (ep->qid != 0) {
					if (ep->ctrl->kato_countdown)
						continue;
				} else {
					if (--ep->ctrl->kato_countdown > 0)
						continue;
					ctrl_err(ep, "kato timeout");
				}
			}
		}
		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			ctrl_info(ep, "connection closed");
			break;
		}
		if (ret < 0) {
			int retry = ep->ctrl ?
				ep->ctrl->kato_countdown : RETRY_COUNT;
			ctrl_err(ep, "error %d retry %d", ret, retry);
			break;
		}
	}
	pthread_cleanup_pop(1);

out_disconnect:
	pthread_cleanup_pop(1);

	pthread_cleanup_pop(1);

	pthread_exit(NULL);

	return NULL;
}

struct nofuse_queue *create_queue(int conn, struct nofuse_port *port)
{
	struct nofuse_queue *ep;
	int ret;

	ep = malloc(sizeof(struct nofuse_queue));
	if (!ep) {
		close(conn);
		return NULL;
	}

	memset(ep, 0, sizeof(struct nofuse_queue));

	ep->ops = port->ops;
	ep->port = port;
	ep->kato_interval = KATO_INTERVAL;
	ep->maxh2cdata = 0x10000;
	ep->qid = -1;
	ep->recv_state = RECV_PDU;
	ep->io_ops = tcp_register_io_ops();
	INIT_LINKED_LIST(&ep->node);

	ret = start_queue(ep, conn);
	if (ret) {
		fprintf(stderr, "ep %d: failed to start queue", conn);
		goto out;
	}

	ep_info(ep, "start queue");
	pthread_mutex_lock(&port->ep_mutex);
	list_add(&ep->node, &port->ep_list);
	pthread_mutex_unlock(&port->ep_mutex);
	return ep;
out:
	free(ep);
	close(conn);
	return NULL;
}

void destroy_queue(struct nofuse_queue *ep)
{
	if (ep->state == CONNECTED) {
		ep->state = STOPPED;
		queue_submit_cancel(ep);
	}
	ep_info(ep, "cancel queue");
	if (ep->pthread) {
		pthread_cancel(ep->pthread);
		ep->pthread = 0;
	}
}

void terminate_queues(struct nofuse_port *port, const char *subsysnqn)
{
	struct nofuse_queue *ep = NULL, *_ep;

	pthread_mutex_lock(&port->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &port->ep_list, node) {
		printf("%s: ctrl %d qid %d subsys %s\n",
		       __func__,
		       ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		       ep->ctrl->subsysnqn ? ep->ctrl->subsysnqn : "<none>");
		if (ep->state != CONNECTED)
			continue;
		if (!ep->ctrl)
			continue;
		if (strcmp(ep->ctrl->subsysnqn, subsysnqn))
			continue;
		destroy_queue(ep);
	}
	pthread_mutex_unlock(&port->ep_mutex);
}

void raise_aen(const char *subsysnqn, u16 cntlid, int level)
{
	const char *aen_type = NULL;
	struct nofuse_ctrl *ctrl;
	struct nofuse_queue *ep = NULL;

	pthread_mutex_lock(&ctrl_list_mutex);
	list_for_each_entry(ctrl, &ctrl_linked_list, node) {
		if (!subsysnqn || strcmp(subsysnqn, ctrl->subsysnqn))
			continue;
		if (ctrl->cntlid != cntlid)
			continue;
		ep = ctrl->ep;
		break;
	}
	pthread_mutex_unlock(&ctrl_list_mutex);
	if (!ep || !ep->ctrl)
		return;
	switch (level) {
	case NVME_AER_NOTICE_NS_CHANGED:
		if (!(ep->ctrl->aen_masked & NVME_AEN_CFG_NS_ATTR)) {
			ep->ctrl->aen_pending |= NVME_AEN_CFG_NS_ATTR;
		}
		aen_type = "ns_changed";
		break;
	case NVME_AER_NOTICE_ANA:
		if (!(ep->ctrl->aen_masked & NVME_AEN_CFG_NS_ATTR)) {
			ep->ctrl->aen_pending |= NVME_AEN_CFG_ANA_CHANGE;
		}
		aen_type = "ana";
		break;
	case NVME_AER_NOTICE_DISC_CHANGED:
		if (!(ep->ctrl->aen_masked & NVME_AEN_CFG_DISC_CHANGE)) {
			ep->ctrl->aen_pending |= NVME_AEN_CFG_DISC_CHANGE;
		}
		aen_type = "discovery changed";
		break;
	default:
		return;
	}
	if (aen_pending(ep->ctrl)) {
		printf("%s: subsys %s ctrl %d type %s pending %#x masked %#x\n",
		       __func__, ep->ctrl->subsysnqn, ep->ctrl->cntlid,
		       aen_type, ep->ctrl->aen_pending, ep->ctrl->aen_masked);
		queue_submit_aen(ep);
	}
}
