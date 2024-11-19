/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * endpoint.c
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

static int nvmf_ctrl_id = 1;

int connect_queue(struct endpoint *ep, struct nofuse_subsys *subsys,
		  u16 cntlid, const char *hostnqn, const char *subsysnqn)
{
	struct nofuse_ctrl *ctrl;
	int ret = 0;

	pthread_mutex_lock(&subsys->ctrl_mutex);
	if (cntlid < NVME_CNTLID_MAX) {
		list_for_each_entry(ctrl, &subsys->ctrl_list, node) {
			if (!strcmp(hostnqn, ctrl->nqn)) {
				if (ctrl->cntlid != cntlid)
					continue;
				ep->ctrl = ctrl;
				ctrl->num_endpoints++;
				break;
			}
		}
		if (!ep->ctrl)
			ret = -ENOENT;
		goto out_unlock;
	}

	if (configdb_check_allowed_host(hostnqn, subsys->nqn,
				     ep->port->portid) <= 0) {
		ep_err(ep, "rejecting host NQN '%s' for subsys '%s'",
		       hostnqn, subsys->nqn);
		ret = -EPERM;
		goto out_unlock;
	}
	ep_info(ep, "Allocating new controller '%s' for '%s'",
		hostnqn, subsysnqn);
	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl) {
		ep_err(ep, "Out of memory allocating controller");
		ret = -ENOMEM;
		goto out_unlock;
	}
	memset(ctrl, 0, sizeof(*ctrl));
	strcpy(ctrl->nqn, hostnqn);
	ctrl->max_endpoints = NVMF_NUM_QUEUES;
	ep->ctrl = ctrl;
	ctrl->num_endpoints = 1;
	ctrl->subsys = subsys;
	ctrl->cntlid = nvmf_ctrl_id++;
	if (subsys->type == NVME_NQN_CUR) {
		ctrl->ctrl_type = NVME_CTRL_CNTRLTYPE_DISC;
		ep->qsize = NVMF_DQ_DEPTH;
	} else {
		ctrl->ctrl_type = NVME_CTRL_CNTRLTYPE_IO;
	}
	INIT_LINKED_LIST(&ctrl->node);
	list_add(&ctrl->node, &subsys->ctrl_list);
out_unlock:
	pthread_mutex_unlock(&subsys->ctrl_mutex);
	return ret;
}

static void disconnect_queue(struct endpoint *ep, int shutdown)
{
	struct nofuse_ctrl *ctrl = ep->ctrl;
	int ep_num = ep->sockfd;

	ep->ops->destroy_endpoint(ep);

	ep->state = DISCONNECTED;

	if (ctrl) {
		struct nofuse_subsys *subsys = ctrl->subsys;

		pthread_mutex_lock(&subsys->ctrl_mutex);
		ctrl->num_endpoints--;
		ep->ctrl = NULL;
		if (!ctrl->num_endpoints) {
			printf("ep %d: deleting controller %u\n",
			       ep_num, ctrl->cntlid);
			list_del(&ctrl->node);
			free(ctrl);
		}
		pthread_mutex_unlock(&subsys->ctrl_mutex);
	}
}

static int start_queue(struct endpoint *ep, int id)
{
	int			 ret;

	ret = ep->ops->create_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "ep %d: Failed to create endpoint", ret);
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

int endpoint_update_qdepth(struct endpoint *ep, int qsize)
{
	struct ep_qe *qes;
	int i;

	if (qsize + 1 == ep->qsize)
		return 0;

	qes = calloc(qsize + 1, sizeof(struct ep_qe));
	if (!qes)
		return -1;
	free(ep->qes);
	ep->qes = qes;
	for (i = 0; i <= qsize; i++) {
		ep->qes[i].tag = i;
		ep->qes[i].ep = ep;
		INIT_LINKED_LIST(&ep->node);
	}
	ep->qsize = qsize + 1;
	return 0;
}

static struct io_uring_sqe *endpoint_submit_poll(struct endpoint *ep,
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

static int endpoint_submit_cancel(struct endpoint *ep)
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

static void pop_disconnect(void *arg)
{
	struct endpoint *ep = arg;

	ep_info(ep, "qid %d disconnect", ep->qid);
	disconnect_queue(ep, !stopped);
}

static void pop_uring_exit(void *arg)
{
	struct endpoint *ep = arg;

	io_uring_queue_exit(&ep->uring);
}

void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	struct io_uring_sqe *pollin_sqe = NULL;
	sigset_t set;
	int ret;

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
			pollin_sqe = endpoint_submit_poll(ep, POLLIN);
			if (!pollin_sqe)
				break;
		}

		ret = io_uring_wait_cqe_timeout(&ep->uring, &cqe, &ts);
		if (ret < 0) {
			if (ret == -ETIME && --ep->kato_countdown) {
				ep_err(ep, "qid %d wait cqe retry %d",
				       ep->qid, ep->kato_countdown);
				continue;
			}
			ep_err(ep, "qid %d wait cqe error %d",
			       ep->qid, ret);
			break;
		}
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
			}
			if (!ret && ep->recv_state == HANDLE_PDU) {
				ret = ep->ops->handle_msg(ep);
				if (!ret) {
					ep->recv_pdu_len = 0;
					ep->recv_state = RECV_PDU;
				}
			}
			if (!ret || ret == -EAGAIN) {
				if (ep->ctrl)
					ep->kato_countdown = ep->ctrl->kato;
				else
					ep->kato_countdown = RETRY_COUNT;
			}
		} else if (cqe_data) {
			struct ep_qe *qe = cqe_data;
			ret = handle_data(ep, qe, cqe->res);
		} else {
			ctrl_err(ep, "cancel cqe");
		}
		if (ret == -EAGAIN)
			if (--ep->kato_countdown > 0)
				continue;
		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			ctrl_info(ep, "connection closed");
			break;
		}
		if (ret < 0) {
			ctrl_err(ep, "error %d retry %d",
				 ret, ep->kato_countdown);
			break;
		}
	}
	pthread_cleanup_pop(1);

out_disconnect:
	pthread_cleanup_pop(1);

	pthread_exit(NULL);

	return NULL;
}

struct endpoint *create_queue(int id, struct nofuse_port *port)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(struct endpoint));
	if (!ep) {
		close(id);
		return NULL;
	}

	memset(ep, 0, sizeof(struct endpoint));

	ep->ops = port->ops;
	ep->port = port;
	ep->kato_countdown = RETRY_COUNT;
	ep->kato_interval = KATO_INTERVAL;
	ep->maxh2cdata = 0x10000;
	ep->qid = -1;
	ep->recv_state = RECV_PDU;
	ep->io_ops = tcp_register_io_ops();
	INIT_LINKED_LIST(&ep->node);

	ret = start_queue(ep, id);
	if (ret) {
		fprintf(stderr, "ep %d: failed to start endpoint", id);
		goto out;
	}

	ep_info(ep, "start endpoint");
	pthread_mutex_lock(&port->ep_mutex);
	list_add(&ep->node, &port->ep_list);
	pthread_mutex_unlock(&port->ep_mutex);
	return ep;
out:
	free(ep);
	close(id);
	return NULL;
}

void destroy_queue(struct endpoint *ep)
{
	if (ep->state == CONNECTED) {
		ep->state = STOPPED;
		endpoint_submit_cancel(ep);
	}
	if (ep->pthread) {
		ep_info(ep, "destroy queue");
		pthread_cancel(ep->pthread);
		pthread_join(ep->pthread, NULL);
		ep->pthread = 0;
	}
	list_del(&ep->node);
	free(ep);
}

void terminate_queues(struct nofuse_port *port, const char *subsysnqn)
{
	struct endpoint *ep = NULL, *_ep;

	pthread_mutex_lock(&port->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &port->ep_list, node) {
		printf("%s: ctrl %d qid %d subsys %s\n",
		       __func__,
		       ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		       ep->ctrl->subsys ? ep->ctrl->subsys->nqn : "<none>");
		if (ep->state != CONNECTED)
			continue;
		if (!ep->ctrl)
			continue;
		if (strcmp(ep->ctrl->subsys->nqn, subsysnqn))
			continue;
		destroy_queue(ep);
	}
	pthread_mutex_unlock(&port->ep_mutex);
}

void kato_reset_counter(struct nofuse_port *port, struct nofuse_ctrl *ctrl)
{
	struct endpoint *ep = NULL, *_ep;

	pthread_mutex_lock(&port->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &port->ep_list, node) {
		if (ep->ctrl != ctrl)
			continue;
		ep->kato_countdown = ep->ctrl->kato;
	}
	pthread_mutex_unlock(&port->ep_mutex);
}
