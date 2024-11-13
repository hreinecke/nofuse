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

#define ep_info(e, f, x...)				\
	if (ep_debug) {					\
		printf("ep %d: " f "\n",		\
		       (e)->sockfd, ##x);		\
		fflush(stdout);				\
}

#define ep_err(e, f, x...)				\
	do {						\
		fprintf(stderr, "ep %d: " f "\n",	\
			(e)->sockfd, ##x);		\
		fflush(stderr);				\
	} while (0)


int connect_endpoint(struct endpoint *ep, struct nofuse_subsys *subsys,
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
				     ep->iface->portid) <= 0) {
		ep_err(ep, "Rejecting host NQN '%s'\n", hostnqn);
		ret = -EPERM;
		goto out_unlock;
	}
	ep_info(ep, "Allocating new controller '%s' for '%s'\n",
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
	list_add(&ctrl->node, &subsys->ctrl_list);
out_unlock:
	pthread_mutex_unlock(&subsys->ctrl_mutex);
	return ret;
}

static void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	struct nofuse_ctrl *ctrl = ep->ctrl;

	ep->ops->destroy_endpoint(ep);

	ep->state = DISCONNECTED;

	if (ctrl) {
		struct nofuse_subsys *subsys = ctrl->subsys;

		pthread_mutex_lock(&subsys->ctrl_mutex);
		ctrl->num_endpoints--;
		ep->ctrl = NULL;
		if (!ctrl->num_endpoints) {
			ep_info(ep, "deleting controller %u",
				ctrl->cntlid);
			list_del(&ctrl->node);
			free(ctrl);
		}
		pthread_mutex_unlock(&subsys->ctrl_mutex);
	}
}

static int start_interface(struct interface *iface)
{
	int ret;

	iface->ops = tcp_register_ops();
	if (!iface->ops)
		return -EINVAL;

	ret = iface->ops->init_listener(iface);
	if (ret < 0) {
		fprintf(stderr, "iface %d: init_listener failed\n",
			iface->portid);
		return ret;
	}
	return 0;
}

int start_endpoint(struct endpoint *ep, int id)
{
	int			 ret;

	ret = ep->ops->create_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "ep %d: Failed to create endpoint\n", ret);
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
	io_uring_sqe_set_data(sqe, sqe);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		ep_err(ep, "qid %d submit poll sqe failed, error %d",
		       ep->qid, ret);
		return NULL;
	}
	return sqe;
}

static void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	struct io_uring_sqe *pollin_sqe = NULL;
	sigset_t set;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = io_uring_queue_init(32, &ep->uring, 0);
	if (ret) {
		ep_err(ep, "qid %d error %d creating uring",
		       ep->qid, ret);
		goto out_disconnect;
	}

	while (!stopped) {
		struct io_uring_cqe *cqe;
		void *cqe_data;

		if (!pollin_sqe) {
			pollin_sqe = endpoint_submit_poll(ep, POLLIN);
			if (!pollin_sqe)
				break;
		}

		ret = io_uring_wait_cqe(&ep->uring, &cqe);
		if (ret < 0) {
			ep_err(ep, "qid %d wait cqe error %d",
			       ep->qid, ret);
			break;
		}
		io_uring_cqe_seen(&ep->uring, cqe);
		cqe_data = io_uring_cqe_get_data(cqe);
		if (cqe_data == pollin_sqe) {
			ret = cqe->res;
			if (ret < 0) {
				fprintf(stderr, "ctrl %d qid %d poll error %d",
					ep->ctrl ? ep->ctrl->cntlid : -1,
					ep->qid, ret);
				break;
			}
			if (ret & POLLERR) {
				ret = -ENODATA;
				printf("ctrl %d qid %d poll conn closed",
				       ep->ctrl ? ep->ctrl->cntlid : -1,
				       ep->qid);
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

		} else {
			struct ep_qe *qe = cqe_data;
			if (!qe) {
				fprintf(stderr, "ctrl %d qid %d empty cqe",
					ep->ctrl ? ep->ctrl->cntlid : -1,
					ep->qid);
				ret = -EAGAIN;
			}
			ret = handle_data(ep, qe, cqe->res);
		}
		if (ret == -EAGAIN)
			if (--ep->kato_countdown > 0)
				continue;
		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			printf("ctrl %d qid %d connection closed",
			       ep->ctrl ? ep->ctrl->cntlid : -1,
			       ep->qid);
			break;
		}
		if (ret < 0) {
			fprintf(stderr, "ctrl %d qid %d error %d retry %d",
				ep->ctrl ? ep->ctrl->cntlid : -1,
				ep->qid, ret, ep->kato_countdown);
			break;
		}
	}
	io_uring_queue_exit(&ep->uring);

out_disconnect:
	disconnect_endpoint(ep, !stopped);

	printf("ctrl %d qid %d %s",
	       ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
	       stopped ? "stopped" : "disconnected");
	pthread_exit(NULL);

	return NULL;
}

static struct endpoint *enqueue_endpoint(int id, struct interface *iface)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(struct endpoint));
	if (!ep) {
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
	ep->recv_state = RECV_PDU;
	ep->io_ops = tcp_register_io_ops();

	ret = start_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "ep %d: failed to start endpoint\n", id);
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
	struct interface *iface = arg;
	struct endpoint *ep, *_ep;
	sigset_t set;
	int id;
	pthread_attr_t pthread_attr;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = start_interface(iface);
	if (ret) {
		fprintf(stderr, "iface %d: failed to start, error %d\n",
			iface->portid, ret);
		pthread_exit(NULL);
		return NULL;
	}

	while (!stopped) {
		id = iface->ops->wait_for_connection(iface);

		if (stopped)
			break;

		if (id < 0) {
			if (id != -EAGAIN)
				fprintf(stderr,
					"Host connection failed, error %d\n", id);
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
			fprintf(stderr,
				"iface %d: pthread_create failed with %d\n",
				iface->portid, ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	printf("iface %d: destroy listener\n", iface->portid);

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
