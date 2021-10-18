#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"

void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	ep->ops->destroy_endpoint(ep);

	ep->state = DISCONNECTED;
}

int start_pseudo_target(struct host_iface *iface)
{
	struct sockaddr		 dest;
	int			 ret;

	switch (iface->adrfam) {
	case NVMF_ADDR_FAMILY_IP4:
		ret = inet_pton(AF_INET, iface->address, &dest);
		break;
	case NVMF_ADDR_FAMILY_IP6:
		ret = inet_pton(AF_INET6, iface->address, &dest);
		break;
	default:
		return -EINVAL;
	}

	if (!ret)
		return -EINVAL;
	if (ret < 0)
		return errno;

	iface->ops = tcp_register_ops();
	if (!iface->ops)
		return -EINVAL;

	ret = iface->ops->init_listener(iface->port_num);
	if (ret < 0) {
		printf("start_pseudo_target init_listener failed\n");
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

static void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	int ret;

	while (!stopped) {
		struct timeval timeval;
		void *buf = NULL;
		int len;

		gettimeofday(&timeval, NULL);
		if (!ep->ops) {
			print_err("endpoint %d not initialized",
				  ep->qid);
			break;
		}

		ret = ep->ops->poll_for_msg(ep, &buf, &len);
		if (!ret) {
			ret = ep->ops->handle_msg(ep, buf, len);
			if (!ret && ep->ctrl) {
				ep->kato_countdown = ep->ctrl->kato;
				ep->timeval = timeval;
				free(buf);
				continue;
			}
			print_info("ctrl %d qid %d handle msg error %d",
				   ep->ctrl ? ep->ctrl->cntlid : -1,
				   ep->qid, ret);
			if (buf)
				free(buf);
		} else if (ret != -ETIMEDOUT && ret != -EAGAIN) {
			print_err("ctrl %d qid %d poll error %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret);
		}
		if (ret == -ETIMEDOUT)
			continue;
		if (ret == -EAGAIN)
			if (--ep->kato_countdown > 0)
				continue;
		/*
		 * ->poll_for_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA)
			break;
		if (ret < 0) {
			print_err("ctrl %d qid %d error %d retry %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret, ep->kato_countdown);
			break;
		}
	}

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

int run_host_interface(struct host_iface *iface)
{
	struct endpoint *ep, *_ep;
	int id;
	pthread_attr_t pthread_attr;
	int ret;

	ret = start_pseudo_target(iface);
	if (ret) {
		print_err("failed to start pseudo target");
		return ret;
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

	print_info("destroy listener");

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
	return ret;
}
