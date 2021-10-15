#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"

#define RETRY_COUNT	1200	// 2 min since multiplier of delay timeout
#define KATO_INTERVAL	500	// ms per spec

static LINKED_LIST(endpoint_linked_list);

void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	if (ep->ep) {
		ep->ops->destroy_endpoint(ep->ep);
		ep->ep = NULL;
	}

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

	ret = iface->ops->init_listener(&iface->listener, iface->port_num);
	if (ret) {
		printf("start_pseudo_target init_listener failed\n");
		return ret;
	}

	return 0;
}

int run_pseudo_target(struct endpoint *ep, int id)
{
	int			 ret;

	ret = ep->ops->create_endpoint(&ep->ep, id);
	if (ret) {
		print_errno("Failed to create endpoint", ret);
		return ret;
	}

retry:
	ret = ep->ops->accept_connection(ep->ep);
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
		void *buf;
		int len;

		gettimeofday(&timeval, NULL);

		ret = ep->ops->poll_for_msg(ep->ep, &buf, &len);
		if (!ret) {
			ret = ep->ops->handle_msg(ep, buf, len);
			if (!ret && ep->ctrl) {
				ep->countdown	= ep->ctrl->kato;
				ep->timeval	= timeval;
				free(buf);
				continue;
			}
			print_info("ctrl %d qid %d handle msg error %d",
				   ep->ctrl ? ep->ctrl->cntlid : -1,
				   ep->qid, ret);
			free(buf);
		} else if (ret != -ETIMEDOUT && ret != -EAGAIN) {
			print_err("ctrl %d qid %d poll error %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret);
		}
		if (ret == -ETIMEDOUT)
			continue;
		if (ret == -EAGAIN)
			if (--ep->countdown > 0)
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
				  ep->qid, ret, ep->countdown);
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

	ep = malloc(sizeof(*ep));
	if (!ep) {
		print_err("no memory");
		close(id);
		return NULL;
	}

	memset(ep, 0, sizeof(*ep));

	ep->ops = iface->ops;
	ep->iface = iface;
	ep->countdown = RETRY_COUNT;

	ret = run_pseudo_target(ep, id);
	if (ret) {
		print_errno("run_pseudo_target failed", ret);
		goto out;
	}

	list_add(&ep->node, &endpoint_linked_list);
	return ep;
out:
	free(ep);
	return NULL;
}

int run_host_interface(struct host_iface *iface)
{
	struct xp_pep *listener;
	struct endpoint *ep, *_ep;
	int id;
	pthread_attr_t pthread_attr;
	int ret;

	ret = start_pseudo_target(iface);
	if (ret) {
		print_err("failed to start pseudo target");
		return ret;
	}

	listener = iface->listener;

	signal(SIGTERM, SIG_IGN);

	while (!stopped) {
		id = iface->ops->wait_for_connection(listener);

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

	iface->ops->destroy_listener(listener);

	list_for_each_entry_safe(ep, _ep, &endpoint_linked_list, node) {
		if (ep->pthread) {
			pthread_join(ep->pthread, NULL);
		}
		list_del(&ep->node);
		free(ep);
	}

	return ret;
}
