/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * interface.c
 * Interface handling for NVMe-over-TCP userspace daemon.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#include "common.h"
#include "ops.h"
#include "configdb.h"

LINKED_LIST(iface_linked_list);

int add_iface(unsigned int id, const char *ifaddr, int port)
{
	struct interface *iface;
	int ret;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return -ENOMEM;
	memset(iface, 0, sizeof(*iface));
	iface->listenfd = -1;
	iface->portid = id;
	ret = configdb_add_port(id);
	if (ret < 0) {
		iface_err(iface, "cannot register port, error %d", ret);
		free(iface);
		return ret;
	}
	if (ifaddr && strcmp(ifaddr, "127.0.0.1")) {
		if (!strchr(ifaddr, ','))
			configdb_set_port_attr(iface->portid, "addr_adrfam",
					    "ipv6");
		configdb_set_port_attr(iface->portid, "addr_traddr", ifaddr);
	}
	if (port) {
		char trsvcid[5];

		sprintf(trsvcid, "%d", port);
		configdb_set_port_attr(iface->portid, "addr_trsvcid", trsvcid);
	}
	ret = configdb_add_ana_group(iface->portid, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		iface_err(iface, "cannot add ana group to port, error %d", ret);
		configdb_del_port(iface->portid);
		free(iface);
		return ret;
	}
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LINKED_LIST(&iface->ep_list);
	INIT_LINKED_LIST(&iface->node);
	list_add_tail(&iface->node, &iface_linked_list);
	iface_info(iface, "created");

	return 0;
}

struct interface *find_iface(unsigned int id)
{
	struct interface *iface;

	list_for_each_entry(iface, &iface_linked_list, node) {
		if (iface->portid == id) {
			return iface;
		}
	}
	return NULL;
}

int start_iface(struct interface *iface)
{
	pthread_attr_t pthread_attr;
	int ret;

	if (iface->pthread)
		return 0;

	iface_info(iface, "starting");
	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&iface->pthread, &pthread_attr,
			     run_interface, iface);
	if (ret) {
		iface->pthread = 0;
		iface_err(iface, "failed to start iface thread");
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

int stop_iface(struct interface *iface)
{
	struct endpoint *ep, *_ep;

	iface_info(iface, "stop pthread %ld", iface->pthread);
	if (iface->pthread) {
		pthread_cancel(iface->pthread);
		pthread_join(iface->pthread, NULL);
		iface->pthread = 0;
	}

	pthread_mutex_lock(&iface->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &iface->ep_list, node)
		dequeue_endpoint(ep);
	pthread_mutex_unlock(&iface->ep_mutex);
	return 0;
}

int del_iface(struct interface *iface)
{
	int ret;

	iface_info(iface, "deleting");
	if (iface->pthread) {
		iface_err(iface, "interface still running");
		return -EBUSY;
	}
	ret = configdb_del_ana_group(iface->portid, 1);
	if (ret < 0) {
		iface_err(iface, "cannot delete ana group from port, error %d",
			  ret);
		return ret;
	}
	ret = configdb_del_port(iface->portid);
	if (ret < 0) {
		configdb_add_ana_group(iface->portid, 1, NVME_ANA_OPTIMIZED);
		return ret;
	}
	pthread_mutex_destroy(&iface->ep_mutex);
	list_del(&iface->node);
	free(iface);
	return 0;
}

static int start_interface(struct interface *iface)
{
	int ret;

	iface->ops = tcp_register_ops();
	if (!iface->ops)
		return -EINVAL;

	ret = iface->ops->init_listener(iface);
	if (ret < 0) {
		iface_err(iface, "init_listener failed with %d", ret);
		return ret;
	}
	return 0;
}

static void pop_listener(void *arg)
{
	struct interface *iface = arg;

	iface_info(iface, "destroy_listener");
	iface->ops->destroy_listener(iface);
}

void *run_interface(void *arg)
{
	struct interface *iface = arg;
	struct endpoint *ep;
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
		iface_err(iface, "failed to start, error %d", ret);
		pthread_exit(NULL);
		return NULL;
	}

	pthread_cleanup_push(pop_listener, iface);

	while (!stopped) {
		id = iface->ops->wait_for_connection(iface);

		if (stopped)
			break;

		if (id < 0) {
			if (id == -ESHUTDOWN)
				break;
			if (id != -EAGAIN)
				iface_err(iface,
					  "wait for connection failed, error %d", id);

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
			iface_err(iface, "pthread_create failed with %d", ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	pthread_cleanup_pop(1);
	pthread_exit(NULL);
	return NULL;
}
