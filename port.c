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

LINKED_LIST(port_linked_list);

static void *run_port(void *arg);

int add_port(unsigned int id, const char *ifaddr, int portnum)
{
	struct nofuse_port *port;
	int ret;

	port = malloc(sizeof(*port));
	if (!port)
		return -ENOMEM;
	memset(port, 0, sizeof(*port));
	port->listenfd = -1;
	port->portid = id;
	ret = configdb_add_port(id);
	if (ret < 0) {
		port_err(port, "cannot register port, error %d", ret);
		free(port);
		return ret;
	}
	if (ifaddr && strcmp(ifaddr, "127.0.0.1")) {
		if (!strchr(ifaddr, ','))
			configdb_set_port_attr(port->portid, "addr_adrfam",
					    "ipv6");
		configdb_set_port_attr(port->portid, "addr_traddr", ifaddr);
	}
	if (portnum) {
		char trsvcid[5];

		sprintf(trsvcid, "%d", portnum);
		configdb_set_port_attr(port->portid, "addr_trsvcid", trsvcid);
	}
	ret = configdb_add_ana_group(port->portid, 1, NVME_ANA_OPTIMIZED);
	if (ret < 0) {
		port_err(port, "cannot add ana group to port, error %d", ret);
		configdb_del_port(port->portid);
		free(port);
		return ret;
	}
	pthread_mutex_init(&port->ep_mutex, NULL);
	INIT_LINKED_LIST(&port->ep_list);
	INIT_LINKED_LIST(&port->node);
	list_add_tail(&port->node, &port_linked_list);
	port_info(port, "created");

	return 0;
}

struct nofuse_port *find_port(unsigned int id)
{
	struct nofuse_port *port;

	list_for_each_entry(port, &port_linked_list, node) {
		if (port->portid == id) {
			return port;
		}
	}
	return NULL;
}

int start_port(struct nofuse_port *port)
{
	pthread_attr_t pthread_attr;
	int ret;

	if (port->pthread)
		return 0;

	port_info(port, "starting");
	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&port->pthread, &pthread_attr,
			     run_port, port);
	if (ret) {
		port->pthread = 0;
		port_err(port, "failed to start port thread");
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

int stop_port(struct nofuse_port *port)
{
	struct nofuse_queue *ep, *_ep;

	port_info(port, "stop pthread %ld", port->pthread);
	if (port->pthread) {
		pthread_cancel(port->pthread);
		pthread_join(port->pthread, NULL);
		port->pthread = 0;
	}

	pthread_mutex_lock(&port->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &port->ep_list, node)
		destroy_queue(ep);
	pthread_mutex_unlock(&port->ep_mutex);
	return 0;
}

int del_port(struct nofuse_port *port)
{
	int ret;

	port_info(port, "deleting");
	if (port->pthread) {
		port_err(port, "port still running");
		return -EBUSY;
	}
	ret = configdb_del_ana_group(port->portid, 1);
	if (ret < 0) {
		port_err(port, "cannot delete ana group from port, error %d",
			  ret);
		return ret;
	}
	ret = configdb_del_port(port->portid);
	if (ret < 0) {
		configdb_add_ana_group(port->portid, 1, NVME_ANA_OPTIMIZED);
		return ret;
	}
	pthread_mutex_destroy(&port->ep_mutex);
	list_del(&port->node);
	free(port);
	return 0;
}

static int start_listener(struct nofuse_port *port)
{
	int ret;

	port->ops = tcp_register_ops();
	if (!port->ops)
		return -EINVAL;

	ret = port->ops->init_listener(port);
	if (ret < 0) {
		port_err(port, "init_listener failed with %d", ret);
		return ret;
	}
	return 0;
}

static void pop_listener(void *arg)
{
	struct nofuse_port *port = arg;

	port_info(port, "destroy_listener");
	port->ops->destroy_listener(port);
}

static void *run_port(void *arg)
{
	struct nofuse_port *port = arg;
	struct nofuse_queue *ep;
	sigset_t set;
	int conn;
	pthread_attr_t pthread_attr;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = start_listener(port);
	if (ret) {
		port_err(port, "failed to start listener, error %d", ret);
		pthread_exit(NULL);
		return NULL;
	}

	pthread_cleanup_push(pop_listener, port);

	while (!stopped) {
		conn = port->ops->wait_for_connection(port);

		if (stopped)
			break;

		if (conn < 0) {
			if (conn == -ESHUTDOWN)
				break;
			if (conn != -EAGAIN)
				port_err(port,
					 "wait for connection failed, error %d",
					 conn);

			continue;
		}
		ep = create_queue(conn, port);
		if (!ep)
			continue;

		pthread_attr_init(&pthread_attr);
		pthread_attr_setdetachstate(&pthread_attr,
					    PTHREAD_CREATE_DETACHED);

		ret = pthread_create(&ep->pthread, &pthread_attr,
				     queue_thread, ep);
		if (ret) {
			ep->pthread = 0;
			port_err(port, "pthread_create failed with %d", ret);
			destroy_queue(ep);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	pthread_cleanup_pop(1);
	pthread_exit(NULL);
	return NULL;
}
