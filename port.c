/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * port.c
 * Port handling for NVMe-over-TCP userspace daemon.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <urcu/uatomic.h>

#include "common.h"
#include "ops.h"
#include "etcd_backend.h"

LINKED_LIST(port_linked_list);
pthread_mutex_t port_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *run_port(void *arg);

int add_port(struct etcd_ctx *ctx, unsigned int id,
	     const char *ifaddr, int portnum)
{
	struct nofuse_port *port;

	port = malloc(sizeof(*port));
	if (!port)
		return -ENOMEM;
	memset(port, 0, sizeof(*port));
	port->ref  = 1;
	port->listenfd = -1;
	port->portid = id;
	port->ctx = ctx;
	pthread_mutex_init(&port->ep_mutex, NULL);
	INIT_LINKED_LIST(&port->ep_list);
	INIT_LINKED_LIST(&port->node);
	list_add_tail(&port->node, &port_linked_list);
	port_info(port, "created");

	return 0;
}

struct nofuse_port *_find_port(unsigned int id)
{
	struct nofuse_port *port;

	list_for_each_entry(port, &port_linked_list, node) {
		if (port->portid == id)
			return port;
	}
	return NULL;
}

struct nofuse_port *find_port(unsigned int id)
{
	struct nofuse_port *port;

	pthread_mutex_lock(&port_list_mutex);
	port = _find_port(id);
	if (port) {
		if (!port->ref)
			port_err(port, "refcount already released");
		port->ref++;
	}
	pthread_mutex_unlock(&port_list_mutex);
	return port;
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

void stop_port(struct nofuse_port *port)
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
}

int del_port(struct nofuse_port *port)
{
	port->ref--;
	port_info(port, "deleting, refcount %d", port->ref);
	if (port->pthread) {
		port_err(port, "port still running");
		return -EBUSY;
	}
	pthread_mutex_destroy(&port->ep_mutex);
	list_del_init(&port->node);
	free(port);
	return 0;
}

int find_and_add_port(struct etcd_ctx *ctx, unsigned int portid)
{
	struct nofuse_port *port;
	int ret;

	pthread_mutex_lock(&port_list_mutex);
	port = _find_port(portid);
	if (port)
		ret = -EAGAIN;
	else
		ret = add_port(ctx, portid, NULL, 0);
	pthread_mutex_unlock(&port_list_mutex);
	return ret;
}

int find_and_del_port(unsigned int portid)
{
	struct nofuse_port *port;
	int ret = -ENOENT;

	pthread_mutex_lock(&port_list_mutex);
	port = _find_port(portid);
	if (port)
		ret = del_port(port);
	else
		fprintf(stderr, "port %d: no port to delete\n", portid);
	pthread_mutex_unlock(&port_list_mutex);
	return ret;
}

void cleanup_ports(void)
{
	struct nofuse_port *port, *tmp;

	pthread_mutex_lock(&port_list_mutex);
	list_for_each_entry_safe(port, tmp, &port_linked_list, node) {
		stop_port(port);
		del_port(port);
	}
	pthread_mutex_unlock(&port_list_mutex);
}

void put_port(struct nofuse_port *port)
{
	pthread_mutex_lock(&port_list_mutex);
	port->ref--;
	if (!port->ref)
		port_err(port, "refcount dropped");
	pthread_mutex_unlock(&port_list_mutex);
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
	int conn;
	pthread_attr_t pthread_attr;
	int ret;

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
