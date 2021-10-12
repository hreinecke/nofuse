/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * NVMe over Fabrics Distributed Endpoint Management (NVMe-oF DEM).
 * Copyright (c) 2017-2019 Intel Corporation, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#define unlikely __glibc_unlikely

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nvme.h"
#include "utils.h"

extern int			 debug;
extern struct linked_list	*devices;
extern struct linked_list	*interfaces;

#define NVMF_UUID_FMT		"nqn.2014-08.org.nvmexpress:uuid:%s"

#define NVMF_DQ_DEPTH		2

#define MAX_NQN_SIZE		256
#define MAX_ALIAS_SIZE		64

#define PAGE_SIZE		4096

#define ADRFAM_STR_IPV4 "ipv4"
#define ADRFAM_STR_IPV6 "ipv6"

#define IPV4_LEN		4
#define IPV4_OFFSET		4
#define IPV4_DELIM		"."

#define IPV6_LEN		8
#define IPV6_OFFSET		8
#define IPV6_DELIM		":"

enum { DISCONNECTED, CONNECTED };

extern int			 stopped;

struct endpoint {
	struct linked_list	 node;
	pthread_t		 pthread;
	struct xp_ep		*ep;
	struct xp_ops		*ops;
	struct host_iface	*iface;
	struct ctrl_conn	*ctrl;
	struct nvme_command	*cmd;
	void			*data;
	int			 state;
	int			 qid;
	int			 countdown;
	struct timeval		 timeval;
};

struct ctrl_conn {
	struct linked_list	 node;
	struct linked_list	 ep_list;
	struct subsystem	*subsys;
	char			 nqn[MAX_NQN_SIZE + 1];
	int			 cntlid;
	int			 ctrl_type;
	int			 kato;
	u64			 csts;
	u64			 cc;
};

struct host {
	struct linked_list	 node;
	struct subsystem	*subsystem;
	char			 nqn[MAX_NQN_SIZE + 1];
};

struct nsdev {
	struct linked_list	 node;
	int			 devid;
	int			 nsid;
	int			 fd;
};

struct host_iface {
	char			 address[41];
	unsigned char		 addr[sizeof(struct in6_addr)];
	char			 port[9];
	int			 port_num;
	int			 adrfam;
	struct endpoint		 ep;
	struct xp_pep		*listener;
	struct xp_ops		*ops;
};

struct subsystem {
	struct linked_list	 node;
	struct linked_list	 host_list;
	struct linked_list	 ctrl_list;
	char			 nqn[MAX_NQN_SIZE + 1];
	int			 type;
};

struct target {
	struct host_iface	*iface;
	char			 alias[MAX_ALIAS_SIZE + 1];
	int			 mgmt_mode;
	int			 refresh;
	int			 log_page_retry_count;
	int			 refresh_countdown;
	int			 kato_countdown;
};

extern struct linked_list subsys_linked_list;

void disconnect_endpoint(struct endpoint *ep, int shutdown);

void shutdown_dem(void);

int run_host_interface(struct host_iface *iface);
int start_pseudo_target(struct host_iface *iface);
int run_pseudo_target(struct endpoint *ep, void *id);

#endif
