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

#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_ep {
	struct sockaddr_in	*sock_addr;
	struct xp_qe		*qe;
	int			 sockfd;
	int			 state;
	__u64			 depth;
};

struct xp_pep {
	struct sockaddr_in	*sock_addr;
	int			 listenfd;
	int			 sockfd;
};

struct xp_ops {
	int (*init_endpoint)(struct xp_ep **ep, int depth);
	int (*create_endpoint)(struct xp_ep **ep, void *id, int depth);
	void (*destroy_endpoint)(struct xp_ep *ep);
	int (*init_listener)(struct xp_pep **pep, char *port);
	void (*destroy_listener)(struct xp_pep *pep);
	int (*wait_for_connection)(struct xp_pep *pep, void **id);
	int (*accept_connection)(struct xp_ep *ep);
	int (*rma_read)(struct xp_ep *ep, void *buf, u64 addr, u64 len);
	int (*rma_write)(struct xp_ep *ep, void *buf, u64 addr, u64 len,
			 struct nvme_command *cmd);
	int (*send_rsp)(struct xp_ep *ep, void *msg, int len);
	int (*poll_for_msg)(struct xp_ep *ep, void **msg, int *bytes);
	void (*set_sgl)(struct nvme_command *cmd, u8 opcode, int len,
			void *data);
};

struct xp_ops *tcp_register_ops(void);

#endif /* __OPS_H__ */
