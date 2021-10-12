// SPDX-License-Identifier: DUAL GPL-2.0/BSD
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"

#define NVME_CTRL_ENABLE	0x460001
#define NVME_CTRL_DISABLE	0x464001

#define NVME_DISC_KATO_MS	(u16) 360000
#define RETRY_COUNT		5
#define MSG_TIMEOUT		100
#define CONFIG_TIMEOUT		50
#define CONFIG_RETRY_COUNT	20
#define CONNECT_RETRY_COUNT	10

void dump(u8 *buf, int len)
{
	int			 i, j, n = 0;
	char			 hex[49];
	char			 prev[49];
	char			 chr[17];
	char			*p, *c;

	memset(prev, 0, sizeof(prev));
	memset(hex, 0, sizeof(hex));
	memset(chr, 0, sizeof(chr));
	c = chr;
	p = hex;

	for (i = j = 0; i < len; i++) {
		sprintf(p, "%02x ", buf[i]);
		p += 3;
		*c++ = (buf[i] >= 0x20 && buf[i] <= 0x7f) ? buf[i] : '.';

		if (++j == 16) {
			if (strcmp(hex, prev)) {
				if (n) {
					printf("----  repeated %d %s  ----\n",
					       n, n == 1 ? "time" : "times");
					n = 0;
				}
				printf("%04x  %s  %s\n", i - j + 1, hex, chr);
				strcpy(prev, hex);
			} else
				n++;
			j = 0;
			memset(hex, 0, sizeof(hex));
			memset(chr, 0, sizeof(chr));
			c = chr;
			p = hex;
		}
	}

	if (j) {
		if (strcmp(hex, prev) == 0)
			n++;
		if (n)
			printf("----  repeated %d %s  ----\n",
			       n, n == 1 ? "time" : "times");
		if (strcmp(hex, prev))
			printf("%04x  %-48s  %s\n", i - j, hex, chr);
	}
}

void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	if (ep->ep)
		ep->ops->destroy_endpoint(ep->ep);

	if (ep->cmd)
		free(ep->cmd);

	ep->state = DISCONNECTED;
}

int start_pseudo_target(struct host_iface *iface)
{
	struct sockaddr		 dest;
	int			 ret;

	if (strcmp(iface->family, "ipv4") == 0)
		ret = inet_pton(AF_INET, iface->address, &dest);
	else if (strcmp(iface->family, "ipv6") == 0)
		ret = inet_pton(AF_INET6, iface->address, &dest);
	else
		return -EINVAL;

	if (!ret)
		return -EINVAL;
	if (ret < 0)
		return errno;

	iface->ops = tcp_register_ops();
	if (!iface->ops)
		return -EINVAL;

	ret = iface->ops->init_listener(&iface->listener, iface->port);
	if (ret) {
		printf("start_pseudo_target init_listener failed\n");
		return ret;
	}

	return 0;
}

int run_pseudo_target(struct endpoint *ep, void *id)
{
	void			*cmd;
	void			*data;
	int			 ret;

	ret = ep->ops->create_endpoint(&ep->ep, id, NVMF_DQ_DEPTH);
	if (ret)
		return ret;

	ret = ep->ops->accept_connection(ep->ep);
	if (ret)
		goto out_destroy;

	if (posix_memalign(&cmd, PAGE_SIZE, PAGE_SIZE)) {
		ret = -errno;
		goto out_destroy;
	}

	memset(cmd, 0, PAGE_SIZE);

	if (posix_memalign(&data, PAGE_SIZE, PAGE_SIZE)) {
		ret = -errno;
		goto out_free_cmd;
	}

	memset(data, 0, PAGE_SIZE);

	ep->cmd = cmd;
	ep->data = data;

	ep->state = CONNECTED;

	return 0;

out_free_cmd:
	free(cmd);
out_destroy:
	ep->ops->destroy_endpoint(ep->ep);
	return ret;
}
