/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * null.c
 * null backend for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <errno.h>

#include "utils.h"
#include "common.h"
#include "nvme.h"
#include "ops.h"

int null_ns_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return 0;
}

int null_ns_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return ep->ops->rma_write(ep, qe, qe->data_len);
}

int null_ns_prep_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return ep->ops->prep_rma_read(ep, qe->tag);
}

static struct ns_ops null_ops = {
	.ns_read = null_ns_read,
	.ns_write = null_ns_write,
	.ns_prep_read = null_ns_prep_read,
};

struct ns_ops *null_register_ops(void)
{
	return &null_ops;
}

	
