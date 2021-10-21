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

int null_ns_read(struct endpoint *ep, u16 tag)
{
	struct ep_qe *qe;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("endpoint %d: invalid tag %u",
			  ep->qid, tag);
		return NVME_SC_NS_NOT_READY;
	}

	ret = ep->ops->rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
	if (ret < 0) {
		print_errno("rma_read failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}

	ep->ops->release_tag(ep, tag);
	return ret;
}

int null_ns_write(struct endpoint *ep, u16 tag)
{
	struct ep_qe *qe;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("endpoint %d: invalid tag %u",
			  ep->qid, tag);
		return NVME_SC_NS_NOT_READY;
	}

	ret = ep->ops->rma_write(ep, qe->iovec.iov_base, 0,
				 qe->iovec.iov_len, qe->ccid, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	ep->ops->release_tag(ep, tag);
	return ret;
}

int null_ns_prep_read(struct endpoint *ep, u16 tag)
{
	struct ep_qe *qe = NULL;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("endpoint %d: invalid tag %u", ep->qid, tag);
		return NVME_SC_NS_NOT_READY;
	}

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

	
