#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <pthread.h>

#include "common.h"
#include "nvme.h"
#include "ops.h"

int uring_submit_read(struct endpoint *ep, u16 tag)
{
	struct io_uring_sqe *sqe;
	struct ep_qe *qe;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("endpoint %d: invalid tag %u", ep->qid, tag);
		return NVME_SC_NS_NOT_READY;
	}
	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		print_err("No SQEs available");
		ret = NVME_SC_QUEUE_SIZE;
		goto out_put;
	}

	ret = ep->ops->rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
	if (ret < 0) {
		print_errno("rma_read failed", ret);
		ret = NVME_SC_WRITE_FAULT;
		goto out_put;
	}
	io_uring_prep_writev(sqe, qe->ns->fd, &qe->iovec, 1, qe->pos);
	io_uring_sqe_set_data(sqe, qe);

	ret = io_uring_submit(&ep->uring);
	if (ret < 0) {
		print_errno("io_uring_submit failed", errno);
		ret = NVME_SC_INTERNAL;
		goto out_put;
	}
	
	return -1;
out_put:
	ep->ops->release_tag(ep, tag);
	return ret;
}

int uring_submit_write(struct endpoint *ep, u16 tag)
{
	struct ep_qe *qe;
	struct io_uring_sqe *sqe;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("endpoint %d: invalid tag %u", ep->qid, tag);
		return NVME_SC_NS_NOT_READY;
	}
	
	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		print_err("No SQEs available");
		ret = NVME_SC_QUEUE_SIZE;
		goto out_put;
	}
	io_uring_prep_readv(sqe, qe->ns->fd, &qe->iovec, 1,
			    qe->pos);
	io_uring_sqe_set_data(sqe, qe);

	ret = io_uring_submit(&ep->uring);
	if (ret < 0) {
		print_err("endpoint %d tag %d: io_uring_submit error %d",
			  ep->qid, tag, errno);
		ret = NVME_SC_INTERNAL;
		goto out_put;
	}
	return -1;
out_put:
	ep->ops->release_tag(ep, tag);
	return ret;
}

static int uring_handle_qe(struct endpoint *ep, struct ep_qe *qe, int res)
{
	int ret = 0;
	u16 ccid = qe->ccid, tag = qe->tag;
	int cntlid = ep->ctrl ? ep->ctrl->cntlid : -1;
	struct nvme_completion resp;

	print_info("ctrl %d qid %d tag %#x ccid %#x handle qe res %d",
		   cntlid, ep->qid, tag, ccid, res);
	if (qe->opcode != nvme_cmd_write &&
	    qe->opcode != nvme_cmd_read) {
		print_err("ctrl %d qid %d tag %#x unhandled opcode %d",
			  cntlid, ep->qid, qe->tag, qe->opcode);
		ret = NVME_SC_INVALID_OPCODE;
		goto out_rsp;
	}
	if (res < 0) {
		if (res != -EAGAIN)
			return res;
		print_info("ctrl %d qid %d tag %#x retry",
			   cntlid, ep->qid, qe->tag);
		if (qe->opcode == nvme_cmd_write)
			ret = uring_submit_read(ep, qe->tag);
		else
			ret = uring_submit_write(ep, qe->tag);
		goto out_rsp;
	}
	if (qe->opcode == nvme_cmd_read) {
		ret = ep->ops->rma_write(ep, qe->iovec.iov_base,
					 qe->pos, qe->iovec.iov_len,
					 qe->ccid, true);
	} else if (res != qe->iovec.iov_len) {
		qe->pos += res;
		qe->iovec.iov_base += res;
		qe->iovec.iov_len -= res;
		ret = uring_submit_read(ep, qe->tag);
	}
out_rsp:
	if (ret < 0)
		return ret;
	ep->ops->release_tag(ep, tag);
	memset(&resp, 0, sizeof(resp));
	if (ret)
		resp.status = (NVME_SC_DNR | ret) << 1;
	return ep->ops->send_rsp(ep, ccid, &resp);
}

static struct ns_ops uring_ops = {
	.ns_read = uring_submit_read,
	.ns_write = uring_submit_write,
	.ns_handle_qe = uring_handle_qe,
};

struct ns_ops *uring_register_ops(void)
{
	return &uring_ops;
}
