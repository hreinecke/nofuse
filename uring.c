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

static int uring_handle_cqe(struct endpoint *ep, struct io_uring_cqe *cqe)
{
	struct ep_qe *qe;
	
	qe = io_uring_cqe_get_data(cqe);
	if (!qe) {
		print_err("ctrl %d qid %d empty cqe",
			  ep->ctrl->cntlid, ep->qid);
		return 0;
	}
	print_info("ctrl %d qid %d got cqe",
		   ep->ctrl->cntlid, ep->qid);
	if (qe->opcode != nvme_cmd_write &&
	    qe->opcode != nvme_cmd_read) {
		print_err("ctrl %d qid %d unhandled opcode %d\n",
			  ep->ctrl->cntlid, ep->qid,
			  qe->opcode);
		return NVME_SC_INVALID_OPCODE;
	}
	if (cqe->res < 0) {
		if (cqe->res != -EAGAIN)
			return cqe->res;
		print_info("ctrl %d qid %d retry",
			   ep->ctrl->cntlid, ep->qid);
		if (qe->opcode == nvme_cmd_write)
			return uring_submit_read(ep, qe->tag);
		else
			return uring_submit_write(ep, qe->tag);
	}
	if (qe->opcode == nvme_cmd_read)
		return ep->ops->rma_write(ep, qe->iovec.iov_base,
					  qe->pos, qe->iovec.iov_len,
					  qe->ccid, true);
	if ((size_t)cqe->res != qe->iovec.iov_len) {
		qe->pos += cqe->res;
		qe->iovec.iov_base += cqe->res;
		qe->iovec.iov_len -= cqe->res;
		return uring_submit_read(ep, qe->tag);
	}
	return 0;
}

static struct ns_ops uring_ops = {
	.ns_read = uring_submit_read,
	.ns_write = uring_submit_write,
	.ns_handle_cqe = uring_handle_cqe,
};

struct ns_ops *uring_register_ops(void)
{
	return &uring_ops;
}
