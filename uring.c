#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <pthread.h>

#include "common.h"
#include "nvme.h"
#include "ops.h"

int uring_submit_write(struct endpoint *ep, struct ep_qe *qe)
{
	struct io_uring_sqe *sqe;
	int ret;

	qe->opcode = nvme_cmd_write;
	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		print_err("No SQEs available");
		return NVME_SC_QUEUE_SIZE;
	}

	io_uring_prep_writev(sqe, qe->ns->fd, &qe->iovec, 1, qe->data_pos);
	io_uring_sqe_set_data(sqe, qe);

	ret = io_uring_submit(&ep->uring);
	if (ret < 0) {
		print_err("endpoint %d tag %d: io_uring_submit error %d",
			  ep->qid, qe->tag, errno);
		return NVME_SC_INTERNAL;
	}
	
	return 0;
}

int uring_submit_read(struct endpoint *ep, struct ep_qe *qe)
{
	struct io_uring_sqe *sqe;
	int ret;

	qe->opcode = nvme_cmd_read;
	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		print_err("No SQEs available");
		return NVME_SC_QUEUE_SIZE;
	}
	io_uring_prep_readv(sqe, qe->ns->fd, &qe->iovec, 1,
			    qe->data_pos);
	io_uring_sqe_set_data(sqe, qe);

	ret = io_uring_submit(&ep->uring);
	if (ret < 0) {
		print_err("endpoint %d tag %d: io_uring_submit error %d",
			  ep->qid, qe->tag, errno);
		return NVME_SC_INTERNAL;
	}
	return 0;
}

static int uring_handle_qe(struct endpoint *ep, struct ep_qe *qe, int res)
{
	int status = 0, ret;
	u16 ccid = qe->ccid, tag = qe->tag;
	int cntlid = ep->ctrl ? ep->ctrl->cntlid : -1;

	print_info("ctrl %d qid %d tag %#x ccid %#x handle qe res %d",
		   cntlid, ep->qid, tag, ccid, res);
	if (qe->opcode != nvme_cmd_write &&
	    qe->opcode != nvme_cmd_read) {
		print_err("ctrl %d qid %d tag %#x unhandled opcode %d",
			  cntlid, ep->qid, qe->tag, qe->opcode);
		status = NVME_SC_INVALID_OPCODE;
		goto out_rsp;
	}
	if (res < 0) {
		if (res != -EAGAIN)
			return res;
		print_info("ctrl %d qid %d tag %#x retry",
			   cntlid, ep->qid, qe->tag);
		if (qe->opcode == nvme_cmd_write)
			status = uring_submit_read(ep, qe);
		else
			status = uring_submit_write(ep, qe);
		if (!status)
			return 0;
		goto out_rsp;
	}
	if (qe->opcode == nvme_cmd_read)
		return ep->ops->rma_write(ep, qe, qe->data_len);

	if (res != qe->iovec.iov_len) {
		qe->iovec.iov_base += res;
		qe->iovec.iov_len -= res;
		status = uring_submit_read(ep, qe);
		if (!status)
			return 0;
	}
out_rsp:
	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, ccid, status, true);
	ret = ep->ops->send_rsp(ep, &qe->resp);
	ep->ops->release_tag(ep, qe);
	return ret;
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
