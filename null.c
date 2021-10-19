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

int null_ns_read(struct endpoint *ep, struct nsdev *ns, u16 tag, u16 ccid)
{
	struct ep_qe *qe;
	u8 *buf;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("ns %d: invalid tag %u", ns->nsid, tag);
		return NVME_SC_NS_NOT_READY;
	}

	buf = malloc(qe->len);
	if (!buf) {
		ep->ops->release_tag(ep, tag);
		return NVME_SC_NS_NOT_READY;
	}

	ret = ep->ops->rma_read(ep, buf, qe->len);
	if (ret < 0) {
		print_errno("rma_read failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	free(buf);
	ep->ops->release_tag(ep, tag);
	return ret;
}

int null_ns_write(struct endpoint *ep, struct nsdev *ns, u16 tag, u16 ccid)
{
	struct ep_qe *qe;
	u8 *buf;
	int ret;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("ns %d: invalid tag %u", ns->nsid, tag);
		return NVME_SC_NS_NOT_READY;
	}

	buf = malloc(qe->len);
	if (!buf) {
		ep->ops->release_tag(ep, tag);
		return NVME_SC_NS_NOT_READY;
	}

	ret = ep->ops->rma_write(ep, buf, 0, qe->len, ccid, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	free(buf);
	ep->ops->release_tag(ep, tag);
	return ret;
}

int null_ns_prep_read(struct endpoint *ep, struct nsdev *ns, u16 tag, u16 ccid)
{
	struct ep_qe *qe = NULL;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		print_err("ns %d: invalid tag %u", ns->nsid, tag);
		return NVME_SC_NS_NOT_READY;
	}

	return ep->ops->prep_rma_read(ep, ccid, tag);
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

	
