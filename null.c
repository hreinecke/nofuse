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

int null_ns_read(struct endpoint *ep, struct nsdev *ns, u64 pos, u64 len)
{
	u8 *buf;
	int ret;
	
	buf = malloc(len);
	if (!buf)
		return NVME_SC_NS_NOT_READY;

	ret = ep->ops->rma_read(ep, buf, len);
	if (ret < 0) {
		print_errno("rma_read failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	free(buf);
	return ret;
}

int null_ns_write(struct endpoint *ep, struct nsdev *ns, u64 offset, u64 len, u16 tag)
{
	u8 *buf;
	int ret;

	buf = malloc(len);
	if (!buf)
		return NVME_SC_NS_NOT_READY;

	ret = ep->ops->rma_write(ep, buf, 0, len, tag, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	free(buf);
	return ret;
}

static struct ns_ops null_ops = {
	.ns_read = null_ns_read,
	.ns_write = null_ns_write,
};

struct ns_ops *null_register_ops(void)
{
	return &null_ops;
}

	
