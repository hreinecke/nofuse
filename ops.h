/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * ops.h
 * Callback function definitions
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_ops {
	int (*create_queue)(struct nofuse_queue *ep, int id);
	void (*destroy_queue)(struct nofuse_queue *ep);
	int (*init_listener)(struct nofuse_port *port);
	void (*destroy_listener)(struct nofuse_port *port);
	int (*wait_for_connection)(struct nofuse_port *port);
	int (*accept_connection)(struct nofuse_queue *ep);
	struct ep_qe *(*acquire_tag)(struct nofuse_queue *ep,
				     union nvme_tcp_pdu *pdu,
				     u16 ccid, u64 pos, u64 len);
	struct ep_qe *(*get_tag)(struct nofuse_queue *ep, u16 tag);
	struct ep_qe *(*get_aen)(struct nofuse_queue *ep);
	void (*release_tag)(struct nofuse_queue *ep, struct ep_qe *qe);
	int (*rma_read)(struct nofuse_queue *ep, void *buf, u64 len);
	int (*rma_write)(struct nofuse_queue *ep, struct ep_qe *qe, u64 len);
	int (*prep_rma_read)(struct nofuse_queue *ep, u16 ttag);
	int (*send_rsp)(struct nofuse_queue *ep, struct nvme_completion *comp);
	int (*read_msg)(struct nofuse_queue *ep);
	int (*handle_msg)(struct nofuse_queue *ep);
	int (*handle_aen)(struct nofuse_queue *ep, struct ep_qe *qe);
};

struct xp_ops *tcp_register_ops(void);

struct ns_ops {
	int (*ns_read)(struct nofuse_queue *ep, struct ep_qe *qe);
	int (*ns_write)(struct nofuse_queue *ep, struct ep_qe *qe);
	int (*ns_prep_read)(struct nofuse_queue *ep, struct ep_qe *qe);
	int (*ns_handle_qe)(struct nofuse_queue *ep, struct ep_qe *qe, int res);
};

struct io_ops {
	int (*io_read)(struct nofuse_queue *ep, void *buf, size_t buf_len);
	int (*io_write)(struct nofuse_queue *ep, void *buf, size_t buf_len);
};

struct ns_ops *null_register_ops(void);
struct ns_ops *uring_register_ops(void);

struct io_ops *tcp_register_io_ops(void);

#endif /* __OPS_H__ */
