#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_ops {
	int (*create_endpoint)(struct endpoint *ep, int id);
	void (*destroy_endpoint)(struct endpoint *ep);
	int (*init_listener)(struct host_iface *iface);
	void (*destroy_listener)(struct host_iface *iface);
	int (*wait_for_connection)(struct host_iface *iface);
	int (*accept_connection)(struct endpoint *ep);
	struct ep_qe *(*acquire_tag)(struct endpoint *ep,
				     union nvme_tcp_pdu *pdu,
				     u16 ccid, u64 pos, u64 len);
	struct ep_qe *(*get_tag)(struct endpoint *ep, u16 tag);
	void (*release_tag)(struct endpoint *ep, struct ep_qe *qe);
	int (*rma_read)(struct endpoint *ep, void *buf, u64 len);
	int (*rma_write)(struct endpoint *ep, void *buf, u32 offset, u32 len,
			 u16 cid, bool last);
	int (*prep_rma_read)(struct endpoint *ep, u16 ttag);
	int (*send_rsp)(struct endpoint *ep, struct nvme_completion *comp);
	int (*read_msg)(struct endpoint *ep);
	int (*handle_msg)(struct endpoint *ep);
};

struct xp_ops *tcp_register_ops(void);

struct ns_ops {
	int (*ns_read)(struct endpoint *ep, struct ep_qe *qe);
	int (*ns_write)(struct endpoint *ep, struct ep_qe *qe);
	int (*ns_prep_read)(struct endpoint *ep, struct ep_qe *qe);
	int (*ns_handle_qe)(struct endpoint *ep, struct ep_qe *qe, int res);
};

struct ns_ops *null_register_ops(void);
struct ns_ops *uring_register_ops(void);

#endif /* __OPS_H__ */
