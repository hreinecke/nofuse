#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_ops {
	int (*create_endpoint)(struct endpoint *ep, int id);
	void (*destroy_endpoint)(struct endpoint *ep);
	int (*init_listener)(int port);
	void (*destroy_listener)(struct host_iface *iface);
	int (*wait_for_connection)(struct host_iface *iface);
	int (*accept_connection)(struct endpoint *ep);
	int (*rma_read)(struct endpoint *ep, void *buf, u64 len);
	int (*rma_write)(struct endpoint *ep, void *buf, u32 offset, u32 len,
			 u16 cid, bool last);
	int (*prep_rma_read)(struct endpoint *ep, u16 cid, u16 ttag,
			     u32 offset, u32 len);
	int (*send_rsp)(struct endpoint *ep, u16 command_id, void *msg, int len);
	int (*poll_for_msg)(struct endpoint *ep, void **msg, int *bytes);
	int (*handle_msg)(struct endpoint *ep, void *msg, int bytes);
};

struct xp_ops *tcp_register_ops(void);

struct ns_ops {
	int (*ns_read)(struct endpoint *ep, struct nsdev *ns, u64 offset, u64 len);
	int (*ns_write)(struct endpoint *ep, struct nsdev *ns, u64 offset, u64 len, u16 tag);
};

struct ns_ops *null_register_ops(void);

#endif /* __OPS_H__ */
