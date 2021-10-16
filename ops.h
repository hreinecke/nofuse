#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_pep {
	struct sockaddr_in	*sock_addr;
	int			 listenfd;
};

struct xp_ops {
	int (*create_endpoint)(struct endpoint *ep, int id);
	void (*destroy_endpoint)(struct endpoint *ep);
	int (*init_listener)(struct xp_pep **pep, int port);
	void (*destroy_listener)(struct xp_pep *pep);
	int (*wait_for_connection)(struct xp_pep *pep);
	int (*accept_connection)(struct endpoint *ep);
	int (*rma_read)(struct endpoint *ep, void *buf, u64 len);
	int (*rma_write)(struct endpoint *ep, void *buf, u64 len,
			 struct nvme_command *cmd, bool last);
	int (*prep_rma_read)(struct endpoint *ep, u16 cmdid, u16 ttag,
			     u32 offset, u32 len);
	int (*send_rsp)(struct endpoint *ep, void *msg, int len);
	int (*poll_for_msg)(struct endpoint *ep, void **msg, int *bytes);
	int (*handle_msg)(struct endpoint *ep, void *msg, int bytes);
};

struct xp_ops *tcp_register_ops(void);

#endif /* __OPS_H__ */
