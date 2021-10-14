#ifndef __OPS_H__
#define __OPS_H__

#include <sys/socket.h>

struct xp_ep {
	struct sockaddr_in	*sock_addr;
	struct xp_qe		*qe;
	int			 sockfd;
	int			 state;
	__u64			 depth;
};

struct xp_pep {
	struct sockaddr_in	*sock_addr;
	int			 listenfd;
	int			 sockfd;
};

struct xp_ops {
	int (*create_endpoint)(struct xp_ep **ep, void *id);
	void (*destroy_endpoint)(struct xp_ep *ep);
	int (*init_listener)(struct xp_pep **pep, int port);
	void (*destroy_listener)(struct xp_pep *pep);
	int (*wait_for_connection)(struct xp_pep *pep, void **id);
	int (*accept_connection)(struct xp_ep *ep);
	int (*rma_read)(struct xp_ep *ep, void *buf, u64 len);
	int (*rma_write)(struct xp_ep *ep, void *buf, u64 len,
			 struct nvme_command *cmd, bool last);
	int (*prep_rma_read)(struct xp_ep *ep, u16 ttag,
			     u32 offset, u32 len);
	int (*send_rsp)(struct xp_ep *ep, void *msg, int len);
	int (*poll_for_msg)(struct xp_ep *ep, void **msg, int *bytes);
	int (*handle_msg)(struct endpoint *ep, void *msg, int bytes);
};

struct xp_ops *tcp_register_ops(void);

#endif /* __OPS_H__ */
