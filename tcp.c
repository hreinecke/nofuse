#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <poll.h>

#include "common.h"
#include "tcp.h"
#include "ops.h"

#define NVME_OPCODE_MASK 0x3
#define NVME_OPCODE_H2C  0x1
#define NVME_OPCODE_C2H  0x2

#define BACKLOG			16
#define RESOLVE_TIMEOUT		5000
#define EVENT_TIMEOUT		200

#define TCP_SYNCNT		7
#define TCP_NODELAY		1

struct xp_qe {
	void			*buf;
	union nvme_tcp_pdu	 pdu;
};

static void tcp_destroy_endpoint(struct xp_ep *ep)
{
	struct xp_qe		*qe = ep->qe;
	int			 i = ep->depth;

	if (qe) {
		while (i > 0)
			if (qe[--i].buf)
				free(qe[i].buf);
		free(qe);
	}

	close(ep->sockfd);

	free(ep);
}

static int tcp_create_endpoint(struct xp_ep **_ep, void *id)
{
	struct xp_ep		*ep;
	int			 flags;

	ep = malloc(sizeof(*ep));
	if (!ep)
		return -ENOMEM;

	memset(ep, 0, sizeof(*ep));

	ep->sockfd = *(int *) id;

	flags = fcntl(ep->sockfd, F_GETFL);
	fcntl(ep->sockfd, F_SETFL, flags | O_NONBLOCK);

	*_ep = (struct xp_ep *) ep;

	return 0;
}

static int tcp_init_listener(struct xp_pep **_pep, int port)
{
	struct xp_pep		*pep;
	struct sockaddr_in	 addr;
	int			 listenfd;
	int			 ret;

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	listenfd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (listenfd < 0) {
		print_err("Socket error %d", errno);
		return -errno;
	}

	ret = bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		print_err("Socket bind error %d", errno);
		goto err;
	}

	ret = listen(listenfd, BACKLOG);
	if (ret) {
		print_err("Socket listen error %d", errno);
		goto err;
	}

	pep = malloc(sizeof(*pep));
	if (!pep) {
		ret = -ENOMEM;
		goto err;
	}

	memset(pep, 0, sizeof(*pep));

	*_pep = (struct xp_pep *) pep;

	pep->listenfd = listenfd;

	return 0;
err:
	close(listenfd);
	return ret;
}

static int tcp_accept_connection(struct xp_ep *ep)
{
	struct nvme_tcp_icreq_pdu *init_req = NULL;
	struct nvme_tcp_icresp_pdu *init_rep;
	struct nvme_tcp_hdr *hdr;
	unsigned int digest = 0;
	int ret, len;

	if (!ep)
		return -EINVAL;

	hdr = malloc(sizeof(*hdr));
	if (!hdr)
		return -ENOMEM;

	memset(hdr, 0, sizeof(*hdr));

	len = sizeof(*hdr);
	ret = read(ep->sockfd, hdr, len);
	if (ret != sizeof(*hdr)) {
		ret = (ret < 0) ? -EAGAIN : -ENODATA;
		goto err1;
	}

	if (hdr->type == 0) {
		if (posix_memalign((void **) &init_req, PAGE_SIZE,
					sizeof(*init_req))) {
			ret = -ENOMEM;
			goto err1;
		}
		len = sizeof(*init_req)-sizeof(*hdr);
		ret = read(ep->sockfd, init_req, len);
		if (ret != len) {
			ret = -ENODATA;
			goto err2;
		}
		if (init_req->hpda != 0) {
			ret = -EPROTO;
			goto err2;
		}
	}

	if (posix_memalign((void **) &init_rep, PAGE_SIZE,
				sizeof(*init_rep))) {
		ret = -ENOMEM;
		goto err2;
	}

	init_rep->hdr.type = nvme_tcp_icresp;
	init_rep->hdr.hlen = sizeof(*init_rep);
	init_rep->hdr.pdo = 0;
	init_rep->hdr.plen = htole32(sizeof(*init_rep));
	init_rep->pfv = htole16(NVME_TCP_PFV_1_0);
	init_rep->maxdata = 0xffff;
	init_rep->cpda = 0;
	digest = 0;
	init_rep->digest = htole16(digest);

	ret = write(ep->sockfd, init_rep, sizeof(*init_rep));
	if (ret < 0)
		goto err3;

	return 0;
err3:
	free(init_rep);
err2:
	if (init_req)
		free(init_req);
err1:
	free(hdr);
	return ret;
}

static int tcp_wait_for_connection(struct xp_pep *pep, void **_id)
{
	int			 sockfd;
	int			*id;
	int			 ret;

	id = malloc(sizeof(int));
	if (!id)
		return -ENOMEM;

	while (true) {
		usleep(100); //TBD
		if (stopped) {
			ret = -ESHUTDOWN;
			goto err;
		}

		sockfd = accept(pep->listenfd, (struct sockaddr *) NULL,
				NULL);
		if (sockfd < 0) {
			if (errno != EAGAIN)
				print_err("failed to accept err=%d\n",
						sockfd);
			ret = -EAGAIN;
			goto err;
		}

		pep->sockfd = sockfd;
		*id = sockfd;
		*_id = id;
		return 0;
	}
err:
	free(id);
	return ret;
}

static void tcp_destroy_listener(struct xp_pep *pep)
{
	close(pep->listenfd);
	pep->listenfd = -1;
	free(pep->sock_addr);
}

static int tcp_rma_read(struct xp_ep *ep, void *buf, u64 _len)
{
	int			 len;

	len = read(ep->sockfd, buf, _len);
	if (len < 0) {
		print_err("read returned %d", errno);
		return -errno;
	}

	return 0;
}

static int tcp_rma_write(struct xp_ep *ep, void *buf, u64 _len,
			 struct nvme_command *cmd, bool last)
{
	struct nvme_tcp_data_pdu pdu;
	int			 len;

	pdu.hdr.type = nvme_tcp_c2h_data;
	pdu.hdr.flags = last ? NVME_TCP_F_DATA_LAST : 0;
	pdu.hdr.pdo = 0;
	pdu.hdr.hlen = sizeof(struct nvme_tcp_data_pdu);
	pdu.hdr.plen = sizeof(struct nvme_tcp_data_pdu) + _len;
	pdu.data_offset = 0;
	pdu.data_length = _len;
	pdu.command_id = cmd->common.command_id;

	len = write(ep->sockfd, &pdu, sizeof(pdu));
	if (len < 0) {
		print_err("header write returned %d", errno);
		return -errno;
	}

	len = write(ep->sockfd, buf, _len);
	if (len < 0) {
		print_err("data write returned %d", errno);
		return -errno;
	}

	return 0;
}

static int tcp_inline_write(size_t sockfd, void *data, size_t _len)
{
	int			 len;

	len = write(sockfd, (const void *) data, _len);
	if (len < 0) {
		print_err("data write returned %d", errno);
		return -errno;
	}

	return 0;
}

static int tcp_inline_read(size_t sockfd, void *data, size_t _len)
{
	struct nvme_tcp_data_pdu d_pdu;
	int			 len;

	UNUSED(_len);

	len = read(sockfd, &d_pdu, sizeof(d_pdu));
	if (len != sizeof(d_pdu)) {
		print_err("header read returned %d", errno);
		return (len < 0) ? -errno : -ENODATA;
	}

	while (d_pdu.data_length > 0) {
		len = read(sockfd, (char *) data + d_pdu.data_offset,
			   d_pdu.data_length);
		if (len < 0) {
			if (errno == EAGAIN)
				continue;

			print_err("data read returned %d", errno);
			return -errno;
		}

		d_pdu.data_length -= len;
		d_pdu.data_offset += len;
	}

	return 0;
}

static inline int tcp_handle_inline_data(struct xp_ep *ep,
					struct nvme_command *cmd)
{
	struct nvme_sgl_desc	*sg = &cmd->common.dptr.sgl;
	char			*data = (char *)sg->addr;
	int			 length = sg->length;
	int			 direction;
	int			 ret;

	if (cmd->common.opcode == nvme_fabrics_command)
		direction = cmd->fabrics.fctype & NVME_OPCODE_MASK;
	else
		direction = cmd->common.opcode & NVME_OPCODE_MASK;

	if (direction == NVME_OPCODE_H2C)
		ret = tcp_inline_write(ep->sockfd, data, length);
	else if (direction == NVME_OPCODE_C2H)
		ret = tcp_inline_read(ep->sockfd, data, length);
	else
		ret = 0;

	return ret;
}

static int tcp_send_rsp(struct xp_ep *ep, void *msg, int _len)
{
	struct nvme_completion *comp = (struct nvme_completion *)msg;
	struct nvme_tcp_rsp_pdu pdu;
	int len;

	UNUSED(msg);
	UNUSED(_len);

	pdu.hdr.type = nvme_tcp_rsp;
	pdu.hdr.flags = 0;
	pdu.hdr.pdo = 0;
	pdu.hdr.hlen = sizeof(struct nvme_tcp_rsp_pdu);
	pdu.hdr.plen = sizeof(struct nvme_tcp_rsp_pdu);

	memcpy(&(pdu.cqe), comp, sizeof(struct nvme_completion));

	len = write(ep->sockfd, &pdu, sizeof(pdu));
	if (len != sizeof(pdu)) {
		print_err("write completion returned %d", errno);
		return -errno;
	}

	return 0;
}

static int tcp_poll_for_msg(struct xp_ep *ep, void **_msg, int *bytes)
{
	struct nvme_tcp_hdr hdr;
	void *msg;
	int msg_len;
	int ret, len;
	struct pollfd fds;

	fds.fd = ep->sockfd;
	fds.events = POLLIN | POLLERR;

	ret = poll(&fds, 1, 100);
	if (ret <= 0) {
		if (ret == 0)
			return -ETIMEDOUT;
		return -errno;
	}
	len = read(ep->sockfd, &hdr, sizeof(hdr));
	if (len != sizeof(hdr)) {
		return (len < 0) ? -errno : -ENODATA;
	}

	msg_len = hdr.hlen - sizeof(hdr);
	if (msg_len <= 0)
		return msg_len;

	if (posix_memalign(&msg, PAGE_SIZE, hdr.hlen))
		return -ENOMEM;

	memcpy(msg, &hdr, msg_len);
	len = read(ep->sockfd, msg + sizeof(hdr), msg_len);
	if (len == 0)
		return -EAGAIN;
	if (len < 0)
		return -errno;
	*_msg = msg;
	*bytes = hdr.hlen;

	return 0;
}

static void tcp_set_sgl(struct nvme_command *cmd, u8 opcode, int len,
			void *data)
{
	struct nvme_sgl_desc	*sg;

	memset(cmd, 0, sizeof(*cmd));

	cmd->common.flags = NVME_CMD_SGL_METABUF;
	cmd->common.opcode = opcode;

	sg = &cmd->common.dptr.sgl;
	sg->length = htole32(len);

	if (opcode == nvme_admin_get_log_page)
		sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) |
			   NVME_SGL_FMT_TRANSPORT_A;
	else
		sg->type = (NVME_SGL_FMT_DATA_DESC << 4) |
			   NVME_SGL_FMT_OFFSET;

	sg->addr = (u64) data;
}

static struct xp_ops tcp_ops = {
	.create_endpoint	= tcp_create_endpoint,
	.destroy_endpoint	= tcp_destroy_endpoint,
	.init_listener		= tcp_init_listener,
	.destroy_listener	= tcp_destroy_listener,
	.wait_for_connection	= tcp_wait_for_connection,
	.accept_connection	= tcp_accept_connection,
	.rma_read		= tcp_rma_read,
	.rma_write		= tcp_rma_write,
	.send_rsp		= tcp_send_rsp,
	.poll_for_msg		= tcp_poll_for_msg,
	.set_sgl		= tcp_set_sgl,
};

struct xp_ops *tcp_register_ops(void)
{
	return &tcp_ops;
}
