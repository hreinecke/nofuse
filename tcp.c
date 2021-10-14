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

static int tcp_create_endpoint(struct xp_ep **_ep, int id)
{
	struct xp_ep		*ep;
	int			 flags;

	ep = malloc(sizeof(*ep));
	if (!ep)
		return -ENOMEM;

	memset(ep, 0, sizeof(*ep));

	ep->sockfd = id;

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
		ep->maxr2t = init_req->maxr2t + 1;
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

static int tcp_wait_for_connection(struct xp_pep *pep)
{
	int sockfd;
	int ret = -ESHUTDOWN;

	while (true) {
		usleep(100); //TBD
		if (stopped)
			break;

		sockfd = accept(pep->listenfd, (struct sockaddr *) NULL,
				NULL);
		if (sockfd < 0) {
			if (errno != EAGAIN)
				print_errno("failed to accept",
					    errno);
			return -EAGAIN;
		}

		pep->sockfd = sockfd;
		return sockfd;
	}

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

static int tcp_send_r2t(struct xp_ep *ep, u16 ttag,
			u32 _offset, u32 _len)
{
	struct nvme_tcp_r2t_pdu pdu;
	int len;

	pdu.hdr.type = nvme_tcp_r2t;
	pdu.hdr.flags = 0;
	pdu.hdr.pdo = 0;
	pdu.hdr.hlen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu.hdr.plen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu.ttag = ttag;
	pdu.r2t_offset = htole32(_offset);
	pdu.r2t_length = htole32(_len);
	ep->ttag = ttag;

	len = write(ep->sockfd, &pdu, sizeof(pdu));
	if (len < 0) {
		print_err("r2t write returned %d", errno);
		return -errno;
	}
	return 0;
}

static int tcp_send_c2h_term(struct xp_ep *ep, u16 fes, u8 pdu_offset,
			     u8 parm_offset, bool hdr_digest,
			     union nvme_tcp_pdu *pdu, int pdu_len)
{
	u8 raw_pdu[152];
	struct nvme_tcp_term_pdu *term_pdu =
		(struct nvme_tcp_term_pdu *)raw_pdu;
	int len;

	if (pdu_len > 152 - sizeof(struct nvme_tcp_term_pdu))
		pdu_len = 152 - sizeof(struct nvme_tcp_term_pdu);
	term_pdu->hdr.type = nvme_tcp_c2h_term;
	term_pdu->hdr.flags = 0;
	term_pdu->hdr.pdo = 0;
	term_pdu->hdr.hlen = sizeof(struct nvme_tcp_term_pdu);
	term_pdu->hdr.plen = sizeof(struct nvme_tcp_term_pdu) + pdu_len;
	term_pdu->fes = htole16(fes);
	term_pdu->fei = htole32(parm_offset << 6 | pdu_offset << 1);
	memcpy(raw_pdu + sizeof(struct nvme_tcp_term_pdu), pdu, pdu_len);

	len = write(ep->sockfd, raw_pdu, term_pdu->hdr.plen);
	if (len < 0) {
		print_err("c2h_term write returned %d", errno);
		return -errno;
	}
	if (len != term_pdu->hdr.plen) {
		print_err("c2h_term short write; %d bytes missing",
			  term_pdu->hdr.plen - len);
		return -EAGAIN;
	}
	return 0;
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

static int tcp_handle_h2c_data(struct endpoint *ep, union nvme_tcp_pdu *pdu)
{
	u16 ttag = le16toh(pdu->data.ttag);
	u32 data_offset = le32toh(pdu->data.data_offset);
	u32 data_len = le32toh(pdu->data.data_length);
	char *buf;
	int ret, offset = 0;

	print_info("ctrl %d qid %d h2c data tag %04x pos %u len %u",
		   ep->ctrl->cntlid, ep->qid, ttag, data_offset, data_len);
	if (ttag != ep->ep->ttag) {
		print_err("ctrl %d qid %d h2c ttag mismatch, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid, ttag, ep->ep->ttag);
		return tcp_send_c2h_term(ep->ep, NVME_TCP_FES_INVALID_PDU_HDR,
				offset_of(struct nvme_tcp_data_pdu, ttag),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_offset != ep->data_offset) {
		print_err("ctrl %d qid %d h2c offset mismatch, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid,
			  data_offset, ep->data_offset);
		return tcp_send_c2h_term(ep->ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offset_of(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_len > ep->data_expected) {
		print_err("ctrl %d qid %d h2c len overflow, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid,
			  data_len, ep->data_expected);
		return tcp_send_c2h_term(ep->ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offset_of(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}

	buf = malloc(data_len);
	if (!buf) {
		print_errno("malloc failed", errno);
		return NVME_SC_INTERNAL;
	}

	while (offset < data_len) {
		ret = tcp_rma_read(ep->ep, buf + offset, data_len - offset);
		if (ret < 0) {
			print_err("ctrl %d qid %d h2c data read failed, error %d",
				  ep->ctrl->cntlid, ep->qid, errno);
			return NVME_SC_SGL_INVALID_DATA;
		}
		offset += ret;
	}
	free(buf);
	ep->data_expected -= data_len;
	ep->data_offset += data_len;
	if (!ep->data_expected) {
		struct nvme_completion resp;

		memset(&resp, 0, sizeof(resp));
		tcp_send_rsp(ep->ep, &resp, sizeof(resp));
		return 0;
	}

	return tcp_send_r2t(ep->ep, ttag, ep->data_offset, ep->data_expected);
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
		if (len < 0)
			print_errno("failed to read msg hdr", errno);
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
	if (len < 0) {
		print_errno("failed to read msg payload", errno);
		return -errno;
	}
	*_msg = msg;
	*bytes = hdr.hlen;

	return 0;
}

int tcp_handle_msg(struct endpoint *ep, void *msg, int bytes)
{
	union nvme_tcp_pdu *pdu = msg;
	struct nvme_tcp_hdr *hdr = &pdu->common;
	int ret;

	if (hdr->type == nvme_tcp_h2c_data) {
		ret = tcp_handle_h2c_data(ep, pdu);
		if (!ret)
			return 0;
	}
	if (hdr->type != nvme_tcp_cmd) {
		print_err("unknown PDU type %x\n", hdr->type);
		return NVME_SC_INVALID_OPCODE;
	}

	return handle_request(ep, &pdu->cmd.cmd,
			      bytes - sizeof(struct nvme_tcp_hdr));
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
	.prep_rma_read		= tcp_send_r2t,
	.send_rsp		= tcp_send_rsp,
	.poll_for_msg		= tcp_poll_for_msg,
	.handle_msg		= tcp_handle_msg,
};

struct xp_ops *tcp_register_ops(void)
{
	return &tcp_ops;
}
