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

static void tcp_destroy_endpoint(struct endpoint *ep)
{
	free(ep->pdu);
	ep->pdu = NULL;
	close(ep->sockfd);
	ep->sockfd = -1;
}

static int tcp_create_endpoint(struct endpoint *ep, int id)
{
	int flags;

	ep->sockfd = id;

	flags = fcntl(ep->sockfd, F_GETFL);
	fcntl(ep->sockfd, F_SETFL, flags | O_NONBLOCK);

	ep->pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->pdu) {
		print_err("no memory");
		return -ENOMEM;
	}

	return 0;
}

static int tcp_init_listener(int port)
{
	struct sockaddr_in addr;
	int listenfd;
	int ret;

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
		ret = -errno;
		goto err;
	}

	ret = listen(listenfd, BACKLOG);
	if (ret < 0) {
		print_err("Socket listen error %d", errno);
		ret = -errno;
		goto err;
	}

	return listenfd;
err:
	close(listenfd);
	return ret;
}

static int tcp_accept_connection(struct endpoint *ep)
{
	struct nvme_tcp_icreq_pdu *icreq = NULL;
	struct nvme_tcp_icresp_pdu *icrep;
	int ret, len, hdr_len;

	if (!ep)
		return -EINVAL;

	icreq = malloc(sizeof(*icreq));
	if (!icreq)
		return -ENOMEM;

	memset(icreq, 0, sizeof(*icreq));

	hdr_len = sizeof(struct nvme_tcp_hdr);
	ret = read(ep->sockfd, icreq, hdr_len);
	if (ret < 0) {
		print_errno("icreq header read", errno);
		return -errno;
	}
	if (ret != hdr_len) {
		print_err("icreq short header read, %d bytes missing",
			  hdr_len - ret);
		ret = (ret < 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}

	if (icreq->hdr.type == 0) {
		len = icreq->hdr.hlen - hdr_len;
		ret = read(ep->sockfd, (u8 *)icreq + hdr_len, len);
		if (ret != len) {
			print_err("icreq short read, %d bytes missing",
				  len - ret);
			ret = -ENODATA;
			goto out_free;
		}
		if (icreq->hpda != 0) {
			ret = -EPROTO;
			goto out_free;
		}
		ep->maxr2t = le32toh(icreq->maxr2t) + 1;
	}

	icrep = malloc(sizeof(*icrep));
	if (!icrep) {
		ret = -ENOMEM;
		goto out_free;
	}

	memset(icrep, 0, sizeof(*icrep));
	icrep->hdr.type = nvme_tcp_icresp;
	icrep->hdr.hlen = sizeof(*icrep);
	icrep->hdr.pdo = 0;
	icrep->hdr.plen = htole32(sizeof(*icrep));
	icrep->pfv = htole16(NVME_TCP_PFV_1_0);
	icrep->maxdata = 0xffff;
	icrep->cpda = 0;
	icrep->digest = 0;

	len = write(ep->sockfd, icrep, sizeof(*icrep));
	if (len != sizeof(*icrep)) {
		print_err("icrep short read, %ld bytes missing",
			  sizeof(*icrep) - len);
		ret = -ENODATA;
	} else
		ret = 0;

	free(icrep);
out_free:
	free(icreq);
	return ret;
}

static int tcp_wait_for_connection(struct host_iface *iface)
{
	int sockfd;
	int ret = -ESHUTDOWN;

	while (true) {
		usleep(100); //TBD
		if (stopped)
			break;

		sockfd = accept(iface->listenfd, (struct sockaddr *) NULL,
				NULL);
		if (sockfd < 0) {
			if (errno != EAGAIN)
				print_errno("failed to accept",
					    errno);
			return -EAGAIN;
		}

		return sockfd;
	}

	return ret;
}

static void tcp_destroy_listener(struct host_iface *iface)
{
	close(iface->listenfd);
	iface->listenfd = -1;
}

static int tcp_rma_read(struct endpoint *ep, void *buf, u64 _len)
{
	int			 len;

	len = read(ep->sockfd, buf, _len);
	if (len < 0) {
		print_err("read returned %d", errno);
		return -errno;
	}
	if (len != _len) {
		print_err("short read, %llu bytes missing",
			  _len - len);
	}
	return 0;
}

static int tcp_rma_write(struct endpoint *ep, void *buf, u32 _offset, u32 _len,
			 u16 cid, bool last)
{
	int len;
	struct nvme_tcp_data_pdu *pdu = &ep->pdu->data;

	print_info("ctrl %d qid %d write cid %u offset %u len %u",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   cid, _offset, _len);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_c2h_data;
	pdu->hdr.flags = last ? NVME_TCP_F_DATA_LAST : 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_data_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_data_pdu) + _len);
	pdu->data_offset = htole32(_offset);
	pdu->data_length = htole32(_len);
	pdu->command_id = cid;

	len = write(ep->sockfd, pdu, sizeof(struct nvme_tcp_data_pdu));
	if (len < 0) {
		print_err("header write returned %d", errno);
		return -errno;
	}
	if (len != sizeof(struct nvme_tcp_data_pdu)) {
		print_err("short header write, %d bytes missing",
			  (int)sizeof(pdu) - len);
		return -EAGAIN;
	}

	len = write(ep->sockfd, buf, _len);
	if (len < 0) {
		print_err("data write returned %d", errno);
		return -errno;
	}
	if (len != _len) {
		print_err("short data write, %d bytes missing",
			  (int)_len - len);
		return -EAGAIN;
	}

	return 0;
}

static int tcp_send_r2t(struct endpoint *ep, u16 cid, u16 ttag,
			u32 _offset, u32 _len)
{
	struct nvme_tcp_r2t_pdu *pdu = &ep->pdu->r2t;
	int len;

	print_info("ctrl %d qid %d r2t cid %u ttag %u offset %u len %u",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   cid, ttag, _offset, _len);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_r2t;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_r2t_pdu));
	pdu->ttag = ttag;
	pdu->command_id = cid;
	pdu->r2t_offset = htole32(_offset);
	pdu->r2t_length = htole32(_len);

	len = write(ep->sockfd, pdu, sizeof(*pdu));
	if (len < 0) {
		print_err("r2t write returned %d", errno);
		return -errno;
	}
	if (len < sizeof(*pdu)) {
		print_err("short r2t write, %d bytes missing",
			  (int)sizeof(*pdu) - len);
		return -EAGAIN;
	}
	return 0;
}

static int tcp_send_c2h_term(struct endpoint *ep, u16 fes, u8 pdu_offset,
			     u8 parm_offset, bool hdr_digest,
			     union nvme_tcp_pdu *pdu, int pdu_len)
{
	struct nvme_tcp_term_pdu *term_pdu = (struct nvme_tcp_term_pdu *)&ep->pdu->data;
	int len, plen;

	print_info("ctrl %d qid %d c2h term fes %u offset pdu %u parm %u",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   fes, pdu_offset, parm_offset);

	if (!pdu)
		pdu_len = 0;
	if (pdu_len > 152 - sizeof(struct nvme_tcp_term_pdu))
		pdu_len = 152 - sizeof(struct nvme_tcp_term_pdu);
	plen = sizeof(struct nvme_tcp_term_pdu) + pdu_len;
	term_pdu->hdr.type = nvme_tcp_c2h_term;
	term_pdu->hdr.flags = 0;
	term_pdu->hdr.pdo = 0;
	term_pdu->hdr.hlen = sizeof(struct nvme_tcp_term_pdu);
	term_pdu->hdr.plen = htole32(plen);
	term_pdu->fes = htole16(fes);
	term_pdu->fei = htole32(parm_offset << 6 | pdu_offset << 1);

	len = write(ep->sockfd, term_pdu, sizeof(*term_pdu));
	if (len < 0) {
		print_err("c2h_term write returned %d", errno);
		return -errno;
	}
	if (len != sizeof(*term_pdu)) {
		print_err("c2h_term short write; %d bytes missing",
			  plen - len);
		return -EAGAIN;
	}
	if (pdu) {
		len = write(ep->sockfd, pdu, pdu_len);
		if (len < 0) {
			print_err("c2h term pdu write returned %d", errno);
			return -errno;
		}
		if (len != pdu_len) {
			print_err("c2h term short write; %d bytes missing",
				  pdu_len - len);
			return -EAGAIN;
		}
	}
	return 0;
}

static int tcp_send_rsp(struct endpoint *ep, u16 command_id, void *msg, int _len)
{
	struct nvme_completion *comp = (struct nvme_completion *)msg;
	struct nvme_tcp_rsp_pdu *pdu = &ep->pdu->rsp;
	int len;

	print_info("ctrl %d qid %d rsp tag %04x status %04x",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   command_id, comp->status);

	pdu->hdr.type = nvme_tcp_rsp;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_rsp_pdu);
	pdu->hdr.plen = sizeof(struct nvme_tcp_rsp_pdu);

	memcpy(&(pdu->cqe), comp, sizeof(struct nvme_completion));

	len = write(ep->sockfd, pdu, sizeof(*pdu));
	if (len != sizeof(*pdu)) {
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
	struct nvme_completion resp;

	print_info("ctrl %d qid %d h2c data tag %04x pos %u len %u",
		   ep->ctrl->cntlid, ep->qid, ttag, data_offset, data_len);
	if (ttag != ep->data_tag) {
		print_err("ctrl %d qid %d h2c ttag mismatch, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid, ttag, ep->data_tag);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
				offset_of(struct nvme_tcp_data_pdu, ttag),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_offset != ep->data_offset) {
		print_err("ctrl %d qid %d h2c offset mismatch, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid,
			  data_offset, ep->data_offset);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offset_of(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_len > ep->data_expected) {
		print_err("ctrl %d qid %d h2c len overflow, is %u exp %u\n",
			  ep->ctrl->cntlid, ep->qid,
			  data_len, ep->data_expected);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offset_of(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}

	buf = malloc(data_len);
	if (!buf) {
		print_errno("malloc failed", errno);
		ret = NVME_SC_INTERNAL;
		goto out_rsp;
	}

	while (offset < data_len) {
		ret = tcp_rma_read(ep, buf + offset, data_len - offset);
		if (ret < 0) {
			print_err("ctrl %d qid %d h2c data read failed, error %d",
				  ep->ctrl->cntlid, ep->qid, errno);
			ret = NVME_SC_SGL_INVALID_DATA;
			goto out_rsp;
		}
		offset += ret;
	}
	free(buf);
	ep->data_expected -= data_len;
	ep->data_offset += data_len;
	if (!ep->data_expected) {
		ret = 0;
		goto out_rsp;
	}

	return tcp_send_r2t(ep, pdu->data.command_id,
			    ttag, ep->data_offset, ep->data_expected);
out_rsp:
	memset(&resp, 0, sizeof(resp));
	if (ret)
		resp.status = (NVME_SC_DNR | ret) << 1;
	return tcp_send_rsp(ep, pdu->data.command_id, &resp, sizeof(resp));
}

static int tcp_poll_for_msg(struct endpoint *ep, void **_msg, int *bytes)
{
	struct nvme_tcp_hdr hdr;
	void *msg;
	int hdr_len, msg_len;
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
	print_debug("msg hdr %u len %d hlen %d", hdr.type, len, hdr.hlen);
	hdr_len = hdr.hlen;
	if (hdr_len < sizeof(hdr)) {
#if 0
		int i;
		u8 *p = (u8 *)&hdr;

		print_err("corrupt hdr, hlen %d size %ld",
			  hdr.hlen, sizeof(hdr));
		for (i = 0; i < len; i++) {
			fprintf(stdout, "%02x ", p[i]);
		}
#endif
		ep->data_skipped += len;
		ep->countdown = ep->ctrl->kato;
		return -ETIMEDOUT;
	}

	if (ep->data_skipped) {
		print_info("%d bytes skipped", ep->data_skipped);
		ep->data_skipped = 0;
	}

	if (posix_memalign(&msg, PAGE_SIZE, hdr_len))
		return -ENOMEM;

	memcpy(msg, &hdr, sizeof(hdr));
	msg_len = hdr_len - sizeof(hdr);
	if (msg_len) {
		len = read(ep->sockfd, msg + sizeof(hdr), msg_len);
		if (len == 0)
			return -EAGAIN;
		if (len < 0) {
			print_errno("failed to read msg payload", errno);
			return -errno;
		}
		if (len != msg_len)
			print_err("short msg payload read, %d bytes missing",
				  msg_len - len);
	}
	*_msg = msg;
	*bytes = hdr_len;

	return 0;
}

int tcp_handle_msg(struct endpoint *ep, void *msg, int bytes)
{
	union nvme_tcp_pdu *pdu = msg;
	struct nvme_tcp_hdr *hdr = &pdu->common;

	if (hdr->type == nvme_tcp_h2c_data)
		return tcp_handle_h2c_data(ep, pdu);

	if (hdr->type != nvme_tcp_cmd) {
		print_err("unknown PDU type %x", hdr->type);
		return -EPROTO;
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
