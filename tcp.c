/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * tcp.c
 * NVMe-over-fabrics TCP transport protocol handling.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common.h"
#include "tcp.h"
#include "ops.h"
#include "configdb.h"
#include "tls.h"

#define NVME_OPCODE_MASK 0x3
#define NVME_OPCODE_H2C  0x1
#define NVME_OPCODE_C2H  0x2

#define BACKLOG			16
#define RESOLVE_TIMEOUT		5000
#define EVENT_TIMEOUT		200

#define TCP_SYNCNT		7
#define TCP_NODELAY		1

#define tcp_info(e, f, x...)					\
	if (tcp_debug) {					\
		printf("ctrl %d qid %d: " f "\n",		\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stdout);					\
	}

#define tcp_err(e, f, x...)					\
	do {							\
		fprintf(stderr, "ctrl %d qid %d: " f "\n",	\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stderr);					\
	} while (0)

static int tcp_ep_read(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return read(ep->sockfd, buf, buf_len);
}

static int tcp_ep_write(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return write(ep->sockfd, buf, buf_len);
}

static struct io_ops tcp_io_ops = {
	.io_read = tcp_ep_read,
	.io_write = tcp_ep_write,
};

struct io_ops *tcp_register_io_ops(void)
{
	return &tcp_io_ops;
}

static int tcp_create_queue(struct nofuse_queue *ep, int conn)
{
	int flags, i;

	ep->sockfd = conn;

	flags = fcntl(ep->sockfd, F_GETFL);
	fcntl(ep->sockfd, F_SETFL, flags | O_NONBLOCK);

	ep->send_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->send_pdu) {
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}
	memset(ep->send_pdu, 0, sizeof(union nvme_tcp_pdu));

	ep->recv_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->recv_pdu) {
		free(ep->send_pdu);
		ep->send_pdu = NULL;
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}
	memset(ep->recv_pdu, 0, sizeof(union nvme_tcp_pdu));

	ep->qes = calloc(NVMF_SQ_DEPTH, sizeof(struct ep_qe));
	if (!ep->qes) {
		free(ep->recv_pdu);
		ep->recv_pdu = NULL;
		free(ep->send_pdu);
		ep->send_pdu = NULL;
		return -ENOMEM;
	}
	ep->qsize = NVMF_SQ_DEPTH;
	for (i = 0; i < ep->qsize; i++) {
		ep->qes[i].tag = i;
		ep->qes[i].ep = ep;
	}
	return 0;
}

static void tcp_destroy_queue(struct nofuse_queue *ep)
{
	if (ep->qes) {
		int i;

		for (i = 0; i < ep->qsize; i++) {
			struct ep_qe *qe = &ep->qes[i];

			if (!qe->busy)
				continue;
			qe->busy = false;
			if (qe->data)
				free(qe->data);
		}
		free(ep->qes);
		ep->qes = NULL;
	}
	if (ep->recv_pdu) {
		free(ep->recv_pdu);
		ep->recv_pdu = NULL;
	}
	if (ep->send_pdu) {
		free(ep->send_pdu);
		ep->send_pdu = NULL;
	}
	tls_free_queue(ep);
	if (ep->sockfd >= 0) {
		close(ep->sockfd);
		ep->sockfd = -1;
	}
}

struct ep_qe *tcp_acquire_tag(struct nofuse_queue *ep, union nvme_tcp_pdu *pdu,
			      u16 ccid, u64 pos, u64 len)
{
	int i;

	for (i = 0; i < ep->qsize; i++) {
		struct ep_qe *qe = &ep->qes[i];

		if (!qe->busy) {
			qe->busy = true;
			qe->ccid = ccid;
			if (len) {
				qe->data = malloc(len);
				if (!qe->data) {
					tcp_err(ep,
						"Error allocating iovec base");
					return NULL;
				}
				memset(qe->data, 0, len);
				qe->data_pos = pos;
				qe->data_len = len;
				qe->iovec.iov_base = NULL;
				qe->iovec.iov_len = 0;
				qe->iovec_offset = 0;
				qe->data_remaining = 0;
			}
			memcpy(&qe->pdu, pdu,
			       sizeof(union nvme_tcp_pdu));
			memset(&qe->resp, 0, sizeof(qe->resp));
			qe->resp.command_id = 0xffff;
			tcp_info(ep, "acquire tag %#x", qe->tag);
			return qe;
		}
	}
	return NULL;
}

struct ep_qe *tcp_get_tag(struct nofuse_queue *ep, u16 tag)
{
	if (tag >= ep->qsize || !ep->qes[tag].busy)
		return NULL;
	return &ep->qes[tag];
}

void tcp_release_tag(struct nofuse_queue *ep, struct ep_qe *qe)
{
	if (!qe)
		return;
	if (&ep->qes[qe->tag] != qe)
		return;

	qe->busy = false;
	if (qe->data) {
		free(qe->data);
		qe->data = NULL;
		qe->data_len = 0;
	}
	qe->iovec.iov_base = NULL;
	qe->iovec.iov_len = 0;
	tcp_info(ep, "release tag %#x", qe->tag);
}

static int tcp_init_listener(struct nofuse_port *port)
{
	int listenfd;
	int ret, reuse = 1;
	struct addrinfo *ai, hints;
	char traddr[256];
	char trsvcid[32];
	char adrfam_str[32];
	sa_family_t adrfam = AF_INET;

	ret = configdb_get_port_attr(port->portid, "addr_traddr", traddr);
	if (ret < 0) {
		port_err(port, "failed to get traddr, error %d", ret);
		return ret;
	}
	ret = configdb_get_port_attr(port->portid, "addr_trsvcid", trsvcid);
	if (ret < 0) {
		port_err(port, "failed to get trsvcid, errot %d", ret);
		return ret;
	}
	ret = configdb_get_port_attr(port->portid, "addr_adrfam", adrfam_str);
	if (ret < 0) {
		port_err(port, "failed to get adrfam, error %d", ret);
		return ret;
	}
	if (!strcmp(adrfam_str, "ipv6"))
		adrfam = AF_INET6;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = adrfam;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

	ret = getaddrinfo(traddr, trsvcid, &hints, &ai);
	if (ret != 0) {
		port_err(port, "getaddrinfo() failed: %s",
			  gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		port_err(port, "no results from getaddrinfo()");
		return -EHOSTUNREACH;
	}

	listenfd = socket(ai->ai_family, ai->ai_socktype,
			  ai->ai_protocol);
	if (listenfd < 0) {
		port_err(port, "socket error %d", errno);
		ret = -errno;
		goto err_free;
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
		       &reuse, sizeof(int)) < 0) {
		port_err(port, "setsockopt SO_REUSEADDR error %d", errno);
		ret = -errno;
		goto err_close;
	}

	ret = bind(listenfd, ai->ai_addr, ai->ai_addrlen);
	if (ret < 0) {
		port_err(port, "socket %s:%s bind error %d",
			  traddr, trsvcid, errno);
		ret = -errno;
		goto err_close;
	}
	if (ai->ai_next)
		port_err(port, "duplicate addresses");
	freeaddrinfo(ai);

	ret = listen(listenfd, BACKLOG);
	if (ret < 0) {
		port_err(port, "socket listen error %d", errno);
		ret = -errno;
		goto err_close;
	}
	port_info(port, "listening on %s:%s", traddr, trsvcid);
	port->listenfd = listenfd;
	return 0;
err_close:
	close(listenfd);
err_free:
	freeaddrinfo(ai);
	return ret;
}

static void tcp_destroy_listener(struct nofuse_port *port)
{
	if (port->listenfd < 0)
		return;
	close(port->listenfd);
	port->listenfd = -1;
}

static int tcp_accept_connection(struct nofuse_queue *ep)
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
	ret = recv(ep->sockfd, icreq, hdr_len, MSG_PEEK);
	if (ret < 0) {
		tcp_err(ep, "icreq header peek error %d", errno);
		return -errno;
	}

	if (icreq->hdr.type != nvme_tcp_icreq) {
		ret = tls_handshake(ep);
		if (ret)
			return ret;
	}

	ret = ep->io_ops->io_read(ep, icreq, hdr_len);
	if (ret < 0) {
		if (errno != EAGAIN)
			tcp_err(ep, "icreq header read error %d", errno);
		return -errno;
	}
	if (ret != hdr_len) {
		tcp_err(ep, "icreq short header read, %d bytes missing",
			hdr_len - ret);
		ret = (ret > 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}

	if (icreq->hdr.type != nvme_tcp_icreq) {
		tcp_err(ep, "icreq header type mismatch (%02x)",
			icreq->hdr.type);
		ret = -ENOMSG;
		goto out_free;
	}
	len = icreq->hdr.hlen - hdr_len;
	ret = ep->io_ops->io_read(ep, (u8 *)icreq + hdr_len, len);
	if (ret < 0) {
		tcp_err(ep, "icreq read error %d", errno);
		ret = -errno;
		goto out_free;
	}
	if (ret != len) {
		tcp_err(ep, "icreq short read, %d bytes missing",
			len - ret);
		ret = (ret > 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}
	if (icreq->hpda != 0) {
		ret = -EPROTO;
		goto out_free;
	}
	ep->maxr2t = le32toh(icreq->maxr2t) + 1;

	tcp_info(ep, "read %d icreq bytes (type %d, maxr2t %u)",
		 icreq->hdr.hlen, icreq->hdr.type, icreq->maxr2t);

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
	icrep->maxdata = 0xf000;
	icrep->cpda = 0;
	icrep->digest = 0;

	len = ep->io_ops->io_write(ep, icrep, sizeof(*icrep));
	if (len < 0) {
		tcp_err(ep, "icresp write error %d", errno);
		return -errno;
	}
	if (len != sizeof(*icrep)) {
		tcp_err(ep, "icrep short write, %ld bytes missing",
			sizeof(*icrep) - len);
		ret = -ENODATA;
	} else {
		tcp_info(ep, "wrote %d icresp bytes", len);
		ret = 0;
	}

	free(icrep);
out_free:
	free(icreq);
	return ret;
}

static int tcp_wait_for_connection(struct nofuse_port *port)
{
	int sockfd;
	int ret = -ESHUTDOWN;

	while (port->listenfd > 0) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(port->listenfd, &rfd);
		tmo.tv_sec = (KATO_INTERVAL / 1000);
		tmo.tv_usec = (KATO_INTERVAL % 1000) * 1000;
		ret = select(port->listenfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			port_err(port, "select error %d", errno);
			ret = -errno;
			break;
		}
		if (ret > 0)
			break;
	}

	if (port->listenfd < 0)
		return -ESHUTDOWN;

	if (ret <= 0)
		return ret ? ret : -ETIMEDOUT;

	sockfd = accept(port->listenfd, (struct sockaddr *) NULL,
			NULL);
	if (sockfd < 0) {
		if (errno != EAGAIN)
			port_err(port, "accept error %d", errno);
		ret = -EAGAIN;
	} else
		ret = sockfd;

	return ret;
}

static int tcp_rma_read(struct nofuse_queue *ep, void *buf, u64 _len)
{
	int len = 0, offset = 0;

	while (offset < _len) {
		tcp_info(ep, "recv %llu data bytes",
			_len - offset);
		len = ep->io_ops->io_read(ep, (u8 *)buf + offset,
					  _len - offset);
		if (len < 0) {
			tcp_err(ep, "recv returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "%s: disconnect during recv data",
				__func__);
			return -ENODATA;
		}
		offset += len;
	}
	return 0;
}

static int tcp_send_c2h_data(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int len, send_pdu_len = 0;
	bool last = qe->data_remaining == qe->iovec.iov_len;
	struct nvme_tcp_data_pdu *pdu = &ep->send_pdu->data;

	tcp_info(ep, "c2h data cid %x offset %llu len %lu/%llu",
		  qe->ccid, qe->data_pos, qe->iovec.iov_len,
		  qe->data_remaining);

	if (!qe->data_remaining) {
		tcp_err(ep, "Nothing to send, %lu bytes left",
			 qe->iovec.iov_len);
		return 0;
	}
	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_c2h_data;
	pdu->hdr.flags = last ? (NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS) : 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_data_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_data_pdu) +
				qe->iovec.iov_len);
	pdu->data_offset = htole32(qe->data_pos);
	pdu->data_length = htole32(qe->iovec.iov_len);
	pdu->command_id = qe->ccid;
	tcp_info(ep, "c2h hdr init %u/%u bytes",
		 pdu->hdr.hlen, pdu->hdr.plen);

	while (send_pdu_len < pdu->hdr.hlen) {
		u8 *data = (u8 *)pdu + send_pdu_len;
		u64 data_len = pdu->hdr.hlen - send_pdu_len;

		len = ep->io_ops->io_write(ep, data, data_len);
		if (len < 0) {
			tcp_err(ep, "c2h hdr write returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "c2h hdr write connection closed");
			return -ENODATA;
		}
		send_pdu_len += len;
		tcp_info(ep, "c2h hdr wrote %d bytes", len);
	}
	while (qe->iovec.iov_len) {
		u8 *data = qe->iovec.iov_base;

		len = ep->io_ops->io_write(ep, data, qe->iovec.iov_len);
		if (len < 0) {
			tcp_err(ep, "c2h data write returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "c2h data write connection closed");
			return -ENODATA;
		}
		qe->data_remaining -= len;
		data += len;
		qe->iovec.iov_base = data;
		qe->iovec.iov_len -= len;
		qe->iovec_offset += len;
		tcp_info(ep, "c2h data wrote %d bytes", len);
	}

	return 0;
}

static int tcp_send_r2t(struct nofuse_queue *ep, u16 tag)
{
	struct nvme_tcp_r2t_pdu *pdu = &ep->send_pdu->r2t;
	struct ep_qe *qe;
	int len;

	qe = ep->ops->get_tag(ep, tag);
	if (!qe) {
		tcp_err(ep, "invalid ttag %#x", tag);
		return -EINVAL;
	}

	tcp_info(ep, "r2t cid %#x ttag %#x offset %llu len %lu",
		 qe->ccid, qe->tag, qe->iovec_offset,
		 qe->iovec.iov_len);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_r2t;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_r2t_pdu));
	pdu->ttag = qe->tag;
	pdu->command_id = qe->ccid;
	pdu->r2t_offset = htole32(qe->iovec_offset);
	pdu->r2t_length = htole32(qe->iovec.iov_len);

	memcpy(&qe->pdu, pdu, sizeof(*pdu));

	len = ep->io_ops->io_write(ep, pdu, sizeof(*pdu));
	if (len < 0) {
		tcp_err(ep, "r2t write returned %d", errno);
		return -errno;
	}
	if (len < sizeof(*pdu)) {
		tcp_err(ep, "short r2t write, %d bytes missing",
			(int)sizeof(*pdu) - len);
		return -EAGAIN;
	}
	return 0;
}

static int tcp_send_c2h_term(struct nofuse_queue *ep, u16 fes, u8 pdu_offset,
			     u8 parm_offset, bool hdr_digest,
			     union nvme_tcp_pdu *pdu, int pdu_len)
{
	struct nvme_tcp_term_pdu *term_pdu = &ep->send_pdu->term;
	int len, plen;

	tcp_info(ep, "c2h term fes %u offset pdu %u parm %u",
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

	len = ep->io_ops->io_write(ep, term_pdu, sizeof(*term_pdu));
	if (len < 0) {
		tcp_err(ep, "c2h_term write returned %d", errno);
		return -errno;
	}
	if (len != sizeof(*term_pdu)) {
		tcp_err(ep, "c2h_term short write; %d bytes missing",
			 plen - len);
		return -EAGAIN;
	}
	if (pdu) {
		len = ep->io_ops->io_write(ep, pdu, pdu_len);
		if (len < 0) {
			tcp_err(ep, "c2h term pdu write returned %d", errno);
			return -errno;
		}
		if (len != pdu_len) {
			tcp_err(ep, "c2h term short write; %d bytes missing",
				 pdu_len - len);
			return -EAGAIN;
		}
	}

	ep->recv_state = RECV_PDU;
	ep->recv_pdu_len = 0;

	/* Return -EPROTO to signal the connection should be dropped */
	return -EPROTO;
}

static int tcp_send_rsp(struct nofuse_queue *ep, struct nvme_completion *comp)
{
	struct nvme_tcp_rsp_pdu *pdu = &ep->send_pdu->rsp;
	int len;

	tcp_info(ep, "rsp tag %#x status %04x",
		  comp->command_id, comp->status);

	pdu->hdr.type = nvme_tcp_rsp;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_rsp_pdu);
	pdu->hdr.plen = sizeof(struct nvme_tcp_rsp_pdu);

	memcpy(&(pdu->cqe), comp, sizeof(struct nvme_completion));

	tcp_info(ep, "write %u pdu bytes", pdu->hdr.plen);
	len = ep->io_ops->io_write(ep, pdu, pdu->hdr.plen);
	if (len != sizeof(*pdu)) {
		tcp_err(ep, "tcp_ep_write returned %d", errno);
		return -errno;
	}

	return 0;
}

static int tcp_handle_h2c_data(struct nofuse_queue *ep, union nvme_tcp_pdu *pdu)
{
	u16 ttag = le16toh(pdu->data.ttag);
	u32 data_offset = le32toh(pdu->data.data_offset);
	u32 data_len = le32toh(pdu->data.data_length);
	u8 *data;
	struct ep_qe *qe;
	int ret;

	tcp_info(ep, "h2c data tag %#x pos %u len %u",
		  ttag, data_offset, data_len);
	qe = ep->ops->get_tag(ep, ttag);
	if (!qe) {
		tcp_err(ep, "h2c invalid ttag %#x", ttag);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
				offsetof(struct nvme_tcp_data_pdu, ttag),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_offset != qe->iovec_offset) {
		tcp_err(ep, "h2c offset mismatch, is %u exp %llu",
			 data_offset, qe->iovec_offset);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_len > qe->iovec.iov_len) {
		tcp_err(ep, "h2c len overflow, is %u exp %llu",
			 data_len, qe->data_remaining);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}

	ret = tcp_rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
	if (ret < 0) {
		tcp_err(ep, "h2c data read failed, error %d", errno);
		ret = NVME_SC_SGL_INVALID_DATA;
		goto out_rsp;
	}
	qe->data_remaining -= ret;
	qe->iovec_offset += ret;
	data = qe->iovec.iov_base;
	data += ret;
	qe->iovec.iov_base = data;
	qe->iovec.iov_len -= ret;
	if (!qe->data_remaining) {
		ret = 0;
		goto out_rsp;
	}

	return tcp_send_r2t(ep, qe->tag);
out_rsp:
	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, qe->ccid, ret, true);
	return tcp_send_rsp(ep, &qe->resp);
}

static int tcp_read_msg(struct nofuse_queue *ep)
{
	u8 *msg = (u8 *)ep->recv_pdu + ep->recv_pdu_len;
	int len, msg_len;

	if (ep->recv_pdu_len < sizeof(struct nvme_tcp_hdr)) {
		msg_len = sizeof(struct nvme_tcp_hdr) - ep->recv_pdu_len;
		tcp_info(ep, "read %u msg bytes", msg_len);
		len = ep->io_ops->io_read(ep, msg, msg_len);
		if (len < 0) {
			tcp_err(ep, "failed to read msg hdr, error %d",
				errno);
			return -errno;
		}
		/* No data received, disconnected */
		if (!len) {
			tcp_info(ep, "disconnect during read msg");
			return -ENODATA;
		}

		ep->recv_pdu_len += len;
		msg_len -= len;
		if (msg_len) {
			tcp_err(ep, "short msg hdr read, %lu bytes missing",
				sizeof(struct nvme_tcp_hdr) - ep->recv_pdu_len);
			return -EAGAIN;
		}
	}
	if (!ep->recv_pdu->common.hlen) {
		tcp_err(ep, "corrupt hdr, hlen %d size %ld",
			ep->recv_pdu->common.hlen,
			sizeof(struct nvme_tcp_hdr));
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
					offsetof(struct nvme_tcp_hdr, hlen),
					0, false, NULL, 0);
	}
	msg_len = ep->recv_pdu->common.hlen - ep->recv_pdu_len;
	if (msg_len) {
		msg = (u8 *)ep->recv_pdu + ep->recv_pdu_len;

		tcp_info(ep, "read %u pdu bytes", msg_len);
		len = ep->io_ops->io_read(ep, msg, msg_len);
		if (len < 0) {
			tcp_err(ep, "failed to read msg payload error %d",
				errno);
			return -errno;
		}
		if (len == 0) {
			tcp_info(ep, "disconnect during read pdu");
			return -ENODATA;
		}
		ep->recv_pdu_len += len;
		msg_len -= len;
		if (msg_len > 0) {
			tcp_err(ep, "short msg payload read, %u bytes missing",
			       msg_len);
			return -EAGAIN;
		}
		ep->recv_state = HANDLE_PDU;
	}
	return 0;
}

int tcp_handle_msg(struct nofuse_queue *ep)
{
	union nvme_tcp_pdu *pdu = ep->recv_pdu;
	struct nvme_tcp_hdr *hdr = &pdu->common;

	if (hdr->type == nvme_tcp_h2c_data)
		return tcp_handle_h2c_data(ep, pdu);

	if (hdr->type == nvme_tcp_h2c_term) {
		ep->recv_state = RECV_PDU;
		ep->recv_pdu_len = 0;
		tcp_info(ep, "h2c term, disconnecting");
		return -ENOTCONN;
	}

	if (hdr->type != nvme_tcp_cmd) {
		tcp_err(ep, "unknown PDU type %x", hdr->type);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
					 offsetof(struct nvme_tcp_hdr, type),
					 0, false, pdu, hdr->hlen);
	}

	return handle_request(ep, &pdu->cmd.cmd);
}

static int tcp_send_data(struct nofuse_queue *ep, struct ep_qe *qe, u64 data_len)
{
	tcp_info(ep, "write cid %x offset %llu len %llu",
		  qe->ccid, qe->data_pos, data_len);

	qe->data_remaining = data_len;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
		ep->mdts : data_len;
	qe->iovec_offset = 0;
	while (qe->data_remaining) {
		int ret = tcp_send_c2h_data(ep, qe);
		if (ret < 0) {
			ep->ops->release_tag(ep, qe);
			return ret;
		}
		data_len = qe->data_remaining;
		qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
			ep->mdts : data_len;
	}
	ep->ops->release_tag(ep, qe);
	return 0;
}

static int tcp_handle_aen(struct nofuse_queue *ep)
{
	struct ep_qe *qe = NULL;
	u32 aen_mask;
	int ret, i;
	u8 type, level = NVME_AER_NOTICE;
	u16 log_page;
	u32 result;

	if (!ep->ctrl)
		return 0;

	aen_mask = ep->ctrl->aen_mask;
	if (aen_mask & NVME_AEN_CFG_NS_ATTR) {
		type = NVME_AER_NOTICE_NS_CHANGED;
		log_page = NVME_LOG_CHANGED_NS;
		aen_mask &= ~NVME_AEN_CFG_NS_ATTR;
	} else if (aen_mask & NVME_AEN_CFG_ANA_CHANGE) {
		type = NVME_AER_NOTICE_ANA;
		log_page = NVME_LOG_ANA;
		aen_mask &= ~NVME_AEN_CFG_ANA_CHANGE;
	} else if (aen_mask & NVME_AEN_CFG_DISC_CHANGE) {
		type = NVME_AER_NOTICE_DISC_CHANGED;
		log_page = NVME_LOG_DISC;
		aen_mask &= ~NVME_AEN_CFG_DISC_CHANGE;
	} else {
		return -EINVAL;
	}
	ep->ctrl->aen_mask = aen_mask;

	for (i = 0; i < ep->qsize; i++) {
		if (!ep->qes[i].aen)
			continue;
		if (!ep->qes[i].busy)
			continue;
		qe = &ep->qes[i];
		break;
	}
	if (!qe)
		return -EBUSY;

	result = level | type << 8 | log_page << 16;
	qe->resp.command_id = htole16(qe->ccid);
	qe->resp.result.u32 = htole32(result);
	qe->resp.status = 0;

	ret = ep->ops->send_rsp(ep, &qe->resp);
	ep->ops->release_tag(ep, qe);
	return ret;
}

static struct xp_ops tcp_ops = {
	.create_queue		= tcp_create_queue,
	.destroy_queue		= tcp_destroy_queue,
	.init_listener		= tcp_init_listener,
	.destroy_listener	= tcp_destroy_listener,
	.wait_for_connection	= tcp_wait_for_connection,
	.accept_connection	= tcp_accept_connection,
	.acquire_tag		= tcp_acquire_tag,
	.get_tag		= tcp_get_tag,
	.release_tag		= tcp_release_tag,
	.rma_read		= tcp_rma_read,
	.rma_write		= tcp_send_data,
	.prep_rma_read		= tcp_send_r2t,
	.send_rsp		= tcp_send_rsp,
	.read_msg		= tcp_read_msg,
	.handle_msg		= tcp_handle_msg,
	.handle_aen		= tcp_handle_aen,
};

struct xp_ops *tcp_register_ops(void)
{
	return &tcp_ops;
}
