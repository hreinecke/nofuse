#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"
#include "nvme.h"
#include "tcp.h"
#include "inode.h"

#define ctrl_info(e, f, x...)					\
	if (cmd_debug) {					\
		if ((e)->ctrl) {				\
			printf("ctrl %d qid %d: " f "\n",	\
			       (e)->ctrl->cntlid,		\
			       (e)->qid, ##x);			\
		} else {					\
			printf("ep %d: " f "\n",		\
			       (e)->sockfd, ##x);		\
		}						\
		fflush(stdout);					\
	}

#define ctrl_err(e, f, x...)					\
	do {							\
		if ((e)->ctrl) {				\
			fprintf(stderr,				\
				"ctrl %d qid %d: " f "\n",	\
				(e)->ctrl->cntlid,		\
				(e)->qid, ##x);			\
		} else {					\
			fprintf(stderr, "ep %d: " f "\n",	\
			       (e)->sockfd, ##x);		\
		}						\
		fflush(stderr);					\
	} while (0)

#define NVME_VER ((1 << 16) | (4 << 8)) /* NVMe 1.4 */

static int send_response(struct endpoint *ep, struct ep_qe *qe,
			 u16 status)
{
	int ret;

	set_response(&qe->resp, qe->ccid, status, true);
	ret = ep->ops->send_rsp(ep, &qe->resp);
	ep->ops->release_tag(ep, qe);
	return ret;
}

static int handle_property_set(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0;

	ctrl_info(ep, "nvme_fabrics_type_property_set %x = %llx",
		  cmd->prop_set.offset, cmd->prop_set.value);

	if (cmd->prop_set.offset == NVME_REG_CC) {
		ep->ctrl->cc = le64toh(cmd->prop_set.value);
		if (ep->ctrl->cc & NVME_CC_SHN_MASK)
			ep->ctrl->csts = NVME_CSTS_SHST_CMPLT;
		else {
			if (ep->ctrl->cc & NVME_CC_ENABLE)
				ep->ctrl->csts = NVME_CSTS_RDY;
			else
				ep->ctrl->csts = NVME_CSTS_SHST_CMPLT;
		}
	} else
		ret = NVME_SC_INVALID_FIELD;

	return ret;
}

static int handle_property_get(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u64 value;

	if (cmd->prop_get.offset == NVME_REG_CSTS)
		value = ep->ctrl->csts;
	else if (cmd->prop_get.offset == NVME_REG_CAP)
		value = 0x200f0003ffL;
	else if (cmd->prop_get.offset == NVME_REG_CC)
		value = ep->ctrl->cc;
	else if (cmd->prop_get.offset == NVME_REG_VS)
		value = NVME_VER;
	else {
		ctrl_info(ep, "nvme_fabrics_type_property_get %x: N/I",
			  cmd->prop_get.offset);
		return NVME_SC_INVALID_FIELD;
	}

	ctrl_info(ep, "nvme_fabrics_type_property_get %x: %llx",
		  cmd->prop_get.offset, value);
	qe->resp.result.u64 = htole64(value);

	return 0;
}

static int handle_set_features(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u32 cdw10 = le32toh(cmd->common.cdw10);
	u32 cdw11 = le32toh(cmd->common.cdw11);
	int fid = (cdw10 & 0xff), ncqr, nsqr;
	int ret = 0;

	ctrl_info(ep,"nvme_fabrics_type_set_features cdw10 %x fid %x",
		  cdw10, fid);

	switch (fid) {
	case NVME_FEAT_NUM_QUEUES:
		ncqr = (cdw11 >> 16) & 0xffff;
		nsqr = cdw11 & 0xffff;
		if (ncqr < ep->ctrl->max_endpoints) {
			ep->ctrl->max_endpoints = ncqr;
		}
		if (nsqr < ep->ctrl->max_endpoints) {
			ep->ctrl->max_endpoints = nsqr;
		}
		qe->resp.result.u32 = htole32(ep->ctrl->max_endpoints << 16 |
					      ep->ctrl->max_endpoints);
		break;
	case NVME_FEAT_ASYNC_EVENT:
		ep->ctrl->aen_mask = cdw11;
		break;
	case NVME_FEAT_KATO:
		/* cdw11 / kato is in msecs */
		ep->ctrl->kato = cdw11 / ep->kato_interval;
		break;
	default:
		ret = NVME_SC_FEATURE_NOT_CHANGEABLE;
	}
	return ret;
}

static int handle_connect(struct endpoint *ep, struct ep_qe *qe,
			  struct nvme_command *cmd)
{
	struct nofuse_subsys *subsys = NULL, *_subsys;
	struct nvmf_connect_data *connect = qe->data;
	u16 sqsize;
	u16 cntlid, qid;
	u32 kato;
	int ret;

	qid = le16toh(cmd->connect.qid);
	sqsize = le16toh(cmd->connect.sqsize);
	kato = le32toh(cmd->connect.kato);

	ctrl_info(ep, "nvme_fabrics_connect qid %u sqsize %u kato %u",
		  qid, sqsize, kato);

	ret = ep->ops->rma_read(ep, connect, qe->data_len);
	if (ret) {
		ctrl_err(ep, "rma_read failed with error %d",
			 errno);
		return ret;
	}

	cntlid = le16toh(connect->cntlid);

	if (qid == 0 && cntlid != 0xFFFF) {
		ctrl_err(ep, "bad controller id %x, expecting %x",
			 cntlid, 0xffff);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (!sqsize) {
		ctrl_err(ep, "ctrl %d qid %d invalid sqsize",
			  cntlid, qid);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (ep->ctrl) {
		ctrl_err(ep, "ctrl %d qid %d already connected",
			  ep->ctrl->cntlid, qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}
	if (qid == 0) {
		ep->qsize = NVMF_SQ_DEPTH;
	} else if (endpoint_update_qdepth(ep, sqsize) < 0) {
		ctrl_err(ep, "ctrl %d qid %d failed to increase sqsize %d",
			  cntlid, qid, sqsize);
		return NVME_SC_INTERNAL;
	}

	ep->qid = qid;

	list_for_each_entry(_subsys, &subsys_linked_list, node) {
		if (!strcmp(connect->subsysnqn, _subsys->nqn)) {
			subsys = _subsys;
			break;
		}
		if (_subsys->type == NVME_NQN_CUR &&
		    !strcmp(connect->subsysnqn, NVME_DISC_SUBSYS_NAME)) {
			subsys = _subsys;
			break;
		}
	}
	if (!subsys) {
		ctrl_err(ep, "subsystem '%s' not found",
			  connect->subsysnqn);
		return NVME_SC_CONNECT_INVALID_HOST;
	}

	ret = connect_endpoint(ep, subsys, cntlid,
			       connect->hostnqn, connect->subsysnqn);
	if (!ret) {
		ctrl_info(ep, "connected");
		ep->ctrl->kato = kato / ep->kato_interval;
		qe->resp.result.u16 = htole16(ep->ctrl->cntlid);
	} else {
		if (ret == -ENOENT) {
			ctrl_err(ep, "bad controller id %x for queue %d",
				 cntlid, qid);
			ret = NVME_SC_CONNECT_INVALID_PARAM;
		} else if (ret == -EPERM)
			ret = NVME_SC_CONNECT_INVALID_HOST;
		else
			ret = NVME_SC_INTERNAL;
	}
	return ret;
}

static int handle_identify_ctrl(struct endpoint *ep, u8 *id_buf, u64 len)
{
	struct nvme_id_ctrl id;

	memset(&id, 0, sizeof(id));

	memset(id.fr, ' ', sizeof(id.fr));
	strncpy((char *) id.fr, " ", sizeof(id.fr));

	id.mdts = 0;
	id.cmic = 3;
	id.cntlid = htole16(ep->ctrl->cntlid);
	id.ver = htole32(NVME_VER);
	id.lpa = (1 << 2);
	id.sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id.kas = ep->kato_interval / 100; /* KAS is in units of 100 msecs */
	id.ioccsz = NVME_NVM_IOSQES;
	id.iorcsz = NVME_NVM_IOCQES;

	id.cntrltype = ep->ctrl->ctrl_type;
	strcpy(id.subnqn, ep->ctrl->subsys->nqn);
	if (ep->ctrl->ctrl_type == NVME_CTRL_CNTRLTYPE_DISC) {
		id.maxcmd = htole16(NVMF_DQ_DEPTH);
	} else {
		id.maxcmd = htole16(ep->qsize);
	}

	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify_ns(struct endpoint *ep, u32 nsid, u8 *id_buf, u64 len)
{
	struct nofuse_namespace *ns = NULL, *_ns;
	struct nvme_id_ns id;

	list_for_each_entry(_ns, &device_linked_list, node) {
		if (strcmp(_ns->subsysnqn, ep->ctrl->subsys->nqn))
			continue;
		if (_ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENODEV;

	memset(&id, 0, sizeof(id));

	id.nsze = (u64)ns->size / ns->blksize;
	id.ncap = id.nsze;
	id.nlbaf = 1;
	id.flbas = 0;
	id.nmic = 1;
	id.lbaf[0].ds = 12;

	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify_active_ns(struct endpoint *ep, u8 *id_buf, u64 len)
{
	struct nofuse_namespace *ns;
	u8 *ns_list = id_buf;
	int id_len = len;

	memset(ns_list, 0, len);
	list_for_each_entry(ns, &device_linked_list, node) {
		u32 nsid = htole32(ns->nsid);
		if (len < 4)
			break;
		if (strcmp(ns->subsysnqn, ep->ctrl->subsys->nqn))
			continue;
		memcpy(ns_list, &nsid, 4);
		ns_list += 4;
		len -= 4;
	}
	return id_len;
}

static int handle_identify_ns_desc_list(struct endpoint *ep, u32 nsid, u8 *desc_list, u64 len)
{
	int desc_len = len, ret;
	char uuid_str[37];
	uuid_t uuid;

	memset(desc_list, 0, len);
	ret = inode_get_namespace_attr(ep->ctrl->subsys->nqn, nsid,
				       "device_uuid", uuid_str);
	if (ret < 0)
		return ret;
	ret = uuid_parse(uuid_str, uuid);
	if (ret < 0)
		return ret;

	desc_list[0] = 3;
	desc_list[1] = 0x10;
	memcpy(&desc_list[2], uuid, 0x10);
	desc_list += 0x12;
	len -= 0x12;
	desc_list[0] = 4;
	desc_list[1] = 1;
	desc_list[2] = 0;
	len -= 3;

	return desc_len;
}

static int handle_identify(struct endpoint *ep, struct ep_qe *qe,
			   struct nvme_command *cmd)
{
	int cns = cmd->identify.cns;
	int nsid = le32toh(cmd->identify.nsid);
	u16 cid = cmd->identify.command_id;
	int ret, id_len;

	ctrl_info(ep, "cid %#x nvme_fabrics_identify cns %d len %llu",
		  cid, cns, qe->data_len);

	switch (cns) {
	case NVME_ID_CNS_NS:
		id_len = handle_identify_ns(ep, nsid, qe->data, qe->data_len);
		break;
	case NVME_ID_CNS_CTRL:
		id_len = handle_identify_ctrl(ep, qe->data, qe->data_len);
		break;
	case NVME_ID_CNS_NS_ACTIVE_LIST:
		id_len = handle_identify_active_ns(ep, qe->data, qe->data_len);
		break;
	case NVME_ID_CNS_NS_DESC_LIST:
		id_len = handle_identify_ns_desc_list(ep, nsid,
						      qe->data, qe->data_len);
		break;
	default:
		ctrl_err(ep, "unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES;
	}

	if (id_len < 0)
		return NVME_SC_INVALID_NS;

	qe->data_pos = 0;
	ret = ep->ops->rma_write(ep, qe, id_len);
	if (ret)
		ctrl_err(ep, "rma_write failed with %d", ret);
	return ret;
}

static int format_disc_log(void *data, u64 data_offset,
			   u64 data_len, struct endpoint *ep)
{
	int len, log_len, genctr, num_recs = 0, ret;
	u8 *log_buf;
	struct nvmf_disc_rsp_page_hdr *log_hdr;
	struct nvmf_disc_rsp_page_entry *log_ptr;

	len = inode_host_disc_entries(ep->ctrl->nqn, NULL, 0);
	if (len < 0) {
		ctrl_err(ep, "error formatting discovery log page");
		return -1;
	}
	num_recs = len / sizeof(struct nvmf_disc_rsp_page_entry);
	log_len = len + sizeof(struct nvmf_disc_rsp_page_hdr);
	log_buf = malloc(log_len);
	if (!log_buf) {
		ctrl_err(ep, "error allocating discovery log");
		errno = ENOMEM;
		return -1;
	}
	memset(log_buf, 0, log_len);
	log_hdr = (struct nvmf_disc_rsp_page_hdr *)log_buf;
	log_ptr = log_hdr->entries;

	if (num_recs) {
		len = inode_host_disc_entries(ep->ctrl->nqn,
					      (u8 *)log_ptr, len);
		if (len < 0) {
			ctrl_err(ep, "error fetching discovery log entries");
			num_recs = 0;
		}
	}

	ret = inode_host_genctr(ep->ctrl->nqn, &genctr);
	if (ret < 0) {
		ctrl_err(ep, "error retrieving genctr");
		genctr = 0;
	}
	log_hdr->recfmt = 1;
	log_hdr->numrec = htole64(num_recs);
	log_hdr->genctr = htole64(genctr);
	if (log_len < data_offset) {
		ctrl_err(ep, "offset %llu beyond log page size %d",
			 data_offset, log_len);
		log_len = 0;
	} else {
		log_len -= data_offset;
		if (log_len > data_len)
			log_len = data_len;
		memcpy(data, log_buf + data_offset, log_len);
	}
	ctrl_info(ep, "discovery log page entries %d offset %llu len %d",
		  num_recs, data_offset, log_len);
	free(log_buf);
	return log_len;
}

static int handle_get_log_page(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0, log_len;
	u64 offset = le64toh(cmd->get_log_page.lpo);

	ctrl_info(ep, "nvme_get_log_page opcode %02x lid %02x offset %lu len %lu",
		  cmd->get_log_page.opcode, cmd->get_log_page.lid,
		  (unsigned long)offset, (unsigned long)qe->data_len);

	qe->data_pos = offset;
	switch (cmd->get_log_page.lid) {
	case 0x02:
		/* SMART Log */
		log_len = qe->data_len;
		memset(qe->data, 0, log_len);
		break;
	case 0x70:
		/* Discovery log */
		log_len = format_disc_log(qe->data, qe->data_pos,
					  qe->data_len, ep);
		if (!log_len) {
			ctrl_err(ep, "get_log_page: discovery log failed");
			return NVME_SC_INTERNAL;
		}
		break;
	default:
		ctrl_err(ep, "get_log_page: lid %02x not supported",
			  cmd->get_log_page.lid);
		return NVME_SC_INVALID_FIELD;
	}
	ret = ep->ops->rma_write(ep, qe, log_len);
	if (ret)
		ctrl_err(ep, "rma_write failed with error %d", ret);

	return ret;
}

static int handle_read(struct endpoint *ep, struct ep_qe *qe,
		       struct nvme_command *cmd)
{
	struct nofuse_namespace *ns;
	int nsid = le32toh(cmd->rw.nsid);

	list_for_each_entry(ns, &device_linked_list, node) {
		if (strcmp(ns->subsysnqn, ep->ctrl->subsys->nqn))
			continue;
		if (ns->nsid == nsid) {
			qe->ns = ns;
			break;
		}
	}
	if (!qe->ns) {
		ctrl_err(ep, "invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	if ((cmd->rw.dptr.sgl.type >> 4) != NVME_TRANSPORT_SGL_DATA_DESC) {
		ctrl_err(ep, "unhandled sgl type %d\n",
			  cmd->rw.dptr.sgl.type >> 4);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	ctrl_info(ep, "nsid %d tag %#x ccid %#x read pos %llu len %llu",
		  nsid, qe->tag, qe->ccid, qe->data_pos, qe->data_len);

	return ns->ops->ns_read(ep, qe);
}

static int handle_write(struct endpoint *ep, struct ep_qe *qe,
			struct nvme_command *cmd)
{
	struct nofuse_namespace *ns;
	u8 sgl_type = cmd->rw.dptr.sgl.type;
	int nsid = le32toh(cmd->rw.nsid);
	int ret;

	list_for_each_entry(ns, &device_linked_list, node) {
		if (strcmp(ns->subsysnqn, ep->ctrl->subsys->nqn))
			continue;
		if (ns->nsid == nsid) {
			qe->ns = ns;
			break;
		}
	}
	if (!qe->ns) {
		ctrl_err(ep, "invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	if (sgl_type == NVME_SGL_FMT_OFFSET) {
		/* Inline data */
		ctrl_info(ep, "nsid %d tag %#x ccid %#x inline write pos %llu len %llu",
			   nsid, qe->tag, qe->ccid,
			   qe->data_pos, qe->data_len);
		ret = ep->ops->rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
		if (ret < 0) {
			ctrl_err(ep, "tag %#x rma_read error %d",
				 qe->tag, ret);
			return ret;
		}
		return ns->ops->ns_write(ep, qe);
	}
	if ((sgl_type & 0x0f) != NVME_SGL_FMT_TRANSPORT_A) {
		ctrl_err(ep, "Invalid sgl type %x", sgl_type);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	ret = ns->ops->ns_prep_read(ep, qe);
	if (ret) {
		ctrl_err(ep, "prep_rma_read failed with error %d", ret);
	} else
		ctrl_info(ep, "nsid %d tag %#x ccid %#x write pos %llu len %llu",
			  nsid, qe->tag, qe->ccid, qe->data_pos, qe->data_len);

	return ret;
}

int handle_request(struct endpoint *ep, struct nvme_command *cmd)
{
	struct ep_qe *qe;
	u32 len;
	u16 ccid;
	int ret;

	len = le32toh(cmd->common.dptr.sgl.length);
	/* ccid is considered opaque; no endian conversion */
	ccid = cmd->common.command_id;
	qe = ep->ops->acquire_tag(ep, ep->recv_pdu, ccid, 0, len);
	if (!qe) {
		struct nvme_completion resp = {
			.status = NVME_SC_NS_NOT_READY,
			.command_id = ccid,
		};

		ctrl_err(ep, "ccid %#x queue busy", ccid);
		return ep->ops->send_rsp(ep, &resp);
	}
	memset(&qe->resp, 0, sizeof(qe->resp));
	if (cmd->common.opcode == nvme_fabrics_command) {
		switch (cmd->fabrics.fctype) {
		case nvme_fabrics_type_property_set:
			ret = handle_property_set(ep, qe, cmd);
			break;
		case nvme_fabrics_type_property_get:
			ret = handle_property_get(ep, qe, cmd);
			break;
		case nvme_fabrics_type_connect:
			ret = handle_connect(ep, qe, cmd);
			break;
		default:
			ctrl_err(ep, "unknown fctype %d", cmd->fabrics.fctype);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (ep->qid != 0) {
		if (cmd->common.opcode == nvme_cmd_read) {
			ret = handle_read(ep, qe, cmd);
			if (!ret)
				return 0;
		} else if (cmd->common.opcode == nvme_cmd_write) {
			ret = handle_write(ep, qe, cmd);
			if (!ret)
				return 0;
		} else {
			ctrl_err(ep, "unknown nvme I/O opcode %d",
				  cmd->common.opcode);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (cmd->common.opcode == nvme_admin_identify) {
		ret = handle_identify(ep, qe, cmd);
		if (!ret)
			return 0;
	} else if (cmd->common.opcode == nvme_admin_keep_alive) {
		ctrl_info(ep, "nvme_keep_alive");
		ret = 0;
	} else if (cmd->common.opcode == nvme_admin_get_log_page) {
		ret = handle_get_log_page(ep, qe, cmd);
		if (!ret)
			return 0;
	} else if (cmd->common.opcode == nvme_admin_set_features) {
		ret = handle_set_features(ep, qe, cmd);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else {
		ctrl_err(ep, "unknown nvme admin opcode %d",
			 cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	}

	if (ret < 0) {
		ctrl_err(ep, "handle_request error %d\n", ret);
		return ret;
	}

	return send_response(ep, qe, ret);
}

int handle_data(struct endpoint *ep, struct ep_qe *qe, int res)
{
	return qe->ns->ops->ns_handle_qe(ep, qe, res);
}
