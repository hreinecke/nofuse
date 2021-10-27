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

#define NVME_VER ((1 << 16) | (4 << 8)) /* NVMe 1.4 */

static int nvmf_discovery_genctr = 1;
static int nvmf_ctrl_id = 1;

static int handle_property_set(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_property_set %x = %llx",
		   cmd->prop_set.offset, cmd->prop_set.value);
#endif
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
#ifdef DEBUG_COMMANDS
		print_debug("nvme_fabrics_type_property_get %x: N/I",
			    cmd->prop_get.offset);
#endif
		return NVME_SC_INVALID_FIELD;
	}

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_property_get %x: %llx",
		    cmd->prop_get.offset, value);
#endif
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

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_set_features cdw10 %x fid %x",
		    cdw10, fid);
#endif

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
	struct subsystem *subsys = NULL, *_subsys;
	struct ctrl_conn *ctrl;
	struct nvmf_connect_data *connect = qe->data;
	u16 sqsize;
	u16 cntlid, qid;
	u32 kato;
	int ret;

	qid = le16toh(cmd->connect.qid);
	sqsize = le16toh(cmd->connect.sqsize);
	kato = le32toh(cmd->connect.kato);

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_connect qid %u sqsize %u kato %u",
		    qid, sqsize, kato);
#endif

	ret = ep->ops->rma_read(ep, connect, qe->data_len);
	if (ret) {
		print_errno("rma_read failed", ret);
		return ret;
	}

	cntlid = le16toh(connect->cntlid);

	if (qid == 0 && cntlid != 0xFFFF) {
		print_err("bad controller id %x, expecting %x",
			  cntlid, 0xffff);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (!sqsize) {
		print_err("ctrl %d qid %d invalid sqsize",
			  cntlid, qid);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (ep->ctrl) {
		print_err("ctrl %d qid %d already connected",
			  ep->ctrl->cntlid, qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}
	if (qid == 0) {
		ep->qsize = NVMF_SQ_DEPTH;
	} else if (endpoint_update_qdepth(ep, sqsize) < 0) {
		print_err("ctrl %d qid %d failed to increase sqsize %d",
			  cntlid, qid, sqsize);
		return NVME_SC_INTERNAL;
	}

	ep->qid = qid;

	list_for_each_entry(_subsys, &subsys_linked_list, node) {
		if (!strcmp(connect->subsysnqn, _subsys->nqn)) {
			subsys = _subsys;
			break;
		}
	}
	if (!subsys) {
		print_err("subsystem '%s' not found",
			  connect->subsysnqn);
		return NVME_SC_CONNECT_INVALID_HOST;
	}

	if (!(ep->iface->port_type & (1 << subsys->type))) {
		print_err("non-matching subsystem '%s' type %x on port %d",
			  subsys->nqn, ep->iface->port_type,
			  ep->iface->portid);
		return NVME_SC_CONNECT_INVALID_HOST;
	}

	pthread_mutex_lock(&subsys->ctrl_mutex);
	list_for_each_entry(ctrl, &subsys->ctrl_list, node) {
		if (!strncmp(connect->hostnqn, ctrl->nqn, MAX_NQN_SIZE)) {
			if (qid == 0 || ctrl->cntlid != cntlid)
				continue;
			ep->ctrl = ctrl;
			ctrl->num_endpoints++;
			break;
		}
	}
	if (!ep->ctrl) {
		print_info("Allocating new controller '%s'",
			   connect->hostnqn);
		ctrl = malloc(sizeof(*ctrl));
		if (!ctrl) {
			print_err("Out of memory allocating controller");
		} else {
			memset(ctrl, 0, sizeof(*ctrl));
			strncpy(ctrl->nqn, connect->hostnqn, MAX_NQN_SIZE);
			ctrl->max_endpoints = NVMF_NUM_QUEUES;
			ctrl->kato = kato / ep->kato_interval;
			ep->ctrl = ctrl;
			ctrl->num_endpoints = 1;
			ctrl->subsys = subsys;
			ctrl->cntlid = nvmf_ctrl_id++;
			if (!strncmp(subsys->nqn, NVME_DISC_SUBSYS_NAME,
				     MAX_NQN_SIZE)) {
				ctrl->ctrl_type = NVME_CTRL_CNTRLTYPE_DISC;
				ep->qsize = NVMF_DQ_DEPTH;
			} else {
				ctrl->ctrl_type = NVME_CTRL_CNTRLTYPE_IO;
			}
			list_add(&ctrl->node, &subsys->ctrl_list);
		}
	}
	pthread_mutex_unlock(&subsys->ctrl_mutex);
	if (!ep->ctrl) {
		print_err("bad controller id %x for queue %d, expecting %x",
			  cntlid, qid, ctrl->cntlid);
		ret = NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (!ret) {
		print_info("ctrl %d qid %d connected",
			   ep->ctrl->cntlid, ep->qid);
		qe->resp.result.u16 = htole16(ep->ctrl->cntlid);
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

	id.cntrltype = ep->ctrl->ctrl_type;
	if (ep->ctrl->ctrl_type == NVME_CTRL_CNTRLTYPE_DISC) {
		strcpy(id.subnqn, NVME_DISC_SUBSYS_NAME);
		id.maxcmd = htole16(NVMF_DQ_DEPTH);
	} else {
		strcpy(id.subnqn, ep->ctrl->subsys->nqn);
		id.maxcmd = htole16(ep->qsize);
	}

	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify_ns(struct endpoint *ep, u32 nsid, u8 *id_buf, u64 len)
{
	struct nsdev *ns = NULL, *_ns;
	struct nvme_id_ns id;

	list_for_each_entry(_ns, devices, node) {
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
	struct nsdev *ns;
	u8 *ns_list = id_buf;
	int id_len = len;

	memset(ns_list, 0, len);
	list_for_each_entry(ns, devices, node) {
		u32 nsid = htole32(ns->nsid);
		if (len < 4)
			break;
		memcpy(ns_list, &nsid, 4);
		ns_list += 4;
		len -= 4;
	}
	return id_len;
}

static int handle_identify_ns_desc_list(struct endpoint *ep, u32 nsid, u8 *desc_list, u64 len)
{
	struct nsdev *ns = NULL, *_ns;
	int desc_len = len;

	memset(desc_list, 0, len);
	list_for_each_entry(_ns, devices, node) {
		if (_ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENODEV;

	desc_list[0] = 3;
	desc_list[1] = 0x10;
	memcpy(&desc_list[2], ns->uuid, 0x10);
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

#ifdef DEBUG_COMMANDS
	print_debug("cid %#x nvme_fabrics_identify cns %d len %llu",
		    cid, cns, qe->data_len);
#endif

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
		print_err("unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES;
	}

	if (id_len < 0)
		return NVME_SC_INVALID_NS;

	qe->data_pos = 0;
	ret = ep->ops->rma_write(ep, qe, id_len);
	if (!ret)
		ret = -1;
	else {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	return ret;
}

static int format_disc_log(void *data, u64 data_offset,
			   u64 data_len, struct endpoint *ep)
{
	struct subsystem *subsys;
	struct host_iface *iface;
	struct nvmf_disc_rsp_page_hdr hdr;
	struct nvmf_disc_rsp_page_entry entry;
	u8 *log_buf, *log_ptr;
	u64 log_len = data_len;

	hdr.genctr = nvmf_discovery_genctr;
	hdr.recfmt = 0;
	hdr.numrec = 0;
	list_for_each_entry(subsys, &subsys_linked_list, node) {
		if (subsys->type != NVME_NQN_NVM)
			continue;
		list_for_each_entry(iface, &iface_linked_list, node) {
			if (iface->port_type & (1 << NVME_NQN_NVM))
				hdr.numrec++;
		}
	}
	print_info("Found %llu entries", hdr.numrec);

	log_len = sizeof(hdr) + hdr.numrec * sizeof(entry);
	if (data_len > log_len)
		log_len = data_len;
	log_buf = malloc(log_len);
	if (!log_buf)
		return log_len;

	memset(log_buf, 0, log_len);
	memcpy(log_buf, &hdr, sizeof(hdr));
	log_ptr = log_buf;
	log_len -= sizeof(hdr);
	log_ptr += sizeof(hdr);

	list_for_each_entry(subsys, &subsys_linked_list, node) {
		char trsvcid[NVMF_TRSVCID_SIZE + 1];

		if (subsys->type != NVME_NQN_NVM)
			continue;
		list_for_each_entry(iface, &iface_linked_list, node) {
			if (!(iface->port_type & (1 << NVME_NQN_NVM)))
				continue;
			memset(&entry, 0,
			       sizeof(struct nvmf_disc_rsp_page_entry));
			entry.trtype = NVMF_TRTYPE_TCP;
			if (iface->adrfam == AF_INET)
				entry.adrfam = NVMF_ADDR_FAMILY_IP4;
			else
				entry.adrfam = NVMF_ADDR_FAMILY_IP6;
			entry.treq = 0;
			entry.portid = iface->portid;
			entry.cntlid = htole16(NVME_CNTLID_DYNAMIC);
			entry.asqsz = 32;
			entry.subtype = subsys->type;
			snprintf(trsvcid, NVMF_TRSVCID_SIZE + 1, "%d",
				 iface->port_num);
			memcpy(entry.trsvcid, trsvcid, NVMF_TRSVCID_SIZE);
			memcpy(entry.traddr, iface->address, NVMF_TRADDR_SIZE);
			strncpy(entry.subnqn, subsys->nqn, NVMF_NQN_FIELD_LEN);
			memcpy(log_ptr, &entry, sizeof(entry));
			log_ptr += sizeof(entry);
			log_len -= sizeof(entry);
		}
	}
	memcpy(data, (u8 *)log_buf + data_offset, data_len);
	print_info("Returning %llu entries offset %llu len %llu",
		   hdr.numrec, data_offset, data_len);
	free(log_buf);
	return data_len;
}

static int handle_get_log_page(struct endpoint *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0;
	u64 offset = le64toh(cmd->get_log_page.lpo), log_len;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_get_log_page opcode %02x lid %02x offset %lu len %lu",
		    cmd->get_log_page.opcode, cmd->get_log_page.lid,
		    (unsigned long)offset, (unsigned long)qe->data_len);
#endif
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
		break;
	default:
		print_err("get_log_page: lid %02x not supported",
			  cmd->get_log_page.lid);
		return NVME_SC_INVALID_FIELD;
	}
	ret = ep->ops->rma_write(ep, qe, log_len);
	if (!ret)
		ret = -1;
	else {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	return ret;
}

static int handle_read(struct endpoint *ep, struct ep_qe *qe,
		       struct nvme_command *cmd)
{
	struct nsdev *ns;
	int nsid = le32toh(cmd->rw.nsid);

	list_for_each_entry(ns, devices, node) {
		if (ns->nsid == nsid) {
			qe->ns = ns;
			break;
		}
	}
	if (!qe->ns) {
		print_err("Invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	if ((cmd->rw.dptr.sgl.type >> 4) != NVME_TRANSPORT_SGL_DATA_DESC) {
		print_err("unhandled sgl type %d\n",
			  cmd->rw.dptr.sgl.type >> 4);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	print_info("ctrl %d qid %d nsid %d tag %#x ccid %#x read pos %llu len %llu",
		   ep->ctrl->cntlid, ep->qid, nsid, qe->tag, qe->ccid,
		   qe->data_pos, qe->data_len);

	return ns->ops->ns_read(ep, qe);
}

static int handle_write(struct endpoint *ep, struct ep_qe *qe,
			struct nvme_command *cmd)
{
	struct nsdev *ns;
	u8 sgl_type = cmd->rw.dptr.sgl.type;
	int nsid = le32toh(cmd->rw.nsid);
	int ret;

	list_for_each_entry(ns, devices, node) {
		if (ns->nsid == nsid) {
			qe->ns = ns;
			break;
		}
	}
	if (!qe->ns) {
		print_err("Invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	if (sgl_type == NVME_SGL_FMT_OFFSET) {
		/* Inline data */
		print_info("ctrl %d qid %d nsid %d tag %#x ccid %#x inline write pos %llu len %llu",
			   ep->ctrl->cntlid, ep->qid, nsid, qe->tag, qe->ccid,
			   qe->data_pos, qe->data_len);
		ret = ep->ops->rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
		if (ret < 0) {
			print_err("ctrl %d qid %d tag %#x rma_read error %d",
				  ep->ctrl->cntlid, ep->qid, qe->tag, ret);
			ret = NVME_SC_WRITE_FAULT;
		}
		return ns->ops->ns_write(ep, qe);
	}
	if ((sgl_type & 0x0f) != NVME_SGL_FMT_TRANSPORT_A) {
		print_err("Invalid sgl type %x", sgl_type);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	ret = ns->ops->ns_prep_read(ep, qe);
	if (ret) {
		print_errno("prep_rma_read failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	} else
		print_info("ctrl %d qid %d nsid %d tag %#x ccid %#x write pos %llu len %llu",
			   ep->ctrl->cntlid, ep->qid, nsid, qe->tag, qe->ccid,
			   qe->data_pos, qe->data_len);

	return ret ? ret : -1;
}

int handle_request(struct endpoint *ep, struct nvme_command *cmd)
{
	struct nvme_completion *resp, _resp;
	struct ep_qe *qe;
	u32 len;
	u16 ccid;
	int ret;

	len = le32toh(cmd->common.dptr.sgl.length);
	/* ccid is considered opaque; no endian conversion */
	ccid = cmd->common.command_id;
	qe = ep->ops->acquire_tag(ep, ep->recv_pdu, ccid, 0, len);
	if (!qe) {
		resp = &_resp;
		print_err("endpoint %d ccid %#x queue busy",
			  ep->qid, ccid);
		ret = NVME_SC_NS_NOT_READY;
		goto out;
	}
	resp = &qe->resp;
	memset(resp, 0, sizeof(qe->resp));
	resp->command_id = qe->ccid;
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
			print_err("unknown fctype %d", cmd->fabrics.fctype);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (ep->qid != 0) {
		if (cmd->common.opcode == nvme_cmd_read) {
			ret = handle_read(ep, qe, cmd);
		} else if (cmd->common.opcode == nvme_cmd_write) {
			ret = handle_write(ep, qe, cmd);
		} else {
			print_err("unknown nvme I/O opcode %d",
				  cmd->common.opcode);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (cmd->common.opcode == nvme_admin_identify)
		ret = handle_identify(ep, qe, cmd);
	else if (cmd->common.opcode == nvme_admin_keep_alive) {
#ifdef DEBUG_COMMANDS
		print_debug("nvme_keep_alive ctrl %d qid %d",
			    ep->ctrl->cntlid, ep->qid);
#endif
		ret = 0;
	} else if (cmd->common.opcode == nvme_admin_get_log_page)
		ret = handle_get_log_page(ep, qe, cmd);
	else if (cmd->common.opcode == nvme_admin_set_features) {
		ret = handle_set_features(ep, qe, cmd);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else {
		print_err("unknown nvme admin opcode %d", cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	}

	if (ret < 0)
		/* Internal return; response is sent separately */
		return 0;
out:
	set_response(resp, ccid, ret, true);

	ret = ep->ops->send_rsp(ep, resp);
	ep->ops->release_tag(ep, qe);
	return ret;
}

int handle_data(struct endpoint *ep, struct ep_qe *qe, int res)
{
	return qe->ns->ops->ns_handle_qe(ep, qe, res);
}
