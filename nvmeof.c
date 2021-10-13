#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"
#include "nvme.h"

#define NVME_DISC_CTRL 1
#define NVME_IO_CTRL   2

#define NVME_VER ((1 << 16) | (4 << 8)) /* NVMe 1.4 */

static int nvmf_discovery_genctr = 1;
static int nvmf_ctrl_id = 1;

static int handle_property_set(struct nvme_command *cmd, struct endpoint *ep)
{
	int			 ret = 0;

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

static int handle_property_get(struct nvme_command *cmd,
			       struct nvme_completion *resp,
			       struct endpoint *ep)
{
	u64			 value;

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
	resp->result.u64 = htole64(value);

	return 0;
}

static int handle_set_features(struct endpoint *ep, struct nvme_command *cmd,
			       struct nvme_completion *resp)
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
		resp->result.u32 = htole32(ep->ctrl->max_endpoints << 16 |
					   ep->ctrl->max_endpoints);
		break;
	case NVME_FEAT_ASYNC_EVENT:
		ep->ctrl->aen_mask = cdw11;
		break;
	case NVME_FEAT_KATO:
		ep->ctrl->kato = cdw11 / DELAY_TIMEOUT; /* in msecs */
		break;
	default:
		ret = NVME_SC_FEATURE_NOT_CHANGEABLE;
	}
	return ret;
}

static int handle_connect(struct endpoint *ep, int qid, u64 len)
{
	struct subsystem *subsys = NULL, *_subsys;
	struct ctrl_conn *ctrl;
	struct nvmf_connect_data *data = ep->data;
	int ret;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_connect");
#endif

	ret = ep->ops->rma_read(ep->ep, ep->data, len);
	if (ret) {
		print_errno("rma_read failed", ret);
		return ret;
	}

	if (ep->ctrl) {
		print_err("ctrl %d qid %d already connected",
			  ep->ctrl->cntlid, ep->qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}

	ep->qid = qid;

	list_for_each_entry(_subsys, &subsys_linked_list, node) {
		if (!strcmp(data->subsysnqn, _subsys->nqn)) {
			subsys = _subsys;
			break;
		}
	}
	if (!subsys) {
		print_err("subsystem '%s' not found",
			  data->subsysnqn);
		return NVME_SC_CONNECT_INVALID_HOST;
	}

	list_for_each_entry(ctrl, &subsys->ctrl_list, node) {
		if (!strncmp(ctrl->nqn, data->hostnqn, MAX_NQN_SIZE)) {
			ep->ctrl = ctrl;
			break;
		}
	}
	if (!ep->ctrl) {
		print_info("Allocating new controller '%s'", data->hostnqn);
		ctrl = malloc(sizeof(*ctrl));
		if (!ctrl) {
			print_err("Out of memory allocating controller");
			goto out;
		}
		memset(ctrl, 0, sizeof(*ctrl));
		strncpy(ctrl->nqn, data->hostnqn, MAX_NQN_SIZE);
		ctrl->max_endpoints = NVMF_NUM_QUEUES;
		ep->ctrl = ctrl;
		ctrl->subsys = subsys;
		if (!strncmp(subsys->nqn, NVME_DISC_SUBSYS_NAME,
			     MAX_NQN_SIZE)) {
			ctrl->ctrl_type = NVME_DISC_CTRL;
			ctrl->qsize = NVMF_DQ_DEPTH;
		} else {
			ctrl->ctrl_type = NVME_IO_CTRL;
			ctrl->qsize = NVMF_SQ_DEPTH;
		}
		list_add(&ctrl->node, &subsys->ctrl_list);
	}
	ctrl = ep->ctrl;

	if (qid == 0) {
		if (data->cntlid != 0xffff) {
			print_err("bad controller id %x, expecting %x",
				  data->cntlid, 0xffff);
			ret = NVME_SC_CONNECT_INVALID_PARAM;
		}
		ctrl->cntlid = nvmf_ctrl_id++;
	} else if (le16toh(data->cntlid) != ctrl->cntlid) {
		print_err("bad controller id %x for queue %d, expecting %x",
			  data->cntlid, qid, ctrl->cntlid);
		ret = NVME_SC_CONNECT_INVALID_PARAM;
	}
	print_info("ctrl %d qid %d connected", ep->ctrl->cntlid, ep->qid);
out:
	return ret;
}

static int handle_identify_ctrl(struct endpoint *ep, u64 len)
{
	struct nvme_id_ctrl *id = ep->data;

	memset(id, 0, sizeof(*id));

	memset(id->fr, ' ', sizeof(id->fr));
	strncpy((char *) id->fr, " ", sizeof(id->fr));

	id->mdts = 0;
	id->cntlid = htole16(ep->ctrl->cntlid);
	id->ver = htole32(NVME_VER);
	id->lpa = (1 << 2);
	id->sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id->kas = DELAY_TIMEOUT / 100; /* KAS is in units of 100 msecs */

	if (ep->ctrl->ctrl_type == NVME_DISC_CTRL) {
		strcpy(id->subnqn, NVME_DISC_SUBSYS_NAME);
		id->maxcmd = htole16(NVMF_DQ_DEPTH);
	} else {
		strcpy(id->subnqn, ep->ctrl->subsys->nqn);
		id->maxcmd = htole16(ep->ctrl->qsize);
	}

	if (len > sizeof(*id))
		len = sizeof(*id);

	return len;
}

static int handle_identify_ns(struct endpoint *ep, u32 nsid, u64 len)
{
	struct nsdev *ns = NULL, *_ns;
	struct nvme_id_ns *id = ep->data;

	memset(id, 0, len);
	list_for_each_entry(_ns, devices, node) {
		if (_ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns)
		return -ENODEV;

	memset(id, 0, sizeof(*id));

	id->nsze = ns->size / ns->blksize;
	id->ncap = id->nsze;
	id->nlbaf = 1;
	id->flbas = 0;
	id->lbaf[0].ds = 12;
	if (len > sizeof(*id))
		len = sizeof(*id);

	return len;
}

static int handle_identify_active_ns(struct endpoint *ep, u64 len)
{
	struct nsdev *ns;
	u8 *ns_list = ep->data;
	int id_len = len;

	memset(ns_list, 0, len);
	list_for_each_entry(ns, devices, node) {
		u16 nsid = htole16(ns->nsid);
		if (len < 2)
			break;
		memcpy(ns_list, &nsid, 2);
		ns_list += 2;
		len -= 2;
	}
	return id_len;
}

static int handle_identify_ns_desc_list(struct endpoint *ep, u32 nsid, u64 len)
{
	struct nsdev *ns = NULL, *_ns;
	u8 *desc_list = ep->data;
	int desc_len = len;

	memset(desc_list, 0, len);
	list_for_each_entry(_ns, devices, node) {
		if (_ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (ns) {
		desc_list[0] = 3;
		desc_list[1] = 0x10;
		memcpy(&desc_list[2], ns->uuid, 0x10);
		desc_list += 0x12;
		len -= 0x12;
		desc_list[0] = 4;
		desc_list[1] = 1;
		desc_list[2] = 0;
		len -= 3;
	}
	return desc_len;
}

static int handle_identify(struct endpoint *ep, struct nvme_command *cmd,
			   u64 len)
{
	int cns = cmd->identify.cns;
	int nsid = le32toh(cmd->identify.nsid);
	int ret, id_len;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_identify cns %d", cns);
#endif

	switch (cns) {
	case NVME_ID_CNS_NS:
		id_len = handle_identify_ns(ep, nsid, len);
		break;
	case NVME_ID_CNS_CTRL:
		id_len = handle_identify_ctrl(ep, len);
		break;
	case NVME_ID_CNS_NS_ACTIVE_LIST:
		id_len = handle_identify_active_ns(ep, len);
		break;
	case NVME_ID_CNS_NS_DESC_LIST:
		id_len = handle_identify_ns_desc_list(ep, nsid, len);
		break;
	default:
		print_err("unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES;
	}

	ret = ep->ops->rma_write(ep->ep, ep->data, id_len, cmd, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}

	return ret;
}

static int format_disc_log(void *data, u64 data_len, struct endpoint *ep)
{
	struct subsystem *subsys;
	struct nvmf_disc_rsp_page_hdr hdr;
	struct nvmf_disc_rsp_page_entry entry;
	u64 log_len = data_len;

	hdr.genctr = nvmf_discovery_genctr;
	hdr.recfmt = 0;
	hdr.numrec = 0;
	list_for_each_entry(subsys, &subsys_linked_list, node) {
		if (subsys->type == NVME_NQN_DISC)
			continue;
		hdr.numrec++;
	}
	print_info("Found %llu subsystems", hdr.numrec);

	if (data_len < sizeof(hdr)) {
		memcpy(data, &hdr, data_len);
		return data_len;
	}
	memcpy(data, &hdr, sizeof(hdr));

	data_len -= sizeof(hdr);
	data += sizeof(hdr);
	list_for_each_entry(subsys, &subsys_linked_list, node) {
		char trsvcid[NVMF_TRSVCID_SIZE + 1];

		if (subsys->type != NVME_NQN_NVME)
			continue;
		memset(&entry, 0, sizeof(struct nvmf_disc_rsp_page_entry));
		entry.trtype = NVMF_TRTYPE_TCP;
		entry.adrfam = ep->iface->adrfam;
		entry.treq = 0;
		entry.portid = ep->iface->portid;
		entry.cntlid = htole16(NVME_CNTLID_DYNAMIC);
		entry.asqsz = 32;
		entry.subtype = subsys->type;
		snprintf(trsvcid, NVMF_TRSVCID_SIZE + 1, "%d",
			 ep->iface->port_num);
		memcpy(entry.trsvcid, trsvcid, NVMF_TRSVCID_SIZE);
		memcpy(entry.traddr, ep->iface->address, NVMF_TRADDR_SIZE);
		strncpy(entry.subnqn, subsys->nqn, NVMF_NQN_FIELD_LEN);
		if (data_len < sizeof(entry)) {
			memcpy(data, &entry, data_len);
			data_len = 0;
			break;
		}
		memcpy(data, &entry, sizeof(entry));
		data += sizeof(entry);
		data_len -= sizeof(entry);
	}
	print_info("Returning %llu entries len %llu", hdr.numrec,
		   log_len - data_len);
	return log_len - data_len;
}

static int handle_get_log_page(struct endpoint *ep, struct nvme_command *cmd,
			       u64 len)
{
	int ret = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_get_log_page opcode %02x lid %02x len %lu",
		    cmd->get_log_page.opcode, cmd->get_log_page.lid,
		    (unsigned long)len);
#endif

	switch (cmd->get_log_page.lid) {
	case 0x02:
		/* SMART Log */
		memset(ep->data, 0, len);
		break;
	case 0x70:
		/* Discovery log */
		len = format_disc_log(ep->data, len, ep);
		break;
	default:
		print_err("get_log_page: lid %02x not supported",
			  cmd->get_log_page.lid);
		return NVME_SC_INVALID_FIELD;
	}

	ret = ep->ops->rma_write(ep->ep, ep->data, len, cmd, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}

	return ret;
}

static int handle_read(struct endpoint *ep, struct nvme_command *cmd,
		       u64 len)
{
	struct nsdev *ns = NULL, *_ns;
	int nsid = le32toh(cmd->rw.nsid);
	u64 pos, data_len;
	void *buf;
	int ret;

	list_for_each_entry(_ns, devices, node) {
		if (_ns->nsid == nsid) {
			ns = _ns;
			break;
		}
	}
	if (!ns) {
		print_err("Invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	if ((cmd->rw.dptr.sgl.type >> 4) != NVME_TRANSPORT_SGL_DATA_DESC) {
		print_err("unhandled sgl type %d\n",
			  cmd->rw.dptr.sgl.type >> 4);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	pos = le64toh(cmd->rw.slba) * ns->blksize;
	data_len = le64toh(cmd->rw.dptr.sgl.length);
	print_info("ctrl %d qid %d nsid %d read pos %llu len %llu",
		   ep->ctrl->cntlid, ep->qid, nsid, pos, data_len);
	buf = malloc(data_len);
	if (!buf)
		return NVME_SC_NS_NOT_READY;
	memset(buf, 0, data_len);
	ret = ep->ops->rma_write(ep->ep, buf, data_len, cmd, true);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}
	free(buf);
	return ret;
}

int handle_request(struct endpoint *ep, void *buf, int length)
{
	struct nvme_command		*cmd = (struct nvme_command *) buf;
	struct nvme_completion		*resp = (void *) ep->cmd;
	struct nvmf_connect_command	*c = &cmd->connect;
	u32				 len;
	int				 ret;

	len = le32toh(c->dptr.sgl.length);

	memset(resp, 0, sizeof(*resp));

	resp->command_id = c->command_id;

	UNUSED(length);

	if (cmd->common.opcode == nvme_fabrics_command) {
		switch (cmd->fabrics.fctype) {
		case nvme_fabrics_type_property_set:
			ret = handle_property_set(cmd, ep);
			break;
		case nvme_fabrics_type_property_get:
			ret = handle_property_get(cmd, resp, ep);
			break;
		case nvme_fabrics_type_connect:
			ret = handle_connect(ep, cmd->connect.qid, len);
			if (!ret)
				resp->result.u16 = htole16(ep->ctrl->cntlid);
			break;
		default:
			print_err("unknown fctype %d", cmd->fabrics.fctype);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (ep->qid != 0) {
		if (cmd->common.opcode == nvme_cmd_read)
			ret = handle_read(ep, cmd, len);
	} else if (cmd->common.opcode == nvme_admin_identify)
		ret = handle_identify(ep, cmd, len);
	else if (cmd->common.opcode == nvme_admin_keep_alive)
		ret = 0;
	else if (cmd->common.opcode == nvme_admin_get_log_page)
		ret = handle_get_log_page(ep, cmd, len);
	else if (cmd->common.opcode == nvme_admin_set_features) {
		ret = handle_set_features(ep, cmd, resp);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else {
		print_err("unknown nvme opcode %d", cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	}

	if (ret)
		resp->status = (NVME_SC_DNR | ret) << 1;

	return ep->ops->send_rsp(ep->ep, resp, sizeof(*resp));
}
