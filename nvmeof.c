/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nvmeof.c
 * NVMe-over-fabrics command handling.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
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
#include "configdb.h"
#include "firmware.h"

static int send_response(struct nofuse_queue *ep, struct ep_qe *qe,
			 u16 status)
{
	int ret;

	set_response(&qe->resp, qe->ccid, status, true);
	ret = ep->ops->send_rsp(ep, &qe->resp);
	ep->ops->release_tag(ep, qe);
	return ret;
}

static int handle_property_set(struct nofuse_queue *ep, struct ep_qe *qe,
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

static int handle_property_get(struct nofuse_queue *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u64 value;

	if (cmd->prop_get.offset == NVME_REG_CSTS)
		value = ep->ctrl->csts;
	else if (cmd->prop_get.offset == NVME_REG_CAP)
		value = 0x200f0003ffL;
	else if (cmd->prop_get.offset == NVME_REG_CC)
		value = ep->ctrl->cc;
	else if (cmd->prop_get.offset == NVME_REG_VS) {
		struct nvme_id_ctrl id;
		int ret;

		ret = configdb_subsys_identify_ctrl(ep->ctrl->subsysnqn, &id);
		if (ret < 0) {
			ctrl_info(ep, "%s: failed to identify controller",
				  __func__);
			return NVME_SC_INTERNAL;
		}
		value = id.ver;
	} else {
		ctrl_info(ep, "%s: offset %x: N/I",
			  __func__, cmd->prop_get.offset);
		return NVME_SC_INVALID_FIELD;
	}

	ctrl_info(ep, "nvme_fabrics_type_property_get %x: %llx",
		  cmd->prop_get.offset, value);
	qe->resp.result.u64 = htole64(value);

	return 0;
}

static int handle_set_features(struct nofuse_queue *ep, struct ep_qe *qe,
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
		if (ncqr < NVMF_NUM_QUEUES) {
			ep->ctrl->max_queues = ncqr;
		}
		if (nsqr < NVMF_NUM_QUEUES) {
			ep->ctrl->max_queues = nsqr;
		}
		qe->resp.result.u32 = htole32(ep->ctrl->max_queues << 16 |
					      ep->ctrl->max_queues);
		break;
	case NVME_FEAT_ASYNC_EVENT:
		ep->ctrl->aen_enabled = cdw11;
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

static int handle_get_features(struct nofuse_queue *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	u32 cdw10 = le32toh(cmd->common.cdw10);
	u8 fid = (cdw10 & 0xff);
	u8 sel = (cdw10 >> 8) & 0x7;
	u32 result = 0;
	int ret = NVME_SC_INVALID_FIELD;

	ctrl_info(ep,"nvme_fabrics_type_get_features cdw10 %x fid %x sel %x",
		  cdw10, fid, sel);

	switch (fid) {
	case NVME_FEAT_NUM_QUEUES:
		switch (sel) {
		case 0:
		case 2:
			result = ep->ctrl->max_queues << 16 |
				ep->ctrl->max_queues;
			break;
		case 1:
			result = NVMF_NUM_QUEUES << 16 |
				NVMF_NUM_QUEUES;
			break;
		case 3:
			result = 5;
			break;
		default:
			break;
		}
		break;
	case NVME_FEAT_ASYNC_EVENT:
		switch (sel) {
		case 0:
		case 2:
			result = ep->ctrl->aen_enabled;
			break;
		case 1:
			result = NVME_AEN_CFG_NS_ATTR |	  \
				NVME_AEN_CFG_ANA_CHANGE | \
				NVME_AEN_CFG_DISC_CHANGE;
			break;
		case 3:
			result = 5;
			break;
		default:
			break;
		}
		break;
	case NVME_FEAT_KATO:
		switch (sel) {
		case 0:
		case 2:
			result = ep->ctrl->kato * ep->kato_interval;
			break;
		case 1:
			result = RETRY_COUNT * ep->kato_interval;
			break;
		case 3:
			result = 5;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	if (result) {
		qe->resp.result.u32 = htole32(result);
		ret = 0;
	}
	return ret;
}

static int handle_connect(struct nofuse_queue *ep, struct ep_qe *qe,
			  struct nvme_command *cmd)
{
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
	if (!sqsize || sqsize > NVMF_SQ_DEPTH) {
		ctrl_err(ep, "ctrl %d qid %d invalid sqsize %u",
			 cntlid, qid, sqsize);
		return NVME_SC_CONNECT_INVALID_PARAM;
	}
	if (ep->ctrl) {
		ctrl_err(ep, "ctrl %d qid %d already connected",
			  ep->ctrl->cntlid, qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}
	if (qid == 0 && sqsize > NVMF_AQ_DEPTH)
		ep->qsize = NVMF_AQ_DEPTH;
	else
		ep->qsize = sqsize;

	ep->qid = qid;

	ret = connect_queue(ep, cntlid, connect->hostnqn, connect->subsysnqn);
	if (!ret) {
		ctrl_info(ep, "connected");
		if (qid == 0) {
			ep->ctrl->kato = kato / ep->kato_interval;
		}
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

static int handle_identify_ctrl(struct nofuse_queue *ep, u8 *id_buf, u64 len)
{
	struct nvme_id_ctrl id;
	int ret;

	memset(&id, 0, sizeof(id));

	memcpy(id.fr, firmware_rev, sizeof(id.fr));
	memset(id.mn, ' ', sizeof(id.mn));
	memset(id.sn, ' ', sizeof(id.sn));

	id.mdts = 0;
	id.cmic = NVME_CTRL_CMIC_MULTI_PORT | NVME_CTRL_CMIC_MULTI_CTRL |
		NVME_CTRL_CMIC_ANA;
	id.cntlid = htole16(ep->ctrl->cntlid);
	id.lpa = (1 << 2);
	id.sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id.kas = ep->kato_interval / 100; /* KAS is in units of 100 msecs */
	id.ctratt = htole32(NVME_CTRL_ATTR_HID_128_BIT |
			    NVME_CTRL_ATTR_TBKAS);
	id.ioccsz = NVME_NVM_IOSQES;
	id.iorcsz = NVME_NVM_IOCQES;
	id.oaes = htole32(NVME_AEN_CFG_NS_ATTR | NVME_AEN_CFG_ANA_CHANGE | \
			  NVME_AEN_CFG_DISC_CHANGE);
	id.acl = 3;
	id.aerl = NVME_NR_AEN_COMMANDS - 1;
	id.nn = htole32(MAX_NSID);
	id.mnan = htole32(MAX_NSID);
	id.sqes = (0x6 << 4) | 0x6;
	id.cqes = (0x4 << 4) | 0x4;

	ret = configdb_subsys_identify_ctrl(ep->ctrl->subsysnqn, &id);
	if (ret < 0)
		return ret;

	id.maxcmd = htole16(ep->qsize);

	id.anacap = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4);
	id.anatt = 10;
	id.anagrpmax = htole32(MAX_ANAGRPID);
	id.nanagrpid = htole32(MAX_ANAGRPID);
	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify_ns(struct nofuse_queue *ep, u32 nsid,
			      u8 *id_buf, u64 len)
{
	struct nofuse_namespace *ns;
	struct nvme_id_ns id;
	int ret, anagrp;

	ns = find_namespace(ep->ctrl->subsysnqn, nsid);
	if (!ns || !ns->size)
		return NVME_SC_INVALID_NS | NVME_SC_DNR;

	ret = configdb_get_namespace_anagrp(ep->ctrl->subsysnqn, nsid,
					    &anagrp);
	if (ret < 0) {
		ctrl_info(ep, "nsid %u error %d retrieving ana grp",
			  nsid, ret);
		anagrp = 0;
	}

	memset(&id, 0, sizeof(id));

	id.nsze = (u64)ns->size / ns->blksize;
	id.ncap = id.nsze;
	id.nlbaf = 1;
	id.flbas = 0;
	if (anagrp > 0) {
		id.nmic = 1;
		id.anagrpid = anagrp;
	}
	id.lbaf[0].ds = 12;
	if (ns->readonly)
		id.nsattr = 1;

	if (len > sizeof(id))
		len = sizeof(id);

	memcpy(id_buf, &id, len);

	return len;
}

static int handle_identify_active_ns(struct nofuse_queue *ep,
				     u8 *id_buf, u64 len)
{
	int ret;

	memset(id_buf, 0, len);
	ret = configdb_identify_active_ns(ep->ctrl->subsysnqn,
					  id_buf, len);
	if (ret < 0)
		return ret;

	return len;
}

static int parse_guid(u8 *guid, size_t guid_len, const char *guid_str)
{
	int i;
	unsigned long val, _val;
	char part[11];

	for (i = 0; i < guid_len; i+=4) {
		char *eptr = NULL;

		memset(part, 0, 11);
		memcpy(part, "0x", 2);
		memcpy(part + 2, guid_str, 8);
		_val = strtoul(part, &eptr, 16);
		if (_val == ULONG_MAX || part == eptr)
			return -EINVAL;
		val = htobe32(_val);
		memcpy(guid, &val, 4);
		guid += 4;
		guid_str += 8;
	}
	return 0;
}

static int handle_identify_ns_desc_list(struct nofuse_queue *ep, u32 nsid,
					u8 *desc_list, u64 len)
{
	int desc_len = len, ret;
	struct nvme_ns_id_desc *desc;
	char uid_str[37];
	uuid_t uuid;
	u8 *desc_list_save = desc_list;

	memset(desc_list, 0, len);
	ret = configdb_get_namespace_attr(ep->ctrl->subsysnqn, nsid,
					  "device_uuid", uid_str);
	if (ret < 0)
		return ret;
	ret = uuid_parse(uid_str, uuid);
	if (ret < 0)
		return ret;

	if (desc_len < sizeof(*desc) + NVME_NIDT_UUID_LEN)
		return -EINVAL;
	desc = (struct nvme_ns_id_desc *)desc_list;
	desc->nidt = NVME_NIDT_UUID;
        desc->nidl = NVME_NIDT_UUID_LEN;
	desc_list += sizeof(*desc);
	desc_len -= sizeof(*desc);
	memcpy(&desc_list[4], uuid, desc->nidl);
	desc_list += desc->nidl;
	desc_len -= desc->nidl;

	if (desc_len < sizeof(*desc) + NVME_NIDT_NGUID_LEN) {
		ctrl_info(ep, "no space for nguid");
		goto parse_eui64;
	}
	ret = configdb_get_namespace_attr(ep->ctrl->subsysnqn, nsid,
					  "device_nguid", uid_str);
	if (!ret) {
		desc = (struct nvme_ns_id_desc *)desc_list;
		desc->nidt = NVME_NIDT_NGUID;
		desc->nidl = NVME_NIDT_NGUID_LEN;
		desc_list += sizeof(*desc);
		desc_len -= sizeof(*desc);
		ret = parse_guid(desc_list, NVME_NIDT_NGUID_LEN, uid_str);
		if (ret) {
			ctrl_info(ep, "failed to parse nguid, error %d", ret);
			desc_list = (u8 *)desc;
		} else {
			desc_list += desc->nidl;
			desc_len -= desc->nidl;
		}
	} else
		ctrl_info(ep, "no nguid");

parse_eui64:
	if (desc_len < sizeof(*desc) + NVME_NIDT_EUI64_LEN) {
		ctrl_info(ep, "no space for eu64");
		goto done;
	}
	ret = configdb_get_namespace_attr(ep->ctrl->subsysnqn, nsid,
					  "device_eui64", uid_str);
	if (!ret) {
		desc = (struct nvme_ns_id_desc *)desc_list;
		desc->nidt = NVME_NIDT_EUI64;
		desc->nidl = NVME_NIDT_EUI64_LEN;
		desc_list += sizeof(*desc);
		desc_len -= sizeof(*desc);
		ret = parse_guid(desc_list, NVME_NIDT_EUI64_LEN, uid_str);
		if (ret) {
			ctrl_info(ep, "failed to parse eui64, error %d", ret);
			desc_list = (u8 *)desc;
		} else {
			desc_list += desc->nidl;
			desc_len -= desc->nidl;
		}
	} else
		ctrl_info(ep, "no eui64");
done:
	if (desc_len < sizeof(*desc) + NVME_NIDT_CSI_LEN)
		return len;

	desc = (struct nvme_ns_id_desc *)desc_list;
	desc->nidt = NVME_NIDT_CSI;
	desc->nidl = NVME_NIDT_CSI_LEN;
	desc_list += sizeof(*desc);
	desc_len -= sizeof(*desc);
	desc_list[0] = 0;
	desc_list += desc->nidl;
	desc_len -= desc->nidl;
	printf("%s: desc nidt %d nidl %d len %ld\n", __func__,
	       desc->nidt, desc->nidl, desc_list - desc_list_save);

	return len;
}

static int handle_identify(struct nofuse_queue *ep, struct ep_qe *qe,
			   struct nvme_command *cmd)
{
	u8 cns = cmd->identify.cns;
	u8 csi = cmd->identify.csi;
	u32 nsid = le32toh(cmd->identify.nsid);
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
		if (id_len < 0) {
			return NVME_SC_INTERNAL;
		}
		break;
	case NVME_ID_CNS_NS_ACTIVE_LIST:
		id_len = handle_identify_active_ns(ep, qe->data, qe->data_len);
		break;
	case NVME_ID_CNS_NS_DESC_LIST:
		id_len = handle_identify_ns_desc_list(ep, nsid,
						      qe->data, qe->data_len);
		break;
	case NVME_ID_CNS_CS_CTRL:
		if (csi == 0) {
			id_len = handle_identify_ctrl(ep, qe->data,
						      qe->data_len);
			if (id_len < 0)
				return NVME_SC_INTERNAL;
			break;
		}
		ctrl_err(ep, "unsupported identify ctrl csi %u\n", csi);
		return NVME_SC_BAD_ATTRIBUTES | NVME_SC_DNR;
	default:
		ctrl_err(ep, "unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES | NVME_SC_DNR;
	}

	if (id_len < 0)
		return NVME_SC_INVALID_NS;

	qe->data_pos = 0;
	ret = ep->ops->rma_write(ep, qe, id_len);
	if (ret)
		ctrl_err(ep, "rma_write failed with %d", ret);
	return ret;
}

static int format_disc_log(struct nofuse_queue *ep,
			   void *data, u64 data_offset, u64 data_len)
{
	int len, log_len, genctr, num_recs = 0, ret;
	u8 *log_buf;
	struct nvmf_disc_rsp_page_hdr *log_hdr;
	struct nvmf_disc_rsp_page_entry *log_ptr;

	len = configdb_host_disc_entries(ep->ctrl->hostnqn, NULL, 0);
	if (len < 0) {
		ctrl_err(ep, "error formatting discovery log page");
		return len;
	}
	num_recs = len / sizeof(struct nvmf_disc_rsp_page_entry);
	log_len = len + sizeof(struct nvmf_disc_rsp_page_hdr);
	log_buf = malloc(log_len);
	if (!log_buf) {
		ctrl_err(ep, "error allocating discovery log");
		return -ENOMEM;
	}
	memset(log_buf, 0, log_len);
	log_hdr = (struct nvmf_disc_rsp_page_hdr *)log_buf;
	log_ptr = log_hdr->entries;

	if (num_recs) {
		len = configdb_host_disc_entries(ep->ctrl->hostnqn,
					      (u8 *)log_ptr, len);
		if (len < 0) {
			ctrl_err(ep, "error fetching discovery log entries");
			num_recs = 0;
		}
	}

	ret = configdb_host_genctr(ep->ctrl->hostnqn, &genctr);
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
	ep->ctrl->aen_masked &= ~NVME_AEN_CFG_DISC_CHANGE;
	return log_len;
}

static int format_ana_log(struct nofuse_queue *ep,
			  void *data, u64 data_offset, u64 data_len)
{
	int len, log_len;
	u8 *log_buf, *grp_ptr;
	struct nvme_ana_rsp_hdr *log_hdr;
	struct nvme_ana_group_desc *desc;
	int grp;

	log_len = sizeof(*log_hdr) +
		MAX_ANAGRPID * sizeof(struct nvme_ana_group_desc) +
		MAX_NSID * sizeof(u32);
	log_buf = malloc(log_len);
	if (!log_buf) {
		ctrl_err(ep, "error allocating ana log");
		return -ENOMEM;
	}
	memset(log_buf, 0, log_len);
	log_hdr = (struct nvme_ana_rsp_hdr *)log_buf;

	len = configdb_ana_log_entries(ep->ctrl->subsysnqn,
				       ep->port->portid,
				       log_buf, log_len);
	if (len < 0) {
		ctrl_err(ep, "error fetching ana log entries");
		log_hdr->ngrps = 0;
	}

	grp_ptr = (u8 *)log_hdr->entries;
	for (grp = 0; grp < le32toh(log_hdr->ngrps); grp++) {
		desc = (struct nvme_ana_group_desc *)grp_ptr;
		ctrl_info(ep, "ANA grp %d (state %d, chgcnt %lu)",
			  desc->grpid, desc->state, le64toh(desc->chgcnt));
		grp_ptr += sizeof(*desc);
		grp_ptr += le32toh(desc->nnsids) * sizeof(u32);
	}
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
	ctrl_info(ep, "ana log page entries %d offset %llu len %d",
		  le32toh(log_hdr->ngrps), data_offset, log_len);
	free(log_buf);
	ep->ctrl->aen_masked &= ~~NVME_AEN_CFG_ANA_CHANGE;
	return log_len;
}

static int format_ns_chg_log(struct nofuse_queue *ep,
			     void *data, u64 data_offset, u64 data_len)
{
	int len, log_len;
	u8 *log_buf;

	log_len = 1024 * sizeof(u32);
	log_buf = malloc(log_len);
	if (!log_buf) {
		ctrl_err(ep, "error allocating ana log");
		return -ENOMEM;
	}
	memset(log_buf, 0, log_len);
	len = configdb_ns_changed_log_entries(ep->ctrl->subsysnqn,
					      ep->ctrl->cntlid,
					      log_buf, log_len);
	if (len < 0) {
		ctrl_err(ep, "error fetching ns changed log entries");
		memset(log_buf, 0, log_len);
	}

	if (log_len < data_offset) {
		ctrl_err(ep, "offset %llu beyond log pag size %d",
			 data_offset, log_len);
		log_len = 0;
	} else {
		log_len += data_offset;
		if (log_len > data_len)
			log_len = data_len;
		memcpy(data, log_buf + data_offset, log_len);
	}
	ctrl_info(ep, "ns changed entries %ld offset %llu len %d",
		  len / sizeof(u32), data_offset, log_len);
	free(log_buf);
	ep->ctrl->aen_masked &= ~NVME_AEN_CFG_NS_ATTR;
	return data_len;
}

static int handle_get_log_page(struct nofuse_queue *ep, struct ep_qe *qe,
			       struct nvme_command *cmd)
{
	int ret = 0, log_len;
	u64 offset = le64toh(cmd->get_log_page.lpo);

	ctrl_info(ep, "nvme_get_log_page opcode %02x lid %02x offset %lu len %lu",
		  cmd->get_log_page.opcode, cmd->get_log_page.lid,
		  (unsigned long)offset, (unsigned long)qe->data_len);

	qe->data_pos = offset;
	switch (cmd->get_log_page.lid) {
	case NVME_LOG_SMART:
		/* SMART Log */
		log_len = qe->data_len;
		memset(qe->data, 0, log_len);
		break;
	case NVME_LOG_CHANGED_NS:
		/* Changed Namespace Log */
		log_len = format_ns_chg_log(ep, qe->data, qe->data_pos,
					    qe->data_len);
		if (log_len < 0) {
			ctrl_err(ep, "%s: changed namespace log failed",
				 __func__);
			return NVME_SC_INTERNAL;
		}
		break;
	case NVME_LOG_ANA:
		/* ANA Log */
		log_len = format_ana_log(ep, qe->data, qe->data_pos,
					 qe->data_len);
		if (log_len < 0) {
			ctrl_err(ep, "%s: ana log failed",
				 __func__);
			return NVME_SC_INTERNAL;
		}
		break;
	case NVME_LOG_DISC:
		/* Discovery log */
		log_len = format_disc_log(ep, qe->data, qe->data_pos,
					  qe->data_len);
		if (log_len < 0) {
			ctrl_err(ep, "%s: discovery log failed",
				__func__);
			return NVME_SC_INTERNAL;
		}
		break;
	default:
		ctrl_err(ep, "%s: lid %02x not supported",
			 __func__, cmd->get_log_page.lid);
		return NVME_SC_INVALID_FIELD;
	}
	ret = ep->ops->rma_write(ep, qe, log_len);
	if (ret)
		ctrl_err(ep, "rma_write failed with error %d", ret);

	return ret;
}

static int handle_read(struct nofuse_queue *ep, struct ep_qe *qe,
		       struct nvme_command *cmd)
{
	u32 nsid = le32toh(cmd->rw.nsid);

	qe->ns = find_namespace(ep->ctrl->subsysnqn, nsid);
	if (!qe->ns) {
		ctrl_err(ep, "invalid nsid %u", nsid);
		return NVME_SC_INVALID_NS;
	}

	if ((cmd->rw.dptr.sgl.type >> 4) != NVME_TRANSPORT_SGL_DATA_DESC) {
		ctrl_err(ep, "unhandled sgl type %d\n",
			  cmd->rw.dptr.sgl.type >> 4);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * qe->ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	ctrl_info(ep, "nsid %u tag %#x ccid %#x read pos %llu len %llu",
		  nsid, qe->tag, qe->ccid, qe->data_pos, qe->data_len);

	return qe->ns->ops->ns_read(ep, qe);
}

static int handle_write(struct nofuse_queue *ep, struct ep_qe *qe,
			struct nvme_command *cmd)
{
	u8 sgl_type = cmd->rw.dptr.sgl.type;
	u32 nsid = le32toh(cmd->rw.nsid);
	int ret;

	qe->ns = find_namespace(ep->ctrl->subsysnqn, nsid);
	if (!qe->ns) {
		ctrl_err(ep, "invalid namespace %d", nsid);
		return NVME_SC_INVALID_NS;
	}

	qe->data_pos = le64toh(cmd->rw.slba) * qe->ns->blksize;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;

	if (sgl_type == NVME_SGL_FMT_OFFSET) {
		/* Inline data */
		ctrl_info(ep, "nsid %u tag %#x ccid %#x inline write pos %llu len %llu",
			   nsid, qe->tag, qe->ccid,
			   qe->data_pos, qe->data_len);
		ret = ep->ops->rma_read(ep, qe->iovec.iov_base, qe->iovec.iov_len);
		if (ret < 0) {
			ctrl_err(ep, "tag %#x rma_read error %d",
				 qe->tag, ret);
			return ret;
		}
		return qe->ns->ops->ns_write(ep, qe);
	}
	if ((sgl_type & 0x0f) != NVME_SGL_FMT_TRANSPORT_A) {
		ctrl_err(ep, "Invalid sgl type %x", sgl_type);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	ret = qe->ns->ops->ns_prep_read(ep, qe);
	if (ret) {
		ctrl_err(ep, "prep_rma_read failed with error %d", ret);
	} else
		ctrl_info(ep, "nsid %u tag %#x ccid %#x write pos %llu len %llu",
			  nsid, qe->tag, qe->ccid, qe->data_pos, qe->data_len);

	return ret;
}

int handle_request(struct nofuse_queue *ep, struct nvme_command *cmd)
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
		ctrl_info(ep, "tag %#x ccid %#x nvme_keep_alive",
			  qe->tag, qe->ccid);
		kato_reset_counter(ep->ctrl);
		ret = 0;
	} else if (cmd->common.opcode == nvme_admin_get_log_page) {
		ret = handle_get_log_page(ep, qe, cmd);
		if (!ret)
			return 0;
	} else if (cmd->common.opcode == nvme_admin_set_features) {
		ret = handle_set_features(ep, qe, cmd);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else if (cmd->common.opcode == nvme_admin_get_features) {
		ret = handle_get_features(ep, qe, cmd);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
	} else if (cmd->common.opcode == nvme_admin_async_event) {
		ctrl_info(ep, "tag %#x ccid %#x nvme_async_event",
			  qe->tag, qe->ccid);
		qe->aen = true;
		return 0;
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

int handle_data(struct nofuse_queue *ep, struct ep_qe *qe, int res)
{
	return qe->ns->ops->ns_handle_qe(ep, qe, res);
}
