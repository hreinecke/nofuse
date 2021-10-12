#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "common.h"
#include "ops.h"

#define RETRY_COUNT	1200	// 2 min since multiplier of delay timeout
#define DELAY_TIMEOUT	100	// ms
#define KATO_INTERVAL	500	// ms per spec

#define NVME_VER ((1 << 16) | (4 << 8)) /* NVMe 1.4 */

static int nvmf_discovery_genctr = 1;
static int nvmf_ctrl_id = 1;

static LINKED_LIST(endpoint_linked_list);

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
			ep->ctrl->csts = NVME_CSTS_SHTS_CMPLT;
		else {
			if (ep->ctrl->cc & NVME_CC_ENABLE)
				ep->ctrl->csts = NVME_CSTS_RDY;
			else
				ep->ctrl->csts = NVME_CSTS_SHTS_CMPLT;
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
	resp->result.U64 = htole64(value);

	return 0;
}

static int handle_set_features(struct endpoint *ep, struct nvme_command *cmd,
			       struct nvme_completion *resp)
{
	u32 cdw10 = le32toh(cmd->common.cdw10[0]);
	u32 cdw11 = le32toh(cmd->common.cdw10[1]);
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
		resp->result.U32 = htole32(ep->ctrl->max_endpoints << 16 |
					   ep->ctrl->max_endpoints);
		break;
	case NVME_FEAT_ASYNC_EVENT:
		ep->ctrl->aen_mask = cdw11;
		break;
	case NVME_FEAT_KATO:
		ep->ctrl->kato = cdw11 * (KATO_INTERVAL / DELAY_TIMEOUT);
		break;
	default:
		ret = NVME_SC_FEATURE_NOT_CHANGEABLE;
	}
	return ret;
}

static int handle_connect(struct endpoint *ep, int qid, u64 addr, u64 len)
{
	struct subsystem *subsys = NULL, *_subsys;
	struct ctrl_conn *ctrl;
	struct nvmf_connect_data *data = ep->data;
	int ret;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_connect");
#endif

	ret = ep->ops->rma_read(ep->ep, ep->data, addr, len);
	if (ret) {
		print_errno("rma_read failed", ret);
		return ret;
	}

	if (ep->ctrl) {
		print_err("ctrl %d qid %d already connected",
			  ep->ctrl->cntlid, ep->qid);
		return NVME_SC_CONNECT_CTRL_BUSY;
	}

	print_info("host '%s' qid %d connected", data->hostnqn, qid);
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
		ctrl->kato = RETRY_COUNT;
		ctrl->max_endpoints = NVMF_NUM_QUEUES;
		ep->ctrl = ctrl;
		ctrl->subsys = subsys;
		if (!strncmp(subsys->nqn, NVME_DISC_SUBSYS_NAME,
			     MAX_NQN_SIZE))
			ctrl->ctrl_type = NVME_DISC_CTRL;
		else
			ctrl->ctrl_type = NVME_IO_CTRL;
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
	id->maxcmd = htole16(NVMF_DQ_DEPTH);
	id->sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id->kas = 10;

	if (ep->ctrl->ctrl_type == NVME_DISC_CTRL)
		strcpy(id->subnqn, NVME_DISC_SUBSYS_NAME);
	else
		strcpy(id->subnqn, ep->ctrl->subsys->nqn);

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
		if (len < 4)
			break;
		memcpy(ns_list, &nsid, 4);
		ns_list += 4;
		len -= 4;
	}
	return id_len;
}

static int handle_identify(struct endpoint *ep, struct nvme_command *cmd,
			   u64 addr, u64 len)
{
	int cns = htole32(cmd->identify.cns);
	int ret, id_len;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_identify cns %d", cns);
#endif

	switch (cns) {
	case NVME_ID_CNS_CTRL:
		id_len = handle_identify_ctrl(ep, len);
		break;
	case NVME_ID_CNS_ACTIVE_NS:
		id_len = handle_identify_active_ns(ep, len);
		break;
	default:
		print_err("unexpected identify command cns %u", cns);
		return NVME_SC_BAD_ATTRIBUTES;
	}

	ret = ep->ops->rma_write(ep->ep, ep->data, addr, id_len, cmd);
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
			       u64 addr, u64 len)
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

	ret = ep->ops->rma_write(ep->ep, ep->data, addr, len, cmd);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}

	return ret;
}

static int handle_request(struct endpoint *ep, void *buf, int length)
{
	struct nvme_command		*cmd = (struct nvme_command *) buf;
	struct nvme_completion		*resp = (void *) ep->cmd;
	struct nvmf_connect_command	*c = &cmd->connect;
	u64				 addr;
	u32				 len;
	int				 ret;

	addr	= c->dptr.ksgl.addr;
	len	= get_unaligned_le24(c->dptr.ksgl.length);

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
			ret = handle_connect(ep, cmd->connect.qid, addr, len);
			if (!ret)
				resp->result.U16 = htole16(ep->ctrl->cntlid);
			break;
		default:
			print_err("unknown fctype %d", cmd->fabrics.fctype);
			ret = NVME_SC_INVALID_OPCODE;
		}
	} else if (cmd->common.opcode == nvme_admin_identify)
		ret = handle_identify(ep, cmd, addr, len);
	else if (cmd->common.opcode == nvme_admin_keep_alive)
		ret = 0;
	else if (cmd->common.opcode == nvme_admin_get_log_page)
		ret = handle_get_log_page(ep, cmd, addr, len);
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

static void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	int ret;

	while (!stopped) {
		struct timeval timeval;
		void *buf;
		int len;

		gettimeofday(&timeval, NULL);

		ret = ep->ops->poll_for_msg(ep->ep, &buf, &len);
		if (!ret) {
			ret = handle_request(ep, buf, len);
			if (!ret && ep->ctrl) {
				ep->countdown	= ep->ctrl->kato;
				ep->timeval	= timeval;
				continue;
			}
			print_info("ctrl %d qid %d returned %d\n",
				   ep->ctrl ? ep->ctrl->cntlid : -1,
				   ep->qid, ret);
		}

		if (ret == -EAGAIN)
			if (--ep->countdown > 0)
				continue;

		if (ret < 0) {
			print_err("ctrl %d qid %d error %d retry %d",
				  ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret, ep->countdown);
			break;
		}
	}

	disconnect_endpoint(ep, !stopped);

	print_info("ctrl %d qid %d %s",
		   ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
		   stopped ? "stopped" : "disconnected");
	pthread_exit(NULL);

	return NULL;
}

static struct endpoint *enqueue_endpoint(void *id, struct host_iface *iface)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(*ep));
	if (!ep) {
		print_err("no memory");
		return NULL;
	}

	memset(ep, 0, sizeof(*ep));

	ep->ops = iface->ops;
	ep->iface = iface;
	ep->countdown = RETRY_COUNT;

	ret = run_pseudo_target(ep, id);
	if (ret) {
		print_errno("run_pseudo_target failed", ret);
		goto out;
	}

	list_add(&ep->node, &endpoint_linked_list);
	return ep;
out:
	free(ep);
	return NULL;
}

int run_host_interface(struct host_iface *iface)
{
	struct xp_pep *listener;
	struct endpoint *ep, *_ep;
	void *id;
	pthread_attr_t pthread_attr;
	int ret;

	ret = start_pseudo_target(iface);
	if (ret) {
		print_err("failed to start pseudo target");
		return ret;
	}

	listener = iface->listener;

	signal(SIGTERM, SIG_IGN);

	while (!stopped) {
		ret = iface->ops->wait_for_connection(listener, &id);

		if (stopped)
			break;

		if (ret) {
			if (ret != -EAGAIN)
				print_errno("Host connection failed", ret);
			continue;
		}
		ep = enqueue_endpoint(id, iface);
		if (!ep)
			continue;

		pthread_attr_init(&pthread_attr);

		ret = pthread_create(&ep->pthread, &pthread_attr,
				     endpoint_thread, ep);
		if (ret) {
			ep->pthread = 0;
			print_err("failed to start endpoint thread");
			print_errno("pthread_create failed", ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	iface->ops->destroy_listener(listener);

	list_for_each_entry_safe(ep, _ep, &endpoint_linked_list, node) {
		if (ep->pthread) {
			pthread_join(ep->pthread, NULL);
		}
		list_del(&ep->node);
		free(ep);
	}

	return ret;
}
