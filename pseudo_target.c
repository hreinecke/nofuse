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

struct ctrl_conn {
	struct linked_list	 node;
	struct endpoint		*ep;
	struct timeval		 timeval;
	int			 ctrl_type;
	int			 countdown;
	int			 kato;
};

static int handle_property_set(struct nvme_command *cmd, struct endpoint *ep)
{
	int			 ret = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_property_set %x = %llx",
		   cmd->prop_set.offset, cmd->prop_set.value);
#endif
	if (cmd->prop_set.offset == NVME_REG_CC) {
		ep->cc = le64toh(cmd->prop_set.value);
		if (ep->cc & NVME_CC_SHN_MASK)
			ep->csts = NVME_CSTS_SHTS_CMPLT;
		else {
			if (ep->cc & NVME_CC_ENABLE)
				ep->csts = NVME_CSTS_RDY;
			else
				ep->csts = NVME_CSTS_SHTS_CMPLT;
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
		value = ep->csts;
	else if (cmd->prop_get.offset == NVME_REG_CAP)
		value = 0x200f0003ffL;
	else if (cmd->prop_get.offset == NVME_REG_CC)
		value = ep->cc;
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

static int handle_set_features(struct nvme_command *cmd, u32 *kato)
{
	u32			 cdw10 = ntohl(cmd->common.cdw10[0]);
	int			 ret;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_type_set_features cdw10 %x", cdw10);
#endif

	if ((cdw10 & 0xff) == *kato) {
		*kato = ntohl(cmd->common.cdw10[1]);
		ret = 0;
	} else
		ret = NVME_SC_FEATURE_NOT_CHANGEABLE;

	return ret;
}

static int handle_connect(struct endpoint *ep, int qid, u64 addr, u64 len)
{
	struct nvmf_connect_data *data = ep->data;
	int			 ret;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_connect");
#endif

	ret = ep->ops->rma_read(ep->ep, ep->data, addr, len);
	if (ret) {
		print_errno("rma_read failed", ret);
		goto out;
	}

	print_info("host '%s' connected", data->hostnqn);
	strncpy(ep->nqn, data->hostnqn, MAX_NQN_SIZE);

	if (!strcmp(data->subsysnqn, NVME_DISC_SUBSYS_NAME))
		ep->ctrl_type = NVME_DISC_CTRL;
	else if (!strcmp(data->subsysnqn, static_subsys.nqn))
		ep->ctrl_type = NVME_IO_CTRL;
	else {
		print_err("bad subsystem '%s', expecting '%s' or '%s'",
			  data->subsysnqn, NVME_DISC_SUBSYS_NAME,
			  static_subsys.nqn);
		ret = NVME_SC_CONNECT_INVALID_HOST;
	}

	if (qid == 0) {
		if (data->cntlid != 0xffff) {
			print_err("bad controller id %x, expecting %x",
				  data->cntlid, 0xffff);
			ret = NVME_SC_CONNECT_INVALID_PARAM;
		}
		ep->cntlid = nvmf_ctrl_id++;
	} else if (le16toh(data->cntlid) != ep->cntlid) {
		print_err("bad controller id %x for queue %d, expecting %x",
			  data->cntlid, qid, ep->cntlid);
		ret = NVME_SC_CONNECT_INVALID_PARAM;
	}
out:
	return ret;
}

static int handle_identify(struct endpoint *ep, struct nvme_command *cmd,
			   u64 addr, u64 len)
{
	struct nvme_id_ctrl	*id = ep->data;
	int			 ret;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_identify");
#endif

	if (htole32(cmd->identify.cns) != NVME_ID_CNS_CTRL) {
		print_err("unexpected identify command");
		return NVME_SC_BAD_ATTRIBUTES;
	}

	memset(id, 0, sizeof(*id));

	memset(id->fr, ' ', sizeof(id->fr));
	strncpy((char *) id->fr, " ", sizeof(id->fr));

	id->mdts = 0;
	id->cntlid = htole16(ep->cntlid);
	id->ver = htole32(NVME_VER);
	id->lpa = (1 << 2);
	id->maxcmd = htole16(NVMF_DQ_DEPTH);
	id->sgls = htole32(1 << 0) | htole32(1 << 2) | htole32(1 << 20);
	id->kas = 10;

	if (ep->ctrl_type == NVME_DISC_CTRL)
		strcpy(id->subnqn, NVME_DISC_SUBSYS_NAME);
	else
		strcpy(id->subnqn, static_subsys.nqn);

	if (len > sizeof(*id))
		len = sizeof(*id);

	ret = ep->ops->rma_write(ep->ep, ep->data, addr, len, cmd);
	if (ret) {
		print_errno("rma_write failed", ret);
		ret = NVME_SC_WRITE_FAULT;
	}

	return ret;
}

static int get_nsdev(void *data)
{
	struct nvmf_get_ns_devices_hdr *hdr = data;
	struct nvmf_get_ns_devices_entry *entry;
	struct nsdev		*dev;
	int			 cnt = 0;

#ifdef DEBUG_COMMANDS
	print_debug("nvme_fabrics_get_ns_devices");
#endif

	entry = (struct nvmf_get_ns_devices_entry *) &hdr->data;

	list_for_each_entry(dev, devices, node) {
		memset(entry, 0, sizeof(*entry));
		entry->devid = dev->devid;
		entry->nsid = dev->nsid;
		cnt++;
		entry++;
	}

	hdr->num_entries = cnt;

	return cnt * sizeof(*entry) + sizeof(*hdr) - 1;
}

static int format_disc_log(void *data, u64 data_len, struct host_iface *iface)
{
	struct nvmf_disc_rsp_page_hdr hdr;
	struct nvmf_disc_rsp_page_entry entry;

	hdr.genctr = nvmf_discovery_genctr;
	hdr.recfmt = 0;
	hdr.numrec = 1;
	if (data_len < sizeof(hdr)) {
		memcpy(data, &hdr, data_len);
		return data_len;
	}
	memcpy(data, &hdr, sizeof(hdr));

	data_len -= sizeof(hdr);
	data += sizeof(hdr);
	if (data_len > sizeof(entry))
		data_len = sizeof(entry);
	memset(&entry, 0, sizeof(struct nvmf_disc_rsp_page_entry));
	entry.trtype = NVMF_TRTYPE_TCP;
	entry.adrfam = iface->adrfam;
	entry.treq = 0;
	entry.portid = 1;
	entry.cntlid = htonl(NVME_CNTLID_DYNAMIC);
	entry.asqsz = 32;
	entry.subtype = NVME_NQN_NVME;
	memcpy(entry.trsvcid, iface->port, NVMF_TRSVCID_SIZE);
	memcpy(entry.traddr, iface->address, NVMF_TRADDR_SIZE);
	strncpy(entry.subnqn, static_subsys.nqn, NVMF_NQN_FIELD_LEN);
	memcpy(data, &entry, data_len);
	return sizeof(hdr) + data_len;
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
		len = format_disc_log(ep->data, len, ep->iface);
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

static int handle_request(struct ctrl_conn *host, void *buf, int length)
{
	struct endpoint			*ep = host->ep;
	struct nvme_command		*cmd = (struct nvme_command *) buf;
	struct nvme_completion		*resp = (void *) ep->cmd;
	struct nvmf_connect_command	*c = &cmd->connect;
	u64				 addr;
	u32				 len;
	u32				 kato = 0;
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
				resp->result.U16 = htole16(ep->cntlid);
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
		ret = handle_set_features(cmd, &kato);
		if (ret)
			ret = NVME_SC_INVALID_FIELD;
		else
			host->kato = kato * (KATO_INTERVAL / DELAY_TIMEOUT);
	} else {
		print_err("unknown nvme opcode %d", cmd->common.opcode);
		ret = NVME_SC_INVALID_OPCODE;
	}

	if (ret)
		resp->status = (NVME_SC_DNR | ret) << 1;

	return ep->ops->send_rsp(ep->ep, resp, sizeof(*resp));
}

#define HOST_QUEUE_MAX 3 /* min of 3 otherwise cannot tell if full */
struct host_queue {
	struct endpoint		*ep[HOST_QUEUE_MAX];
	int			 tail, head;
};

static inline int is_empty(struct host_queue *q)
{
	return q->head == q->tail;
}

static inline int is_full(struct host_queue *q)
{
	return ((q->head + 1) % HOST_QUEUE_MAX) == q->tail;
}

#ifdef DEBUG_HOST_QUEUE
static inline void dump_queue(struct host_queue *q)
{
	print_debug("ep { %p, %p, %p }, tail %d, head %d",
		    q->ep[0], q->ep[1], q->ep[2], q->tail, q->head);
}
#endif

static inline int add_new_ctrl_conn(struct host_queue *q, struct endpoint *ep)
{
	if (is_full(q))
		return -1;

	q->ep[q->head] = ep;
	q->head = (q->head + 1) % HOST_QUEUE_MAX;
#ifdef DEBUG_HOST_QUEUE
	dump_queue(q);
#endif
	return 0;
}

static inline int get_new_ctrl_conn(struct host_queue *q, struct endpoint **ep)
{
	if (is_empty(q))
		return -1;

	if (!q->ep[q->tail])
		return 1;

	*ep = q->ep[q->tail];
	q->ep[q->tail] = NULL;
	q->tail = (q->tail + 1) % HOST_QUEUE_MAX;
#ifdef DEBUG_HOST_QUEUE
	dump_queue(q);
#endif
	return 0;
}

static void *host_thread(void *arg)
{
	struct host_queue	*q = arg;
	struct endpoint		*ep = NULL;
	struct timeval		 timeval;
	struct linked_list	 host_list;
	struct ctrl_conn	*next;
	struct ctrl_conn	*host;
	void			*buf;
	int			 len;
	int			 delta;
	int			 ret;

	INIT_LINKED_LIST(&host_list);

	while (!stopped) {
		gettimeofday(&timeval, NULL);

		do {
			ret = get_new_ctrl_conn(q, &ep);

			if (!ret) {
				host = malloc(sizeof(*host));
				if (!host)
					goto out;

				host->ep	= ep;
				host->kato	= RETRY_COUNT;
				host->countdown	= RETRY_COUNT;
				host->timeval	= timeval;

				list_add_tail(&host->node, &host_list);
			}
		} while (!ret && !stopped);

		/* Service Host requests */
		list_for_each_entry_safe(host, next, &host_list, node) {
			ep = host->ep;
loop:
			ret = ep->ops->poll_for_msg(ep->ep, &buf, &len);
			if (!ret) {
				ret = handle_request(host, buf, len);
				if (!ret) {
					host->countdown	= host->kato;
					host->timeval	= timeval;
					goto loop;
				}
			}

			if (ret == -EAGAIN)
				if (--host->countdown > 0)
					continue;

			disconnect_endpoint(ep, !stopped);

			print_info("host '%s' disconnected", ep->nqn);

			free(ep);
			list_del(&host->node);
			free(host);
		}

		delta = msec_delta(timeval);
		if (delta < DELAY_TIMEOUT)
			usleep((DELAY_TIMEOUT - delta) * 1000);
	}
out:
	list_for_each_entry_safe(host, next, &host_list, node) {
		disconnect_endpoint(host->ep, 1);
		free(host->ep);
		free(host);
	}

	while (!is_empty(q))
		if (!get_new_ctrl_conn(q, &ep)) {
			disconnect_endpoint(ep, 1);
			free(ep);
		}

	pthread_exit(NULL);

	return NULL;
}

static int add_host_to_queue(void *id, struct host_iface *iface, struct host_queue *q)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(*ep));
	if (!ep) {
		print_err("no memory");
		return -ENOMEM;
	}

	memset(ep, 0, sizeof(*ep));

	ep->ops = iface->ops;
	ep->iface = iface;

	ret = run_pseudo_target(ep, id);
	if (ret) {
		print_errno("run_pseudo_target failed", ret);
		goto out;
	}

	while (is_full(q) && !stopped)
		usleep(100);

	add_new_ctrl_conn(q, ep);

	usleep(20);

	return 0;
out:
	free(ep);
	return ret;
}

int run_host_interface(struct host_iface *iface)
{
	struct xp_pep		*listener;
	void			*id;
	struct host_queue	 q;
	pthread_attr_t		 pthread_attr;
	pthread_t		 pthread;
	int			 ret;

	ret = start_pseudo_target(iface);
	if (ret) {
		print_err("failed to start pseudo target");
		return ret;
	}

	listener = iface->listener;

	signal(SIGTERM, SIG_IGN);

	memset(&q, 0, sizeof(q));

	pthread_attr_init(&pthread_attr);

	ret = pthread_create(&pthread, &pthread_attr, host_thread, &q);
	if (ret) {
		print_err("failed to start host thread");
		print_errno("pthread_create failed", ret);
		pthread_attr_destroy(&pthread_attr);
		goto out;
	}

	pthread_attr_destroy(&pthread_attr);

	while (!stopped) {
		ret = iface->ops->wait_for_connection(listener, &id);

		if (stopped)
			break;

		if (ret == 0)
			add_host_to_queue(id, iface, &q);
		else if (ret != -EAGAIN)
			print_errno("Host connection failed", ret);
	}

	pthread_join(pthread, NULL);
out:
	iface->ops->destroy_listener(listener);

	return ret;
}
