/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * common.h
 * Common definitions for NVMe-over-TCP userspace daemon
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>. All rights reserved.
 */
#ifndef __COMMON_H__
#define __COMMON_H__

#define unlikely __glibc_unlikely

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <liburing.h>

#ifdef _GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/ssl.h>
#endif

#include "utils.h"
#include "nvme.h"
#include "tcp.h"

extern bool tcp_debug;
extern bool cmd_debug;
extern bool ep_debug;
extern bool port_debug;
extern bool fuse_debug;

extern struct linked_list device_linked_list;
extern struct linked_list port_linked_list;

#define NVME_NR_AEN_COMMANDS	4
#define NVME_AQ_DEPTH		32
#define NVMF_SQ_DEPTH		128
#define NVMF_NUM_QUEUES		8

#define MAX_NQN_SIZE		256
#define MAX_ALIAS_SIZE		64

#define MAX_NSID		256
#define MAX_ANAGRPID		64

#define PAGE_SIZE		4096

#define KATO_INTERVAL	500	/* in ms as per spec */
#define RETRY_COUNT	1200	/* 2 min; value is multiplied with kato interval */


#define ADRFAM_STR_IPV4 "ipv4"
#define ADRFAM_STR_IPV6 "ipv6"
#define ADRFAM_STR_FC "fc"
#define ADRFAM_STR_IB "ib"
#define ADRFAM_STR_PCI "pci"
#define ADRFAM_STR_LOOP "loop"

#define NOFUSE_NGUID_PREFIX "0efd376f6e756665"

enum { CONNECTED, STOPPED, DISCONNECTED };

extern int stopped;

struct ep_qe {
	int tag;
	struct nofuse_queue *ep;
	struct nofuse_namespace *ns;
	union nvme_tcp_pdu pdu;
	struct iovec iovec;
	struct nvme_completion resp;
	void *data;
	u64 data_len;
	u64 data_pos;
	u64 data_remaining;
	u64 iovec_offset;
	int ccid;
	int opcode;
	bool busy;
	bool aen;
};

enum { RECV_PDU, RECV_DATA, HANDLE_PDU };

struct nofuse_queue {
	struct linked_list node;
	pthread_t pthread;
	struct io_uring uring;
	struct io_ops *io_ops;
	struct xp_ops *ops;
	struct nofuse_port *port;
	struct nofuse_ctrl *ctrl;
	struct ep_qe *qes;
	union nvme_tcp_pdu *recv_pdu;
	int recv_pdu_len;
	union nvme_tcp_pdu *send_pdu;
	int recv_state;
	int qsize;
	int state;
	int qid;
	int kato_interval;
	int sockfd;
	int maxr2t;
	int maxh2cdata;
	int mdts;
#ifdef _GNUTLS
	gnutls_session_t session;
	gnutls_psk_server_credentials_t psk_cred;
#else
	SSL_CTX *ctx;
	SSL *ssl;
#endif
};

struct nofuse_ctrl {
	struct linked_list node;
	char subsysnqn[MAX_NQN_SIZE + 1];
	char hostnqn[MAX_NQN_SIZE + 1];
	struct nofuse_queue *ep;
	int cntlid;
	int kato;
	int kato_countdown;
	int num_queues;
	int max_queues;
	int aen_mask;
	unsigned int ana_chgcnt;
	unsigned int ns_chgcnt;
	unsigned int disc_chgcnt;
	u64 csts;
	u64 cc;
};

struct nofuse_namespace {
	struct linked_list node;
	struct ns_ops *ops;
	char subsysnqn[MAX_NQN_SIZE + 1];
	u32 nsid;
	int fd;
	size_t size;
	unsigned int blksize;
	bool readonly;
};

struct nofuse_port {
	struct linked_list node;
	pthread_t pthread;
	struct xp_ops *ops;
	struct linked_list ep_list;
	pthread_mutex_t ep_mutex;
	int portid;
	int listenfd;
	bool tls;
};

#define ep_info(e, f, x...)				\
	if (ep_debug) {					\
		printf("ep %d: " f "\n",		\
		       (e)->sockfd, ##x);		\
		fflush(stdout);				\
}

#define ep_err(e, f, x...)				\
	do {						\
		fprintf(stderr, "ep %d: " f "\n",	\
			(e)->sockfd, ##x);		\
		fflush(stderr);				\
	} while (0)


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

#define port_info(i, f, x...)			\
	if (port_debug) {			\
		printf("port %d: " f "\n",	\
		       (i)->portid, ##x);	\
		fflush(stdout);			\
	}

#define port_err(i, f, x...)				\
	do {						\
		fprintf(stderr, "port %d: " f "\n",	\
			(i)->portid, ##x);		\
		fflush(stderr);				\
	} while (0)

static inline void set_response(struct nvme_completion *resp,
				u16 ccid, u16 status, bool dnr)
{
	if (!status)
		dnr = false;
	resp->command_id = ccid;
	resp->status = ((dnr ? NVME_SC_DNR : 0) | status) << 1;
}

static inline void kato_reset_counter(struct nofuse_ctrl *ctrl)
{
	ctrl->kato_countdown = ctrl->kato;
}

void raise_aen(const char *subsysnqn, int level);

int handle_request(struct nofuse_queue *ep, struct nvme_command *cmd);
int handle_data(struct nofuse_queue *ep, struct ep_qe *qe, int res);
int send_aen(struct nofuse_queue *ep, int type);
int connect_queue(struct nofuse_queue *ep, u16 cntlid,
		  const char *hostnqn, const char *subsysnqn);
int queue_update_qdepth(struct nofuse_queue *ep, int qsize);
struct nofuse_queue *create_queue(int conn, struct nofuse_port *port);
void destroy_queue(struct nofuse_queue *ep);
void *queue_thread(void *arg);
void terminate_queues(struct nofuse_port *port, const char *subsysnqn);

int default_subsys_type(const char *nqn);

int add_port(unsigned int id, const char *ifaddr, int portnum);
struct nofuse_port *find_port(unsigned int id);
int del_port(struct nofuse_port *port);
int start_port(struct nofuse_port *port);
int stop_port(struct nofuse_port *port);

struct nofuse_namespace *find_namespace(const char *subsysnqn, u32 nsid);
int add_namespace(const char *subsysnqn, u32 nsid);
int del_namespace(const char *subsysnqn, u32 nsid);
int enable_namespace(const char *subsysnqn, u32 nsid);
int disable_namespace(const char *subsysnqn, u32 nsid);

#endif
