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

extern int debug;
extern char *hostnqn;

extern struct linked_list device_linked_list;
extern struct linked_list subsys_linked_list;
extern struct linked_list iface_linked_list;

#define NVMF_UUID_FMT		"nqn.2014-08.org.nvmexpress:uuid:%s"

#define NVMF_DQ_DEPTH		2
#define NVMF_SQ_DEPTH		128
#define NVMF_NUM_QUEUES		8

#define MAX_NQN_SIZE		256
#define MAX_ALIAS_SIZE		64

#define PAGE_SIZE		4096

#define KATO_INTERVAL	500	/* in ms as per spec */
#define RETRY_COUNT	1200	/* 2 min; value is multiplied with kato interval */


#define ADRFAM_STR_IPV4 "ipv4"
#define ADRFAM_STR_IPV6 "ipv6"

#define IPV4_LEN		4
#define IPV4_OFFSET		4
#define IPV4_DELIM		"."

#define IPV6_LEN		8
#define IPV6_OFFSET		8
#define IPV6_DELIM		":"

enum { DISCONNECTED, CONNECTED };

extern int stopped;

struct nofuse_port {
	int port_id;
	char trtype[256];
	char traddr[256];
	char trsvcid[256];
	char adrfam[256];
	char treq[256];
	char tsas[256];
};

struct nofuse_host {
	char nqn[MAX_NQN_SIZE + 1];
};

struct ep_qe {
	struct linked_list node;
	int tag;
	struct endpoint *ep;
	struct nsdev *ns;
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
};

enum { RECV_PDU, RECV_DATA, HANDLE_PDU };

struct endpoint {
	struct linked_list node;
	pthread_t pthread;
	struct io_uring uring;
	struct io_ops *io_ops;
	struct xp_ops *ops;
	struct host_iface *iface;
	struct ctrl_conn *ctrl;
	struct ep_qe *qes;
	union nvme_tcp_pdu *recv_pdu;
	int recv_pdu_len;
	union nvme_tcp_pdu *send_pdu;
	int recv_state;
	int qsize;
	int state;
	int qid;
	int kato_countdown;
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

struct ctrl_conn {
	struct linked_list node;
	struct nofuse_subsys *subsys;
	char nqn[MAX_NQN_SIZE + 1];
	int cntlid;
	int ctrl_type;
	int kato;
	int num_endpoints;
	int max_endpoints;
	int aen_mask;
	u64 csts;
	u64 cc;
};

struct nsdev {
	struct linked_list node;
	struct ns_ops *ops;
	int nsid;
	int fd;
	size_t size;
	unsigned int blksize;
	uuid_t uuid;
};

struct host_iface {
	struct linked_list node;
	pthread_t pthread;
	struct xp_ops *ops;
	struct linked_list ep_list;
	pthread_mutex_t ep_mutex;
	struct nofuse_port port;
	int port_type;
	sa_family_t adrfam;
	int port_num;
	int listenfd;
	bool tls;
};

struct nofuse_subsys {
	struct linked_list node;
	struct linked_list ctrl_list;
	pthread_mutex_t ctrl_mutex;
	char nqn[MAX_NQN_SIZE + 1];
	int type;
	bool allow_any;
};

struct nofuse_context {
	const char *hostnqn;
	const char *subsysnqn;
	const char *interface;
	const char *filename;
	const char *dbname;
	int portnum;
	int ramdisk_size;
	int debug;
	int help;
};

extern struct nofuse_context *ctx;

static inline void set_response(struct nvme_completion *resp,
				u16 ccid, u16 status, bool dnr)
{
	if (!status)
		dnr = false;
	resp->command_id = ccid;
	resp->status = ((dnr ? NVME_SC_DNR : 0) | status) << 1;
}

int handle_request(struct endpoint *ep, struct nvme_command *cmd);
int handle_data(struct endpoint *ep, struct ep_qe *qe, int res);
void *run_host_interface(void *arg);
int endpoint_update_qdepth(struct endpoint *ep, int qsize);

#endif
