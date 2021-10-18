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

#include "utils.h"
#include "nvme.h"

extern int			 debug;
extern struct linked_list	*devices;
extern struct linked_list	*interfaces;

#define NVMF_UUID_FMT		"nqn.2014-08.org.nvmexpress:uuid:%s"

#define NVMF_DQ_DEPTH		2
#define NVMF_SQ_DEPTH		32
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

extern int			 stopped;

struct endpoint {
	struct linked_list	 node;
	pthread_t		 pthread;
	struct xp_ops		*ops;
	struct host_iface	*iface;
	struct ctrl_conn	*ctrl;
	union nvme_tcp_pdu	*pdu;
	u64			 data_pos;
	u64			 data_length;
	unsigned int		 data_offset;
	unsigned int		 data_expected;
	unsigned int		 data_skipped;
	u16			 data_tag;
	int			 state;
	int			 qid;
	int			 kato_countdown;
	int			 kato_interval;
	struct timeval		 timeval;
	int			 sockfd;
	int			 maxr2t;
	int			 maxh2cdata;
};

struct ctrl_conn {
	struct linked_list	 node;
	struct subsystem	*subsys;
	char			 nqn[MAX_NQN_SIZE + 1];
	int			 cntlid;
	int			 ctrl_type;
	int			 kato;
	int			 qsize;
	int			 max_endpoints;
	int			 aen_mask;
	u64			 csts;
	u64			 cc;
};

struct nsdev {
	struct linked_list	 node;
	int			 devid;
	int			 nsid;
	int			 fd;
	off_t			 size;
	unsigned int		 blksize;
	uuid_t			 uuid;
};

struct host_iface {
	char			 address[41];
	unsigned char		 addr[sizeof(struct in6_addr)];
	int			 port_num;
	int			 adrfam;
	int			 portid;
	int			 listenfd;
	struct endpoint		 ep;
	struct xp_ops		*ops;
	struct linked_list ep_list;
	pthread_mutex_t ep_mutex;
};

struct subsystem {
	struct linked_list	 node;
	struct linked_list	 host_list;
	struct linked_list	 ctrl_list;
	pthread_mutex_t ctrl_mutex;
	char			 nqn[MAX_NQN_SIZE + 1];
	int			 type;
};

extern struct linked_list subsys_linked_list;

int handle_request(struct endpoint *ep, void *buf, int length);
int run_host_interface(struct host_iface *iface);

#endif
