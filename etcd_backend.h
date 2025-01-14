#ifndef _ETCD_BACKEND_H
#define _ETCD_BACKEND_H

#include "etcd_client.h"

#define FUSE_USE_VERSION 31
#include <fuse.h>

int etcd_set_discovery_nqn(struct etcd_ctx *ctx, const char *buf);
int etcd_get_discovery_nqn(struct etcd_ctx *ctx, char *buf);

int etcd_count_root(struct etcd_ctx *ctx, const char *root, int *nlinks);
int etcd_fill_host_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler);
int etcd_fill_port_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler);
int etcd_fill_subsys_dir(struct etcd_ctx *ctx, void *buf,
			 fuse_fill_dir_t filler);

int etcd_fill_host(struct etcd_ctx *ctx, const char *nqn,
		   void *buf, fuse_fill_dir_t filler);
int etcd_add_host(struct etcd_ctx *ctx, const char *nqn);
int etcd_test_host(struct etcd_ctx *ctx, const char *nqn);
int etcd_get_host_attr(struct etcd_ctx *ctx, const char *nqn,
		       const char *attr, char *value);
int etcd_del_host(struct etcd_ctx *ctx, const char *nqn);

int etcd_fill_port(struct etcd_ctx *ctx, const char *port,
		   void *buf, fuse_fill_dir_t filler);
int etcd_add_port(struct etcd_ctx *ctx, const char *origin,
		  const char *port, const char *traddr, const char *trsvcid);
int etcd_test_port(struct etcd_ctx *ctx, const char *port);
int etcd_set_port_attr(struct etcd_ctx *ctx, const char *port,
		       const char *attr, const char *value);
int etcd_get_port_attr(struct etcd_ctx *ctx, const char *port,
		       const char *attr, char *value);
int etcd_del_port(struct etcd_ctx *ctx, const char *port);

int etcd_fill_ana_groups(struct etcd_ctx *ctx, const char *port,
			 void *buf, fuse_fill_dir_t filler);
int etcd_add_ana_group(struct etcd_ctx *ctx, const char *port,
		       int ana_grpid, int ana_state);
int etcd_get_ana_group(struct etcd_ctx *ctx, const char *port,
		       int ana_grpid, char *ana_state);
int etcd_set_ana_group(struct etcd_ctx *ctx, const char *port,
		       const char *ana_grp, char *ana_state);
int etcd_del_ana_group(struct etcd_ctx *ctx, const char *port, int ana_grpid);

int etcd_fill_subsys(struct etcd_ctx *ctx, const char *nqn,
		     void *buf, fuse_fill_dir_t filler);
int etcd_add_subsys(struct etcd_ctx *ctx, const char *nqn, int type,
		    bool permanent);
int etcd_test_subsys(struct etcd_ctx *ctx, const char *nqn);
int etcd_set_subsys_attr(struct etcd_ctx *ctx, const char *nqn,
			 const char *attr, const char *value);
int etcd_get_subsys_attr(struct etcd_ctx *ctx, const char *nqn,
			 const char *attr, char *value);
int etcd_del_subsys(struct etcd_ctx *ctx, const char *nqn);

int etcd_fill_subsys_port(struct etcd_ctx *ctx, const char *port,
			  void *buf, fuse_fill_dir_t filler);
int etcd_add_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port);
int etcd_get_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port, char *value);
int etcd_del_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port);

int etcd_fill_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn,
			  void *buf, fuse_fill_dir_t filler);
int etcd_add_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn);
int etcd_get_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn, char *value);
int etcd_del_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn);

int etcd_count_namespaces(struct etcd_ctx *ctx, const char *subsysnqn, int *nns);

int etcd_fill_namespace_dir(struct etcd_ctx *ctx, const char *subsysnqn,
			    void *buf, fuse_fill_dir_t filler);
int etcd_fill_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid,
			void *buf, fuse_fill_dir_t filler);
int etcd_add_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid);
int etcd_test_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid);
int etcd_set_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr, const char *value);
int etcd_get_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr, char *value);
int etcd_set_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int ana_grpid);
int etcd_get_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int *ana_grpid);
int etcd_del_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid);

int etcd_count_subsys_port(struct etcd_ctx *ctx, const char *port, int *nsubsys);
int etcd_count_ana_groups(struct etcd_ctx *ctx, const char *port, int *ngrps);
int etcd_count_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn, int *nhosts);

int etcd_get_cntlid(struct etcd_ctx *ctx, const char *subsysnqn, u16 *cntlid);
int etcd_host_disc_entries(const char *hostnqn, u8 *log, int log_len);
int etcd_host_genctr(const char *hostnqn, int *genctr);
int etcd_subsys_identify_ctrl(const char *subsysnqn,
			      struct nvme_id_ctrl *id);

#endif /* _ETCD_BACKEND_H */



