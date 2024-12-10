#ifndef _ETCD_BACKEND_H
#define _ETCD_BACKEND_H

#define FUSE_USE_VERSION 31
#include <fuse.h>

int etcd_set_discovery_nqn(const char *buf);
int etcd_get_discovery_nqn(char *buf);

int etcd_count_root(const char *root, int *nlinks);
int etcd_fill_host_dir(void *buf, fuse_fill_dir_t filler);
int etcd_fill_port_dir(void *buf, fuse_fill_dir_t filler);
int etcd_fill_subsys_dir(void *buf, fuse_fill_dir_t filler);

int etcd_fill_host(const char *nqn, void *buf, fuse_fill_dir_t filler);
int etcd_add_host(const char *nqn);
int etcd_test_host(const char *nqn);
int etcd_get_host_attr(const char *nqn, const char *attr, char *value);
int etcd_del_host(const char *nqn);

int etcd_fill_port(unsigned int id, void *buf, fuse_fill_dir_t filler);
int etcd_add_port(unsigned int id);
int etcd_test_port(unsigned int id);
int etcd_set_port_attr(unsigned int id, const char *attr, const char *value);
int etcd_get_port_attr(unsigned int id, const char *attr, char *value);
int etcd_del_port(unsigned int id);

int etcd_fill_ana_groups(const char *port, void *buf, fuse_fill_dir_t filler);
int etcd_add_ana_group(int portid, int ana_grpid, int ana_state);
int etcd_get_ana_group(int portid, const char *ana_grp, char *ana_state);
int etcd_set_ana_group(int portid, const char *ana_grp, char *ana_state);
int etcd_del_ana_group(int portid, int ana_grpid);

int etcd_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler);
int etcd_add_subsys(const char *nqn, int type);
int etcd_test_subsys(const char *nqn);
int etcd_set_subsys_attr(const char *nqn, const char *attr, const char *value);
int etcd_get_subsys_attr(const char *nqn, const char *attr, char *value);
int etcd_del_subsys(const char *nqn);

int etcd_fill_subsys_port(int id, void *buf, fuse_fill_dir_t filler);
int etcd_add_subsys_port(const char *subsysnqn, int id);
int etcd_get_subsys_port(const char *subsysnqn, int id, char *value);
int etcd_del_subsys_port(const char *subsysnqn, int id);

int etcd_fill_host_subsys(const char *subsysnqn, void *buf,
			  fuse_fill_dir_t filler);
int etcd_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int etcd_get_host_subsys(const char *hostnqn, const char *subsysnqn,
			 char *value);
int etcd_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int etcd_count_namespaces(const char *subsysnqn, int *nns);

int etcd_fill_namespace_dir(const char *subsysnqn, void *buf,
			    fuse_fill_dir_t filler);
int etcd_fill_namespace(const char *subsysnqn, int nsid,
			void *buf, fuse_fill_dir_t filler);
int etcd_add_namespace(const char *subsysnqn, int nsid);
int etcd_test_namespace(const char *subsysnqn, int nsid);
int etcd_set_namespace_attr(const char *subsysnqn, int nsid,
			    const char *attr, const char *value);
int etcd_get_namespace_attr(const char *subsysnqn, int nsid,
			    const char *attr, char *value);
int etcd_set_namespace_anagrp(const char *subsysnqn, int nsid, int ana_grpid);
int etcd_get_namespace_anagrp(const char *subsysnqn, int nsid, int *ana_grpid);
int etcd_del_namespace(const char *subsysnqn, int nsid);

int etcd_count_subsys_port(int portid, int *nsubsys);
int etcd_count_ana_groups(int portid, int *ngrps);
int etcd_count_host_subsys(const char *subsysnqn, int *nhosts);

int etcd_get_cntlid(const char *subsysnqn, u16 *cntlid);
int etcd_host_disc_entries(const char *hostnqn, u8 *log, int log_len);
int etcd_host_genctr(const char *hostnqn, int *genctr);
int etcd_subsys_identify_ctrl(const char *subsysnqn,
			      struct nvme_id_ctrl *id);

int etcd_backend_init(const char *prefix, bool debug);
void etcd_backend_exit(void);

#endif /* _ETCD_BACKEND_H */



