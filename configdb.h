#ifndef _CONFIGDB_H
#define _CONFIGDB_H

#define FUSE_USE_VERSION 31

#include <fuse.h>

int configdb_open(const char *filename);
void configdb_close(const char *filename);

int configdb_count_table(const char *tbl, int *num);

int configdb_add_host(const char *nqn);
int configdb_stat_host(const char *nqn, struct stat *stbuf);
int configdb_fill_host_dir(void *buf, fuse_fill_dir_t filler);
int configdb_del_host(const char *nqn);

int configdb_add_subsys(struct nofuse_subsys *subsys);
int configdb_get_discovery_nqn(char *nqn);
int configdb_set_discovery_nqn(char *nqn);
int configdb_stat_subsys(const char *nqn, struct stat *stbuf);
int configdb_fill_subsys_dir(void *buf, fuse_fill_dir_t filler);
int configdb_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler);
int configdb_get_subsys_attr(const char *nqn, const char *attr, char *buf);
int configdb_set_subsys_attr(const char *nqn, const char *attr, const char *buf);
int configdb_del_subsys(struct nofuse_subsys *subsys);

int configdb_add_namespace(const char *subsysnqn, int nsid);
int configdb_count_namespaces(const char *subsysnqn, int *num);
int configdb_stat_namespace(const char *subsysnqn, int nsid,
			 struct stat *stbuf);
int configdb_fill_namespace_dir(const char *nqn, void *buf,
			     fuse_fill_dir_t filler);
int configdb_fill_namespace(const char *nqn, int nsid,
			 void *buf, fuse_fill_dir_t filler);
int configdb_get_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, char *buf);
int configdb_set_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, const char *buf);
int configdb_get_namespace_anagrp(const char *subsysnqn, int nsid,
			       int *ana_grpid);
int configdb_set_namespace_anagrp(const char *subsysnqn, int nsid,
			       int ana_grpid);
int configdb_del_namespace(const char *subsysnqn, int nsid);

int configdb_add_ana_group(int port, int grpid, int ana_state);
int configdb_count_ana_groups(const char *port, int *num);
int configdb_stat_ana_group(const char *port, const char *ana_grpid,
			 struct stat *stbuf);
int configdb_fill_ana_groups(const char *port,
			  void *buf, fuse_fill_dir_t filler);
int configdb_get_ana_group(const char *port, const char *ana_grpid,
			int *ana_state);
int configdb_set_ana_group(const char *port, const char *ana_grpid,
			int ana_state);
int configdb_del_ana_group(unsigned int portid, int grpid);

int configdb_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int configdb_count_host_subsys(const char *subsysnqn, int *num_hosts);
int configdb_fill_host_subsys(const char *subsysnqn,
			   void *buf, fuse_fill_dir_t filler);
int configdb_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			   struct stat *stbuf);
int configdb_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int configdb_add_port(unsigned int port);
int configdb_stat_port(unsigned int port, struct stat *stbuf);
int configdb_fill_port_dir(void *buf, fuse_fill_dir_t filler);
int configdb_fill_port(unsigned int port, void *buf, fuse_fill_dir_t filler);
int configdb_get_port_attr(unsigned int port, const char *attr, char *buf);
int configdb_set_port_attr(unsigned int port, const char *attr, const char *buf);
int configdb_del_port(unsigned int port);

int configdb_add_subsys_port(const char *subsysnqn, unsigned int port);
int configdb_count_subsys_port(unsigned int port, int *num_ports);
int configdb_fill_subsys_port(unsigned int port,
			   void *buf, fuse_fill_dir_t filler);
int configdb_stat_subsys_port(const char *subsysnqn, unsigned int port,
			   struct stat *stbuf);
int configdb_del_subsys_port(const char *subsysnqn, unsigned int port);

int configdb_check_allowed_host(const char *hostnqn, const char *subsysnqn,
			     unsigned int portid);
int configdb_host_disc_entries(const char *hostnqn, u8 *log, int log_len);
int configdb_host_genctr(const char *hostnqn, int *genctr);
int configdb_subsys_identify_ctrl(const char *subsysnqn,
				  struct nvme_id_ctrl *id);

#endif /* _CONFIGDB_H */


