#ifndef _INODE_H
#define _INODE_H

#define FUSE_USE_VERSION 31

#include <fuse.h>

int inode_open(const char *filename);
void inode_close(const char *filename);

int inode_count_table(const char *tbl, int *num);

int inode_add_host(const char *nqn);
int inode_stat_host(const char *nqn, struct stat *stbuf);
int inode_fill_host_dir(void *buf, fuse_fill_dir_t filler);
int inode_del_host(const char *nqn);

int inode_add_subsys(struct nofuse_subsys *subsys);
int inode_get_discovery_nqn(char *nqn);
int inode_set_discovery_nqn(char *nqn);
int inode_stat_subsys(const char *nqn, struct stat *stbuf);
int inode_fill_subsys_dir(void *buf, fuse_fill_dir_t filler);
int inode_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler);
int inode_get_subsys_attr(const char *nqn, const char *attr, char *buf);
int inode_set_subsys_attr(const char *nqn, const char *attr, const char *buf);
int inode_del_subsys(struct nofuse_subsys *subsys);

int inode_add_namespace(const char *subsysnqn, int nsid);
int inode_count_namespaces(const char *subsysnqn, int *num);
int inode_stat_namespace(const char *subsysnqn, int nsid,
			 struct stat *stbuf);
int inode_fill_namespace_dir(const char *nqn, void *buf,
			     fuse_fill_dir_t filler);
int inode_fill_namespace(const char *nqn, int nsid,
			 void *buf, fuse_fill_dir_t filler);
int inode_get_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, char *buf);
int inode_set_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, const char *buf);
int inode_get_namespace_anagrp(const char *subsysnqn, int nsid,
			       int *ana_grpid);
int inode_set_namespace_anagrp(const char *subsysnqn, int nsid,
			       int ana_grpid);
int inode_del_namespace(const char *subsysnqn, int nsid);

int inode_add_ana_group(int port, int grpid, int ana_state);
int inode_count_ana_groups(const char *port, int *num);
int inode_stat_ana_group(const char *port, const char *ana_grpid,
			 struct stat *stbuf);
int inode_fill_ana_groups(const char *port,
			  void *buf, fuse_fill_dir_t filler);
int inode_get_ana_group(const char *port, const char *ana_grpid,
			int *ana_state);
int inode_set_ana_group(const char *port, const char *ana_grpid,
			int ana_state);
int inode_del_ana_group(const char *port, const char *grpid);

int inode_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int inode_count_host_subsys(const char *subsysnqn, int *num_hosts);
int inode_fill_host_subsys(const char *subsysnqn,
			   void *buf, fuse_fill_dir_t filler);
int inode_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			   struct stat *stbuf);
int inode_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int inode_add_port(unsigned int port);
int inode_stat_port(unsigned int port, struct stat *stbuf);
int inode_fill_port_dir(void *buf, fuse_fill_dir_t filler);
int inode_fill_port(unsigned int port, void *buf, fuse_fill_dir_t filler);
int inode_get_port_attr(unsigned int port, const char *attr, char *buf);
int inode_set_port_attr(unsigned int port, const char *attr, const char *buf);
int inode_del_port(struct nofuse_port *port);

int inode_add_subsys_port(const char *subsysnqn, unsigned int port);
int inode_count_subsys_port(unsigned int port, int *num_ports);
int inode_fill_subsys_port(unsigned int port,
			   void *buf, fuse_fill_dir_t filler);
int inode_stat_subsys_port(const char *subsysnqn, unsigned int port,
			   struct stat *stbuf);
int inode_del_subsys_port(const char *subsysnqn, unsigned int port);

int inode_check_allowed_host(const char *hostnqn, const char *subsysnqn,
			     struct nofuse_port *port);
int inode_host_disc_entries(const char *hostnqn, u8 *log, int log_len);
int inode_host_genctr(const char *hostnqn, int *genctr);

#endif


