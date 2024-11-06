#ifndef _INODE_H
#define _INODE_H

int inode_open(const char *filename);
void inode_close(const char *filename);

int inode_count_table(const char *tbl, int *num);

int inode_add_host(const char *nqn);
int inode_stat_host(const char *nqn, struct stat *stbuf);
int inode_fill_host_dir(void *buf, fuse_fill_dir_t filler);
int inode_del_host(const char *nqn);

int inode_add_subsys(struct nofuse_subsys *subsys);
int inode_stat_subsys(const char *nqn, struct stat *stbuf);
int inode_fill_subsys_dir(void *buf, fuse_fill_dir_t filler);
int inode_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler);
int inode_get_subsys_attr(const char *nqn, const char *attr, char *buf);
int inode_del_subsys(struct nofuse_subsys *subsys);

int inode_add_namespace(struct nofuse_subsys *subsys,
			struct nofuse_namespace *ns);
int inode_count_namespaces(const char *subsysnqn, int *num);
int inode_stat_namespace(const char *subsysnqn, const char *nsid,
			 struct stat *stbuf);
int inode_fill_namespace_dir(const char *nqn, void *buf,
			     fuse_fill_dir_t filler);
int inode_fill_namespace(const char *nqn, const char *nsid,
			 void *buf, fuse_fill_dir_t filler);
int inode_get_namespace_attr(const char *subsysnqn, const char *nsid,
			     const char *attr, char *buf);
int inode_del_namespace(struct nofuse_namespace *ns);

int inode_add_ana_group(int port, int grpid, int ana_state);
int inode_count_ana_groups(const char *port, int *num);
int inode_stat_ana_group(const char *port, const char *ana_grpid,
			 struct stat *stbuf);
int inode_fill_ana_groups(const char *port,
			  void *buf, fuse_fill_dir_t filler);
int inode_get_ana_group(const char *port, const char *ana_grpid,
			void *buf);
int inode_del_ana_group(const char *port, const char *grpid);

int inode_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int inode_count_host_subsys(const char *subsysnqn, int *num_hosts);
int inode_fill_host_subsys(const char *subsysnqn,
			   void *buf, fuse_fill_dir_t filler);
int inode_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			   struct stat *stbuf);
int inode_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int inode_add_port(struct nofuse_port *port, u8 subtype);
int inode_stat_port(const char *port, struct stat *stbuf);
int inode_fill_port_dir(void *buf, fuse_fill_dir_t filler);
int inode_fill_port(const char *port, void *buf, fuse_fill_dir_t filler);
int inode_get_port_attr(const char *port, const char *attr, char *buf);
int inode_del_port(struct nofuse_port *port);

int inode_add_subsys_port(const char *subsysnqn, unsigned int port);
int inode_count_subsys_port(const char *port, int *num_ports);
int inode_fill_subsys_port(const char *port,
			   void *buf, fuse_fill_dir_t filler);
int inode_stat_subsys_port(const char *subsysnqn, const char *port,
			   struct stat *stbuf);
int inode_del_subsys_port(const char *subsysnqn, unsigned int port);

#endif


