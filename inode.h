#ifndef _INODE_H
#define _INODE_H

int inode_open(const char *filename);
void inode_close(const char *filename);

int inode_add_root(const char *pathname);
int inode_get_root(const char *pathname);
int inode_fill_root(void *buf, fuse_fill_dir_t filler);

int inode_add_inode(const char *pathname, int parent_ino);
int inode_del_inode(int ino);

int inode_find_links(const char *tbl, int parent_ino);

int inode_add_host(const char *nqn);
int inode_get_host_ino(const char *nqn, int *inode);
int inode_fill_host_dir(void *buf, fuse_fill_dir_t filler);
int inode_del_host(const char *nqn);

int inode_add_subsys(struct nofuse_subsys *subsys, int parent_ino);
int inode_get_subsys_ino(const char *subsys, int parent_ino, int *inode);
int inode_stat_subsys(const char *nqn, struct stat *stbuf);
int inode_fill_subsys_dir(void *buf, fuse_fill_dir_t filler);
int inode_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler);
int inode_get_subsys_attr(const char *nqn, const char *attr, char *buf);
int inode_del_subsys(struct nofuse_subsys *subsys);

int inode_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int inode_count_host_subsys(const char *subsysnqn, int *num_hosts);
int inode_fill_host_subsys(const char *subsysnqn,
			   void *buf, fuse_fill_dir_t filler);
int inode_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			   struct stat *stbuf);
int inode_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int inode_add_port(struct nofuse_port *port, u8 subtype);
int inode_get_port_ino(const char *port, int parent_ino, int *ino);
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


