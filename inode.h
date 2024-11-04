#ifndef _INODE_H
#define _INODE_H

int inode_open(const char *filename);
void inode_close(const char *filename);

int inode_add_root(const char *pathname);
int inode_add_inode(const char *pathname, int parent_ino);
int inode_del_inode(int ino);

int inode_add_subsys(struct nofuse_subsys *subsys, int parent_ino);
int inode_del_subsys(struct nofuse_subsys *subsys);

int inode_add_port(struct nofuse_port *port, u8 subtype);
int inode_modify_port(struct nofuse_port *port, char *attr);
int inode_del_port(struct nofuse_port *port);

#endif


