#ifndef _CONFIGFS_H
#define _CONFIGFS_H

int read_attr(char *attr_path, char *value, size_t value_len);
char *path_to_key(struct etcd_ctx *ctx, const char *path);
int update_value_to_key(struct etcd_ctx *ctx, const char *dirname,
			const char *name);
int upload_configfs(struct etcd_ctx *ctx, const char *dir,
		    const char *file);
int validate_cluster(struct etcd_ctx *ctx);
int load_ana(struct etcd_ctx *ctx);
int validate_ana(struct etcd_ctx *ctx);
int purge_ports(struct etcd_ctx *ctx);
int purge_subsystems(struct etcd_ctx *ctx);

#endif /* _CONFIGFS_H */
