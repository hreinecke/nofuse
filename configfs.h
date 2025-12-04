#ifndef _CONFIGFS_H
#define _CONFIGFS_H

int read_attr(char *attr_path, char *value, size_t value_len);
char *path_to_key(struct etcd_ctx *ctx, const char *path);
char *key_to_attr(struct etcd_ctx *ctx, char *key);
int configfs_validate_port(struct etcd_ctx *ctx, unsigned int portid);
int configfs_validate_namespace(struct etcd_ctx *ctx, const char *subsysnqn,
				int nsid);
int configfs_update_key(struct etcd_ctx *ctx, const char *dirname,
			const char *name);
int upload_configfs(struct etcd_ctx *ctx, const char *dir,
		    const char *file);
int configfs_validate_cluster(struct etcd_ctx *ctx);
int configfs_load_ana(struct etcd_ctx *ctx);
int configfs_validate_ana(struct etcd_ctx *ctx);
int configfs_purge_ports(struct etcd_ctx *ctx);
int configfs_purge_subsystems(struct etcd_ctx *ctx);
int configfs_register(struct etcd_ctx *ctx);
int configfs_unregister(struct etcd_ctx *ctx);

#endif /* _CONFIGFS_H */
