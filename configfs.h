#ifndef _CONFIGFS_H

int read_attr(int dfd, char *attr_path, char *value, size_t value_len);
int upload_configfs(struct etcd_ctx *ctx, const char *dir,
		    const char *file);

#endif /* _CONFIGFS_H */
