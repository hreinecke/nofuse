#ifndef _TLS_H
#define _TLS_H

int tls_global_init(void);
int tls_handshake(struct nofuse_queue *ep);
void tls_free_endpoint(struct nofuse_queue *ep);
ssize_t tls_io(struct nofuse_queue *ep, bool is_write,
	       void *buf, size_t buf_len);

#endif /* _TLS_H */
