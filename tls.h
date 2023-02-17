#ifndef _TLS_H
#define _TLS_H

int tls_import_key(struct host_iface *iface, const char *hostnqn,
		   const char *subsysnqn, const char *keystr);
int tls_handshake(struct endpoint *ep);
void tls_free_endpoint(struct endpoint *ep);
ssize_t tls_io(struct endpoint *ep, bool is_write, void *buf, size_t buf_len);

#endif /* _TLS_H */
