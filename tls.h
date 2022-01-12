#ifndef _TLS_H
#define _TLS_H

int tls_import_key(struct subsystem *subsys, const char *hostnqn, const char *keystr);
int tls_handshake(struct endpoint *ep);
void tls_free_endpoint(struct endpoint *ep);

#endif /* _TLS_H */
