#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <gnutls/gnutls.h>
#include <zlib.h>
#include <keyutils.h>

#include "base64.h"

#include "common.h"
#include "tls.h"
#include "ops.h"


static int tls_ep_write(struct endpoint *ep, void *buf, size_t buf_len)
{
	int ret;

	do {
		ret = gnutls_record_send(ep->session, buf, buf_len);
		if (ret < 0) {
			if (gnutls_error_is_fatal(ret)) {
				fprintf(stderr, "tls fatal error (%s)\n",
					gnutls_strerror(ret));
			} else {
				fprintf(stderr, "tls warning (%s)\n",
					gnutls_strerror(ret));
				ret = 1;
			}
		}
	} while (ret >= 0);
	if (ret < 0)
		return -EIO;
	return 0;
}

static int tls_ep_read(struct endpoint *ep, void *buf, size_t buf_len)
{
	int ret;

	do {
		ret = gnutls_record_recv(ep->session, buf, buf_len);
		if (ret < 0) {
			if (gnutls_error_is_fatal(ret)) {
				fprintf(stderr, "tls fatal error (%s)\n",
					gnutls_strerror(ret));
			} else {
				fprintf(stderr, "tls warning (%s)\n",
					gnutls_strerror(ret));
				ret = 1;
			}
		}
	} while (ret >= 0);
	if (ret < 0)
		return -EIO;
	return 0;
}

struct io_ops tls_io_ops = {
	.io_read = tls_ep_read,
	.io_write = tls_ep_write,
};

static int psk_server_cb(gnutls_session_t session, const char *identity,
			 gnutls_datum_t *key)
{
	key_serial_t keyring_id, psk;
	void *psk_key;
	int psk_len;
	const char *psk_key_type = "psk";

	fprintf(stdout, "%s: identity %s\n", __func__, identity);
	if (identity == NULL) {
		fprintf(stderr, "%s: no identity given\n", __func__);
		return -1;
	}

	keyring_id = find_key_by_type_and_desc("keyring", ".tls", 0);
	if (keyring_id < 0) {
		fprintf(stderr, "TLS keyring not available\n");
		return -1;
	}

	psk = keyctl_search(keyring_id, psk_key_type, identity, 0);
	if (key < 0) {
		fprintf(stdout, "%s: psk identity %s not found\n",
			__func__, identity);
		return -1;
	}
	psk_len = keyctl_read_alloc(psk, &psk_key);
	if (psk_len < 0) {
		fprintf(stdout, "%s: failed to read key %u\n",
			__func__, psk);
		return -1;
	}
	key->data = gnutls_malloc(psk_len);
	if (!key->data)
		return -1;
	memcpy(key->data, psk_key, psk_len);
	key->size = psk_len;
	free(psk_key);
	return 0;
}

int tls_handshake(struct endpoint *ep)
{
	const char *tls_priority = "SECURE256:+SECURE128:+SECURE128:-COMP-ALL:-VERS-ALL:+VERS-TLS1.3:%NO_TICKETS:+PSK:+DHE-PSK:+ECDHE-PSK";
	int ret;
	const char *err_pos;

	ret = gnutls_priority_set_direct(ep->session, tls_priority, &err_pos);
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr,"failed to set priorities, err %s\n", err_pos);
		return -EINVAL;
	}
	gnutls_handshake_set_timeout(ep->session, 20 * 1000);
	do {
		ret = gnutls_handshake(ep->session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
	if (ret < 0) {
		fprintf(stderr,"handshaked failed (%s)\n",
			gnutls_strerror(ret));
		ret = -EOPNOTSUPP;
	}
	ep->io_ops = &tls_io_ops;
	return ret;
}

int tls_create_endpoint(struct endpoint *ep)
{
	gnutls_psk_allocate_server_credentials(&ep->psk_cred);

	gnutls_global_set_log_level(9);

	gnutls_psk_set_server_credentials_function(ep->psk_cred,
						   psk_server_cb);
	gnutls_init(&ep->session, GNUTLS_SERVER);
	gnutls_transport_set_int(ep->session, ep->sockfd);

	gnutls_credentials_set(ep->session, GNUTLS_CRD_PSK, ep->psk_cred);

	return 0;
}

void tls_free_endpoint(struct endpoint *ep)
{
	gnutls_deinit(ep->session);
	gnutls_psk_free_server_credentials(ep->psk_cred);
}
