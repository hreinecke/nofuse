/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * tls.c
 * TLS support for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>
#include <keyutils.h>

#include "base64.h"

#include "common.h"
#include "tls.h"
#include "ops.h"

static unsigned char psk_cipher_sha256[2] = { 0x13, 0x01 };
static unsigned char psk_cipher_sha384[2] = { 0x13, 0x02 };

static int tls_ep_read(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return tls_io(ep, false, buf, buf_len);
}

static int tls_ep_write(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return tls_io(ep, true, buf, buf_len);
}

struct io_ops tls_io_ops = {
	.io_read = tls_ep_read,
	.io_write = tls_ep_write,
};

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
	SSL_SESSION *tmpsess = NULL;
	const SSL_CIPHER *cipher = NULL;
	key_serial_t keyring_id, psk;
	void *psk_key;
	size_t psk_len;

	fprintf(stdout, "%s: identity %s len %lu\n",
		__func__, identity, identity_len);

	keyring_id = find_key_by_type_and_desc("keyring", ".nvme", 0);
	if (keyring_id < 0) {
		fprintf(stderr, "%s: '.nvme' keyring not available\n",
			__func__);
		*sess = NULL;
		return 0;
	}

	psk = keyctl_search(keyring_id, "psk", (const char *)identity, 0);
	if (psk < 0) {
		fprintf(stdout, "%s: psk identity %s (not found\n",
			__func__, identity);
		*sess = NULL;
		return 0;
	}
	psk_len = keyctl_read_alloc(psk, &psk_key);
	if (psk_len < 0) {
		fprintf(stdout, "%s: failed to read key %u\n",
			__func__, psk);
		*sess = NULL;
		return 0;
	}

	if (!strncmp((const char *)identity, "NVMe1R02", 8) ||
	    !strncmp((const char *)identity, "NVMe1G02", 8)) {
		/* TLS_AES_256_GCM_SHA384 */
		cipher = SSL_CIPHER_find(ssl, psk_cipher_sha384);
	} else {
		cipher = SSL_CIPHER_find(ssl, psk_cipher_sha256);
	}
	if (cipher == NULL) {
		fprintf(stderr, "Error finding suitable ciphersuite\n");
		return 0;
	}
	fprintf(stdout, "%s: tls %s using cipher %s\n",
		__func__, SSL_get_version(ssl), SSL_CIPHER_get_name(cipher));
	cipher = SSL_get_pending_cipher(ssl);
	if (cipher) {
		fprintf(stdout, "%s: pending cipher %s\n",
			__func__, SSL_CIPHER_get_name(cipher));
	}

	tmpsess = SSL_SESSION_new();
	if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, psk_key, psk_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
		fprintf(stderr, "Error setting tls parameters\n");
		return 0;
	}
	*sess = tmpsess;

	return 1;
}

int tls_handshake(struct nofuse_queue *ep)
{
	long ssl_opts;
	int ret, ssl_err;

	ep->ctx = SSL_CTX_new(TLS_server_method());
	if (!ep->ctx) {
		ret = -ENOMEM;
		goto out_bio_free;
	}

	SSL_CTX_set_psk_server_callback(ep->ctx, NULL);
	SSL_CTX_set_psk_find_session_callback(ep->ctx, psk_find_session_cb);
	ssl_opts = SSL_CTX_get_options(ep->ctx);
	ssl_opts |= SSL_OP_ALLOW_NO_DHE_KEX;
	SSL_CTX_set_options(ep->ctx, ssl_opts);
	SSL_CTX_set_num_tickets(ep->ctx, 0);

	ep->ssl = SSL_new(ep->ctx);
	if (!ep->ssl) {
		fprintf(stderr, "ssl initialisation failed\n");
		ret = -ENOPROTOOPT;
		goto out_ctx_free;
	}
	SSL_set_fd(ep->ssl, ep->sockfd);
	SSL_set_accept_state(ep->ssl);

retry_handshake:
	do {
		ssl_err = SSL_do_handshake(ep->ssl);
		if (ssl_err > 0) {
			fprintf(stdout, "tls handshake succeeded\n");
			ep->io_ops = &tls_io_ops;
			return 0;
		}
		ret = SSL_get_error(ep->ssl, ssl_err);
	} while (ret == SSL_ERROR_WANT_READ ||
		 ret == SSL_ERROR_WANT_WRITE);

	switch (ret) {
	case SSL_ERROR_SSL:
		fprintf(stderr, "SSL library error\n");
		ERR_print_errors_fp(stderr);
		break;
	case SSL_ERROR_WANT_READ:
		fprintf(stderr, "SSL want_read\n");
		goto retry_handshake;
		break;
	case SSL_ERROR_WANT_WRITE:
		fprintf(stderr, "SSL want_write\n");
		goto retry_handshake;
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		fprintf(stderr, "SSL want_x509_lookup\n");
		break;
	case SSL_ERROR_SYSCALL:
		fprintf(stderr, "SSL syscall error \n");
		break;
	case SSL_ERROR_ZERO_RETURN:
		fprintf(stderr, "SSL zero return\n");
		break;
	case SSL_ERROR_WANT_CONNECT:
		fprintf(stderr, "SSL want_connect\n");
		break;
	case SSL_ERROR_WANT_ACCEPT:
		fprintf(stderr, "SSL want_accept\n");
		break;
	case SSL_ERROR_WANT_ASYNC:
		fprintf(stderr, "SSL want_async\n");
		break;
	case SSL_ERROR_WANT_ASYNC_JOB:
		fprintf(stderr, "SSL want_async_job\n");
		break;
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		fprintf(stderr, "SSL want_client_hello\n");
		break;
	case SSL_ERROR_NONE:
	default:
		fprintf(stderr, "SSL unknown\n");
		ERR_print_errors_fp(stderr);
		break;
	}
	ret = -EOPNOTSUPP;
	SSL_free(ep->ssl);
	ep->ssl = NULL;
out_ctx_free:
	SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
out_bio_free:
	return ret;
}

ssize_t tls_io(struct nofuse_queue *ep, bool is_write, void *buf, size_t buf_len)
{
	int ret, err;

	do {
		if (is_write)
			err = SSL_write(ep->ssl, buf, buf_len);
		else
			err = SSL_read(ep->ssl, buf, buf_len);
		if (err > 0)
			return err;
		ret = SSL_get_error(ep->ssl, err);
	} while (ret == SSL_ERROR_WANT_READ ||
		 ret == SSL_ERROR_WANT_WRITE);


	switch (ret) {
	case SSL_ERROR_SSL:
		fprintf(stderr, "SSL library error\n");
		ERR_print_errors_fp(stderr);
		errno = EIO;
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		fprintf(stderr, "SSL want_x509_lookup\n");
		errno = ENOKEY;
		break;
	case SSL_ERROR_SYSCALL:
		fprintf(stderr, "SSL syscall error\n");
		ERR_print_errors_fp(stderr);
		errno = ENXIO;
		break;
	case SSL_ERROR_ZERO_RETURN:
		fprintf(stderr, "SSL zero return\n");
		errno = ENODATA;
		break;
	case SSL_ERROR_WANT_CONNECT:
		fprintf(stderr, "SSL want_connect\n");
		errno = ENOLINK;
		break;
	case SSL_ERROR_WANT_ACCEPT:
		fprintf(stderr, "SSL want_accept\n");
		errno = EPROTO;
		break;
	case SSL_ERROR_WANT_ASYNC:
		fprintf(stderr, "SSL want_async\n");
		errno = EBUSY;
		break;
	case SSL_ERROR_WANT_ASYNC_JOB:
		fprintf(stderr, "SSL want_async_job\n");
		errno = EBUSY;
		break;
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		fprintf(stderr, "SSL want_client_hello\n");
		errno = EPROTO;
		break;
	default:
		fprintf(stderr, "SSL unknown (%d)\n", ret);
		ERR_print_errors_fp(stderr);
		errno = EIO;
		break;
	}
	return -errno;
}

int tls_global_init(void)
{
	key_serial_t serial;
	int ret;
#if 0
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
#endif
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	serial = find_key_by_type_and_desc("keyring", ".nvme", 0);
	if (!serial) {
		fprintf(stderr, "default '.nvme' keyring not found\n");
		return -1;
	}
	ret = keyctl_link(serial, KEY_SPEC_SESSION_KEYRING);
	if (ret < 0) {
		fprintf(stderr, "failed to link '.nvme' into session keyring");
		serial = -1;
	}
	return serial;
}

void tls_free_queue(struct nofuse_queue *ep)
{
	if (ep->ssl)
		SSL_free(ep->ssl);
	ep->ssl = NULL;
	if (ep->ctx)
		SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
}
