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

static char *psk_identity;
static unsigned char psk_key[129];
static size_t psk_len;
static unsigned char psk_cipher[2];

static unsigned char *derive_retained_key(const EVP_MD *md, const char *hostnqn,
					  unsigned char *generated_key,
					  size_t key_len)
{
	unsigned char *retained_key;
	EVP_PKEY_CTX *ctx;
	size_t retained_len;
	key_serial_t keyring_id;
	int err;

	retained_key = malloc(key_len);
	if (!retained_key)
		return NULL;

	retained_len = key_len;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		goto out_free_retained_key;

	err = -ENOKEY;
	if (EVP_PKEY_derive_init(ctx) <= 0)
		goto out_free_retained_key;
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0)
		goto out_free_retained_key;
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, generated_key, key_len) <= 0)
		goto out_free_retained_key;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "tls13 ", 6) <= 0)
		goto out_free_retained_key;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "HostNQN", 7) <= 0)
		goto out_free_retained_key;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, hostnqn, strlen(hostnqn)) <= 0)
		goto out_free_retained_key;

	if (EVP_PKEY_derive(ctx, retained_key, &retained_len) <= 0) {
		fprintf(stderr, "EVP_KDF derive failed\n");
		err = ENOKEY;
	}
	err = 0;

	keyring_id = find_key_by_type_and_desc("keyring", ".nvme", 0);
	if (keyring_id < 0) {
		fprintf(stderr, "NVMe keyring not available, error %d", errno);
	} else {
		key_serial_t key;
		const char *key_type = "psk";
		char *identity;

		identity = malloc(strlen(hostnqn) + 4);
		if (!identity) {
			err = ENOMEM;
			goto out_free_retained_key;
		}
		sprintf(identity, "%02d %s",
			md == EVP_sha256() ? 1 : 2, hostnqn);
		key = keyctl_search(keyring_id, key_type, identity, 0);
		if (key >= 0) {
			printf("updating %s key '%s'\n", key_type, identity);
			err = keyctl_update(key, retained_key, retained_len);
			if (err)
				fprintf(stderr, "updating %s key '%s' failed\n",
					key_type, identity);
		} else {
			printf("adding %s key '%s'\n", key_type, identity);
			key = add_key(key_type, identity,
				      retained_key, retained_len, keyring_id);
			if (key < 0)
				fprintf(stderr, "adding %s key '%s' failed, error %d\n",
					key_type, identity, errno);
		}
		free(identity);
	}
out_free_retained_key:
	if (err) {
		free(retained_key);
		retained_key = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return retained_key;
}

static int derive_tls_key(const EVP_MD *md, struct host_iface *iface,
			  const char *hostnqn, const char *subsysnqn)
{
	EVP_PKEY_CTX *ctx;
	key_serial_t keyring_id;
	int err, i;

	psk_identity = malloc(strlen(hostnqn) + strlen(subsysnqn) + 12);
	if (!psk_identity)
		return -ENOMEM;

	sprintf(psk_identity, "NVMe0R%02d %s %s", md == EVP_sha256() ? 1 : 2,
		hostnqn, subsysnqn);

	psk_len = iface->tls_key_len;
	memset(psk_key, 0, psk_len);

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_free_identity;
	}

	err = -ENOKEY;
	if (EVP_PKEY_derive_init(ctx) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, iface->tls_key,
				       iface->tls_key_len) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "tls13 ", 6) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "nvme-tls-psk", 12) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, psk_identity,
					strlen(psk_identity)) <= 0)
		goto out_free_ctx;

	if (EVP_PKEY_derive(ctx, psk_key, &psk_len) <= 0) {
		fprintf(stderr, "EVP_KDF_derive failed\n");
	}

	keyring_id = find_key_by_type_and_desc("keyring", ".tls", 0);
	if (keyring_id < 0) {
		printf("TLS keyring not available\ngenerated TLS key\n%s\n",
		       psk_identity);
		for (i = 0; i < psk_len; i++)
			printf("%02x", psk_key[i]);
		printf("\n");
	} else {
		key_serial_t key;
		const char *key_type = "psk";
		char *identity;

		identity = malloc(strlen(psk_identity) + 5);
		if (!identity) {
			err = -ENOMEM;
			goto out_free_ctx;
		}
		sprintf(identity, ";;;%s", psk_identity);
		key = keyctl_search(keyring_id, key_type, identity, 0);
		if (key >= 0) {
			printf("updating %s key '%s'\n",
			       key_type, identity);
			err = keyctl_update(key, psk_key, psk_len);
			if (err)
				fprintf(stderr, "updating %s key '%s' failed\n",
					key_type, identity);
		} else {
			printf("adding %s key '%s'\n", key_type, identity);
			key = add_key(key_type, identity,
				      psk_key, psk_len, keyring_id);
			if (key < 0) {
				fprintf(stderr, "adding %s key '%s' failed, error %d\n",
					key_type, identity, errno);
				err = -errno;
			}
		}
		free(identity);
	}
	err = 0;

out_free_ctx:
	EVP_PKEY_CTX_free(ctx);
out_free_identity:
	if (err) {
		free(psk_identity);
		psk_identity = NULL;
	}

	return err;
}

int tls_import_key(struct host_iface *iface, const char *hostnqn,
		   const char *subsysnqn, const char *keystr)
{
	const EVP_MD *md;
	int hmac, err;
	unsigned char decoded_key[64];
	size_t decoded_len, key_len;
	unsigned int crc = 0, key_crc;

    	if (sscanf(keystr, "NVMeTLSkey-1:%02x:*s", &hmac) != 1) {
		fprintf(stderr, "Invalid key header '%s'\n", keystr);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(keystr) != 65) {
			fprintf(stderr, "Invalid key length %lu for SHA(256) on key '%s'\n",
				strlen(keystr), keystr);
			return -EINVAL;
		}
		md = EVP_sha256();
		key_len = 32;
		psk_cipher[0] = 0x13;
		psk_cipher[1] = 0x01;
		break;
	case 2:
		if (strlen(keystr) != 89) {
			fprintf(stderr, "Invalid key length %lu for SHA(384)\n",
				strlen(keystr));
			return -EINVAL;
		}
		md = EVP_sha384();
		key_len = 48;
		psk_cipher[0] = 0x13;
		psk_cipher[1] = 0x02;
		break;
	default:
		fprintf(stderr, "Invalid HMAC identifier %d\n", hmac);
		return -EINVAL;
		break;
	}

	err = base64_decode(keystr + 16, strlen(keystr) - 17,
			    decoded_key);
	if (err < 0) {
		fprintf(stderr, "Base64 decoding failed, error %d\n",
			err);
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		fprintf(stderr, "Base64 decoding failed (%s, size %lu)\n",
			keystr + 16, decoded_len);
		return -EINVAL;
	}
	decoded_len -= 4;
	if (decoded_len != key_len) {
		fprintf(stderr, "Invalid key length %lu, expected %lu\n",
			decoded_len, key_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((u_int32_t)decoded_key[decoded_len]) |
		((u_int32_t)decoded_key[decoded_len + 1] << 8) |
		((u_int32_t)decoded_key[decoded_len + 2] << 16) |
		((u_int32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		fprintf(stderr, "CRC mismatch (key %08x, crc %08x)\n",
			key_crc, crc);
		return -EINVAL;
	}
	printf("Key is valid (HMAC %d, length %lu, CRC %08x)\n",
	       hmac, decoded_len, crc);

	iface->tls_key_len = decoded_len;

	iface->tls_key = derive_retained_key(md, hostnqn,
					     decoded_key, decoded_len);
	if (!iface->tls_key) {
		fprintf(stderr, "Failed to derive retained key\n");
		return -ENOKEY;
	}

	return derive_tls_key(md, iface, hostnqn, subsysnqn);
}

static unsigned int psk_server_cb(SSL *ssl, const char *identity,
				 unsigned char *psk, unsigned int max_psk_len)
{
	fprintf(stdout, "%s: identity %s\n", __func__, identity);
	if (SSL_version(ssl) >= TLS1_3_VERSION)
		return 0;

	if (identity == NULL) {
		fprintf(stderr, "%s: no identity given\n", __func__);
		return 0;
	}

	if (strlen(psk_identity) != strlen(identity) ||
	    memcmp(psk_identity, identity, strlen(psk_identity))) {
		fprintf(stdout, "%s: psk identity mismatch %s len %lu\n",
			__func__, psk_identity, strlen(psk_identity));
		return 0;
	}

	if (psk_len > max_psk_len) {
		fprintf(stdout, "%s: psk buffer too small (%d) for key (%ld)\n",
			__func__, max_psk_len, psk_len);
		return 0;
	}
	memcpy(psk, psk_key, psk_len);
	return psk_len;
}

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
	SSL_SESSION *tmpsess = NULL;
	const SSL_CIPHER *cipher = NULL;
	int i, nsig;

	fprintf(stdout, "%s: identity %s len %lu\n",
		__func__, identity, identity_len);
	if (strlen(psk_identity) != identity_len
            || memcmp(psk_identity, identity, identity_len) != 0) {
		fprintf(stdout, "%s: psk identity mismatch %s len %lu\n",
			__func__, psk_identity, strlen(psk_identity));
		*sess = NULL;
		return 0;
	}

	cipher = SSL_CIPHER_find(ssl, psk_cipher);
	if (cipher == NULL) {
		fprintf(stderr, "Error finding suitable ciphersuite\n");
		return 0;
	}
	fprintf(stdout, "%s: using cipher %s\n",
		__func__, SSL_CIPHER_get_name(cipher));

	nsig = SSL_get_shared_sigalgs(ssl, -1, NULL, NULL, NULL, NULL, NULL);
	for (i = 0; i < nsig; i++) {
		int sign_nid, hash_nid;
		unsigned char rhash, rsign;

		SSL_get_shared_sigalgs(ssl, i, &sign_nid, &hash_nid, NULL,
				&rsign, &rhash);
		fprintf(stdout, "sigalg %d: %02x+%02x raw %02x+%02x ", i,
			sign_nid, hash_nid, rsign, rhash);
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

int tls_handshake(struct endpoint *ep)
{
	const SSL_METHOD *method;
	long ssl_opts;
	int ret;

	ep->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (!ep->bio_err) {
		fprintf(stderr, "failed to create error bio\n");
		return -ENOMEM;
	}
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	method = TLS_server_method();
	if (!method) {
		fprintf(stderr, "Cannot start server\n");
		ret = -EPROTO;
		goto out_bio_free;
	}

	ep->ctx = SSL_CTX_new(method);
	if (!ep->ctx) {
		ret = -ENOMEM;
		goto out_bio_free;
	}

	SSL_CTX_set_psk_server_callback(ep->ctx, psk_server_cb);
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
		int err = SSL_do_handshake(ep->ssl);
		if (err > 0) {
			fprintf(stdout, "tls handshake succeeded\n");
			return 0;
		}
		ret = SSL_get_error(ep->ssl, err);
	} while (ret == SSL_ERROR_WANT_READ ||
		 ret == SSL_ERROR_WANT_WRITE);

	switch (ret) {
	case SSL_ERROR_SSL:
		fprintf(stderr, "SSL library error\n");
		ERR_print_errors(ep->bio_err);
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
		ERR_print_errors(ep->bio_err);
		break;
	}
	ret = -EOPNOTSUPP;
	SSL_free(ep->ssl);
	ep->ssl = NULL;
out_ctx_free:
	SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
out_bio_free:
	BIO_free(ep->bio_err);
	ep->bio_err = NULL;
	return ret;
}

ssize_t tls_io(struct endpoint *ep, bool is_write, void *buf, size_t buf_len)
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
		ERR_print_errors(ep->bio_err);
		errno = EIO;
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		fprintf(stderr, "SSL want_x509_lookup\n");
		errno = ENOKEY;
		break;
	case SSL_ERROR_SYSCALL:
		fprintf(stderr, "SSL syscall error \n");
		ERR_print_errors(ep->bio_err);
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
		ERR_print_errors(ep->bio_err);
		errno = EIO;
		break;
	}
	return -errno;
}

void tls_free_endpoint(struct endpoint *ep)
{
	if (ep->ssl)
		SSL_free(ep->ssl);
	ep->ssl = NULL;
	if (ep->ctx)
		SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
	if (ep->bio_err)
		BIO_free(ep->bio_err);
	ep->bio_err = NULL;
}
