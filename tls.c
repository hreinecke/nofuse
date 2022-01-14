#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <zlib.h>

#include "base64.h"

#include "common.h"
#include "tls.h"

static char *psk_identity;
static unsigned char psk_key[129];
static size_t psk_len;
static unsigned char psk_cipher[2];

int tls_import_key(struct subsystem *subsys, const char *hostnqn, const char *keystr)
{
	EVP_PKEY_CTX *kctx;
	const EVP_MD *md;
	int hmac, err;
	unsigned char decoded_key[64];
	size_t decoded_len;
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
			fprintf(stderr, "Invalid key length %lu for SHA(256)\n",
				strlen(keystr));
			return -EINVAL;
		}
		md = EVP_sha256();
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
	if (decoded_len != 32 && decoded_len != 48) {
		fprintf(stderr, "Invalid key length %lu\n", decoded_len);
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

	subsys->tls_key = malloc(decoded_len);
	if (!subsys->tls_key)
		return -ENOMEM;
	subsys->tls_key_len = decoded_len;

	/* HKDF functions as per NVMe-TCP v1.0a */
	kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!kctx) {
		free(subsys->tls_key);
		subsys->tls_key = NULL;
		return -ENOMEM;
	}

	err = -ENOKEY;
	if (EVP_PKEY_derive_init(kctx) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_set_hkdf_md(kctx, md) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_set1_hkdf_key(kctx, decoded_key, decoded_len) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, "tls13 ", 6) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, "HostNQN", 7) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, hostnqn, strlen(hostnqn)) <= 0)
		goto out_free;

	if (EVP_PKEY_derive(kctx, subsys->tls_key, &subsys->tls_key_len) <= 0) {
		fprintf(stderr, "EVP_KDF_derive failed\n");
		goto out_free;
	}

	psk_identity = malloc(strlen(hostnqn) + strlen(subsys->nqn) + 12);
	if (!psk_identity) {
		err = -ENOMEM;
		goto out_free;
	}
	sprintf(psk_identity, "NVMeR%02d %s %s", hmac,
		hostnqn, subsys->nqn);

	psk_len = subsys->tls_key_len;
	err = -ENOKEY;
	if (EVP_PKEY_derive_init(kctx) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_set_hkdf_md(kctx, md) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_set1_hkdf_key(kctx, subsys->tls_key, subsys->tls_key_len) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, "tls13 ", 6) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, "nvme-tls-psk", 7) <= 0)
		goto out_free;
	if (EVP_PKEY_CTX_add1_hkdf_info(kctx, psk_identity, strlen(psk_identity)) <= 0)
		goto out_free;

	if (EVP_PKEY_derive(kctx, psk_key, &psk_len) <= 0) {
		fprintf(stderr, "EVP_KDF_derive failed\n");
		goto out_free;
	}
	err = 0;

out_free:
	EVP_PKEY_CTX_free(kctx);

	return err;
}

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
	SSL_SESSION *tmpsess = NULL;
	const SSL_CIPHER *cipher = NULL;

	if (strlen(psk_identity) != identity_len
            || memcmp(psk_identity, identity, identity_len) != 0) {
		*sess = NULL;
		return 1;
	}

	cipher = SSL_CIPHER_find(ssl, psk_cipher);
	if (cipher == NULL) {
		fprintf(stderr, "Error finding suitable ciphersuite\n");
		return 0;
	}

	tmpsess = SSL_SESSION_new();
	if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, psk_key, psk_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
		return 0;
	}
	*sess = tmpsess;

	return 1;
}

int tls_handshake(struct endpoint *ep)
{
	const SSL_METHOD *method;
	int ret;

	SSL_library_init();
	SSL_load_error_strings();

	method = TLS_server_method();
	if (!method) {
		fprintf(stderr, "Cannot start server\n");
		return -EPROTO;
	}

	ep->ctx = SSL_CTX_new(method);
	if (!ep->ctx)
		return -ENOMEM;

	SSL_CTX_set_psk_find_session_callback(ep->ctx, psk_find_session_cb);

	if (!SSL_CTX_set_min_proto_version(ep->ctx, TLS1_3_VERSION)) {
		fprintf(stderr, "TLS 1.3 is not supported\n");
		return -EPROTO;
	}

	/*
	 * NOCLOSE prevents the library from sending a session closure
	 * alert when the file descriptor is closed.
	 */
	ep->bio = BIO_new_fd(ep->sockfd, BIO_NOCLOSE);
	if (!ep->bio)
		return -ENOMEM;

	ep->ssl = NULL;
	BIO_get_ssl(ep->bio, &ep->ssl);
	if (!ep->ssl) {
		fprintf(stderr, "ssl initialisation failed\n");
		goto out_bio_free;
	}

	ret = SSL_do_handshake(ep->ssl);
	if (ret > 0)
		return 0;
	fprintf(stderr, "ssl handshaked failed, error %d\n", ret);
out_bio_free:
	SSL_free(ep->ssl);
	ep->ssl = NULL;
	BIO_free_all(ep->bio);
	ep->bio = NULL;
	SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
	return ret;
}
	
void tls_free_endpoint(struct endpoint *ep)
{
	if (ep->ssl)
		SSL_free(ep->ssl);
	ep->ssl = NULL;
	if (ep->bio)
		BIO_free_all(ep->bio);
	ep->bio = NULL;
	if (ep->ctx)
		SSL_CTX_free(ep->ctx);
	ep->ctx = NULL;
}
