/*
 * base64.c - RFC4648-compliant base64 encoding
 *
 * Copyright (c) 2020 Hannes Reinecke, SUSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode() - base64-encode some bytes
 * @src: the bytes to encode
 * @srclen: number of bytes to encode
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes the input string using characters from the set [A-Za-z0-9+,].
 * The encoded string is roughly 4/3 times the size of the input string.
 *
 * Return: length of the encoded string
 */
int base64_encode(const unsigned char *src, int srclen, char *dst)
{
	int i, bits = 0, src_bits = 8, dst_bits = 6;
	u_int32_t ac = 0;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << src_bits) | src[i];
		bits += src_bits;
		do {
			bits -= dst_bits;
			*cp++ = base64_table[(ac >> bits) & 0x3f];
		} while (bits >= dst_bits);
	}
	if (bits) {
		*cp++ = base64_table[(ac << (dst_bits - bits)) & 0x3f];
		bits -= dst_bits;
	}
	while (bits < 0) {
		*cp++ = '=';
		bits += 2;
	}

	return cp - dst;
}

/**
 * base64_decode() - base64-decode some bytes
 * @src: the base64-encoded string to decode
 * @len: number of bytes to decode
 * @dst: (output) the decoded bytes.
 *
 * Decodes the base64-encoded bytes @src according to RFC 4648.
 *
 * Return: number of decoded bytes
 */
int base64_decode(const char *src, int srclen, unsigned char *dst)
{
	u_int32_t ac = 0;
	int i, bits = 0, src_bits = 6, dst_bits = 8;
	unsigned char *bp = dst;

        for (i = 0; i < srclen; i++) {
                const char *p = strchr(base64_table, src[i]);

                if (src[i] == '=') {
                        ac = (ac << src_bits);
			bits += src_bits;
			if (bits >= dst_bits)
				bits -= dst_bits;
                        continue;
                }
                if (p == NULL || src[i] == 0)
                        return -EINVAL;
                ac = (ac << src_bits) | (p - base64_table);
                bits += src_bits;
                if (bits >= dst_bits) {
                        bits -= dst_bits;
                        *bp++ = (unsigned char)(ac >> bits);
                }
	}
	if (ac && ((1 << bits) - 1))
		return -EAGAIN;

	return bp - dst;
}

static const char base32_table[33] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * base32_encode() - base32-encode some bytes
 * @src: the bytes to encode
 * @srclen: number of bytes to encode
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes the input string using characters from the set [A-Z2-7].
 * The encoded string is roughly 4/3 times the size of the input string.
 *
 * Return: length of the encoded string
 */
int base32_encode(const unsigned char *src, int srclen, char *dst)
{
	int i, bits = 0, src_bits = 8, dst_bits = 5, pad;
	u_int32_t ac = 0;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << src_bits) | src[i];
		bits += src_bits;
		do {
			bits -= dst_bits;
			*cp++ = base32_table[(ac >> bits) & 0x1f];
		} while (bits >= dst_bits);
	}
	if (bits) {
		*cp++ = base32_table[(ac << (dst_bits - bits)) & 0x1f];
		bits -= dst_bits;
	}
	pad = (src_bits - ((cp - dst) % src_bits)) % src_bits;
	while (pad > 0) {
		*cp++ = '=';
		pad--;
	}

	return cp - dst;
}

/**
 * base32_decode() - base32-decode some bytes
 * @src: the base64-encoded string to decode
 * @len: number of bytes to decode
 * @dst: (output) the decoded bytes.
 *
 * Decodes the base32-encoded bytes @src according to RFC 4648.
 *
 * Return: number of decoded bytes
 */
int base32_decode(const char *src, int srclen, unsigned char *dst)
{
	u_int32_t ac = 0;
	int i, bits = 0, src_bits = 5, dst_bits = 8;
	unsigned char *bp = dst;

        for (i = 0; i < srclen; i++) {
                const char *p = strchr(base32_table, src[i]);

                if (src[i] == '=') {
                        ac = (ac << src_bits);
			bits += src_bits;
			if (bits >= dst_bits)
				bits -= dst_bits;
                        continue;
                }
                if (p == NULL || src[i] == 0)
                        return -EINVAL;
                ac = (ac << src_bits) | (p - base32_table);
                bits += src_bits;
                if (bits >= dst_bits) {
                        bits -= dst_bits;
                        *bp++ = (unsigned char)(ac >> bits);
                }
	}
	if (ac && ((1 << bits) - 1))
		return -EAGAIN;

	return bp - dst;
}
