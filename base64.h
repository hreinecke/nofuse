#ifndef _BASE64_H
#define _BASE64_H

int base64_encode(const unsigned char *src, int len, char *dst);
int base64_decode(const char *src, int len, unsigned char *dst);
int base32_encode(const unsigned char *src, int len, char *dst);
int base32_decode(const char *src, int len, unsigned char *dst);

#endif /* _BASE64_H */
