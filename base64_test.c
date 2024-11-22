#include <stdio.h>
#include <string.h>

#include "base64.h"

struct test_vec {
    char *str;
    char *res;
};

#define NUM_VECS 7

struct test_vec base64_test[NUM_VECS] = {
    { .str = "",       .res = "" },
    { .str = "f",      .res = "Zg==" },
    { .str = "fo",     .res = "Zm8=" },
    { .str = "foo",    .res = "Zm9v" },
    { .str = "foob",   .res = "Zm9vYg==" },
    { .str = "fooba",  .res = "Zm9vYmE=" },
    { .str = "foobar", .res = "Zm9vYmFy" },
};

struct test_vec base32_test[NUM_VECS] = {
    { .str = "",       .res = "" },
    { .str = "f",      .res = "MY======" },
    { .str = "fo",     .res = "MZXQ====" },
    { .str = "foo",    .res = "MZXW6===" },
    { .str = "foob",   .res = "MZXW6YQ=" },
    { .str = "fooba",  .res = "MZXW6YTB" },
    { .str = "foobar", .res = "MZXW6YTBOI======" },
};

int main(int argc, char **argv)
{
    char result[18];
    int i, ret;

    for (i = 0; i < NUM_VECS; i++) {
	struct test_vec *test = &base64_test[i];

	printf("Base64 encoding %s: ", test->str);
	ret = base64_encode((unsigned char *)test->str,
			    strlen(test->str), result);
	if (ret < 0) {
	    printf("error %d\n", ret);
	} else if (strcmp(result, test->res)) {
	    printf("encoding error '%s' should be '%s'\n",
		   result, test->res);
	} else {
	    printf("Ok\n");
	}
    }
    for (i = 0; i < NUM_VECS; i++) {
	struct test_vec *test = &base64_test[i];

	printf("Base64 decoding %s: ", test->res);
	memset(result, 0, sizeof(result));
	ret = base64_decode(test->res, strlen(test->res),
			    (unsigned char *)result);
	if (ret < 0) {
	    printf("error %d\n", ret);
	} else if (strcmp(result, test->str)) {
	    printf("decoding error '%s' should be '%s'\n",
		   result, test->str);
	} else {
	    printf("Ok\n");
	}
    }

    for (i = 0; i < NUM_VECS; i++) {
	struct test_vec *test = &base32_test[i];

	printf("Base32 encoding %s: ", test->str);
	memset(result, 0, sizeof(result));
	ret = base32_encode((unsigned char *)test->str,
			    strlen(test->str), result);
	if (ret < 0) {
	    printf("error %d\n", ret);
	} else if (strcmp(result, test->res)) {
	    printf("encoding error '%s' should be '%s'\n",
		   result, test->res);
	} else {
	    printf("Ok\n");
	}
    }

    for (i = 0; i < NUM_VECS; i++) {
	struct test_vec *test = &base32_test[i];

	printf("Base32 decoding %s: ", test->res);
	memset(result, 0, sizeof(result));
	ret = base32_decode(test->res, strlen(test->res),
			    (unsigned char*)result);
	if (ret < 0) {
	    printf("error %d\n", ret);
	} else if (strcmp(result, test->str)) {
	    printf("encoding error '%s' should be '%s'\n",
		   result, test->str);
	} else {
	    printf("Ok\n");
	}
    }
}
