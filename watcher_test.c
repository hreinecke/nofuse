#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <json-c/json.h>

#include "base64.h"

static char *default_hostname = "localhost";
static char *default_port = "2379";

static char *__b64enc(const char *str, int str_len)
{
	int encoded_size = (str_len * 2) + 2, len;
	char *encoded_str = malloc(encoded_size + 1);

	if (!encoded_str)
		return NULL;
	memset(encoded_str, 0, encoded_size);
	len = base64_encode((unsigned char *)str, str_len, encoded_str);
	encoded_str[len] = '\0';
	return encoded_str;
}

static char *__b64dec(const char *encoded_str)
{
	int encoded_size = strlen(encoded_str), len;
	char *str = malloc(encoded_size + 1);

	if (!str)
		return NULL;

	memset(str, 0, encoded_size);
	len = base64_decode(encoded_str, encoded_size, (unsigned char *)str);
	str[len] = '\0';
	return str;
}

static int etcd_connect(char *hostname, char *port)
{
	struct addrinfo hints, *ai, *aip;
	int sockfd = -1, ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(hostname, port, &hints, &ai);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() on %s:%s failed: %s\n",
			hostname, port, gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		fprintf(stderr, "no results from getaddrinfo()\n");
		return -EHOSTUNREACH;
	}

	for (aip = ai; aip != NULL; aip = aip->ai_next) {
		sockfd = socket(aip->ai_family, aip->ai_socktype,
				aip->ai_protocol);
		if (sockfd < 0) {
			fprintf(stderr, "socket error %d\n", errno);
			continue;
		}
		if (connect(sockfd, aip->ai_addr, aip->ai_addrlen) == 0) {
			const char *fam = "IPv4";

			if (aip->ai_family == AF_INET6)
				fam = "IPv6";

			printf("connected to %s:%s with %s\n",
			       hostname, port, fam);
			break;
		}
		close(sockfd);
		sockfd = -ENOTCONN;
	}

	freeaddrinfo(ai);

	return sockfd;
}

char *format_watch(char *key, int64_t revision, int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	char *encoded_key, end, *end_key, *encoded_end;
	const char *tmp;
	char *buf;

	post_obj = json_object_new_object();
	req_obj = json_object_new_object();
	encoded_key = __b64enc(key, strlen(key));
	json_object_object_add(req_obj, "key",
			       json_object_new_string(encoded_key));
	end_key = strdup(key);
	end = end_key[strlen(end_key) - 1];
	end++;
	end_key[strlen(end_key) - 1] = end;
	encoded_end = __b64enc(end_key, strlen(end_key));
	json_object_object_add(req_obj, "range_end",
			       json_object_new_string(encoded_end));
	if (revision > 0)
		json_object_object_add(req_obj, "start_revision",
				       json_object_new_int64(revision));
	if (watch_id > 0)
		json_object_object_add(req_obj, "watch_id",
				       json_object_new_int64(watch_id));
	json_object_object_add(post_obj, "create_request", req_obj);

	tmp = json_object_to_json_string_ext(post_obj,
					     JSON_C_TO_STRING_PRETTY);

	buf = strdup(tmp);
	json_object_put(post_obj);
	free(end_key);
	return buf;
}

const char http_post_cancel[] =
	"{ \"cancel_request\": "
	"\"watch_id\": 140095673849536 } }";

int send_http(int sockfd, const char *data, size_t data_len)
{
	const char *data_ptr;
	size_t data_left, len;

	data_ptr = data;
	data_left = data_len;
	while (data_left) {
		len = write(sockfd, data_ptr, data_left);
		if (len < 0) {
			fprintf(stderr, "error %d sending http header\n",
				errno);
			break;
		}
		if (len == 0) {
			fprintf(stderr,
				"connection closed, %ld bytes pending\n",
				data_left);
			break;
		}
		data_left -= len;
		data_ptr += len;
	}
	return data_left;
}

int parse_http(char *buf, size_t len)
{
	printf("data: %s\n", buf);
	return 0;
}

int recv_http(int sockfd, char **data, size_t *data_len)
{
	size_t result_inc = 512, result_size, data_left;
	char *result, *data_ptr;
	int ret;

	result_size = 0;
	result = malloc(result_inc);
	if (!result)
		return -ENOMEM;
	data_ptr = result;
	data_left = result_inc;
	memset(data_ptr, 0, data_left);

	while (sockfd > 0) {
		fd_set rfd;
		struct timeval tmo;
		char *tmp;

		FD_ZERO(&rfd);
		FD_SET(sockfd, &rfd);
		tmo.tv_sec = 1;
		tmo.tv_usec = 0;
		ret = select(sockfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			fprintf(stderr, "select error %d\n", errno);
			break;
		}
		if (!FD_ISSET(sockfd, &rfd)) {
			printf("no events, continue\n");
			continue;
		}
		ret = read(sockfd, data_ptr, data_left);
		if (ret < 0) {
			fprintf(stderr,
				"error %d during read, %ld bytes read\n",
				errno, result_size);
			ret = -errno;
			break;
		}
		if (ret == 0) {
			fprintf(stderr,
				"socket closed during read, %ld bytes read\n",
				result_size);
			break;
		}
		result_size += ret;
		if (parse_http(result, result_size) == 0) {
			memset(result, 0, result_size);
			data_ptr = result;
			data_left = result_size;
			result_size = 0;
			continue;
		}
		printf("read %d bytes (%ld total)\n",
		       ret, result_size + ret);
		data_left -= ret;
		data_ptr += ret;
		if (data_left)
			continue;

		printf("expand buffer, %ld bytes read\n", result_size);
		tmp = result;
		result = malloc(result_size + result_inc);
		if (!result) {
			fprintf(stderr,
				"failed to reallocate result\n");
			break;
		}
		memcpy(result, tmp, result_size);
		data_ptr = result + result_size;
		data_left = result_inc;
		memset(data_ptr, 0, data_left);
		free(tmp);
	}
	*data = result;
	*data_len = result_size;
	return ret;
}

char *http_header =
	"POST /v3/watch HTTP/1.1\r\n"
	"Host: %s:%s\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/json\r\n"
	"Content-Length: %d\r\n\r\n";

int main(int argc, char **argv)
{
	int sockfd, flags, ret, hdrlen;
	size_t buflen, postlen;
	char *hdr, *buf, *post;

	sockfd = etcd_connect(default_hostname, default_port);
	if (sockfd < 0)
		return 1;

	flags = fcntl(sockfd, F_GETFL);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	post = format_watch("nofuse/ports", 0, 0);
	postlen = strlen(post);

	hdrlen = asprintf(&hdr, http_header,
		       default_hostname, default_port,
		       postlen);
	if (hdrlen < 0)
		return 1;

	printf("sending http header (%d bytes)\n", hdrlen);
	ret = send_http(sockfd, hdr, hdrlen);
	free(hdr);
	if (ret != 0) {
		printf("error sending http header, %d bytes left\n", ret);
		close(sockfd);
		return 1;
	}
	printf("sending http post (%ld bytes)\n", postlen);
	ret = send_http(sockfd, post, postlen);
	if (ret != 0) {
		printf("error sending http post, %d bytes left\n", ret);
		close(sockfd);
		return 1;
	}
	ret = recv_http(sockfd, &buf, &buflen);
	close(sockfd);
	if (buflen) {
		printf("received data '%s'\n", buf);
		free(buf);
	}
	return 0;
}
