
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <limits.h>
#include <netdb.h>
#include <errno.h>

#include <json-c/json.h>

#include "base64.h"

struct http_parser {
	char *hdr;
	int code;
	bool chunked;
	size_t size;
};

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
	free(encoded_key);
	free(encoded_end);
	free(end_key);
	return buf;
}

char *format_cancel(int64_t watch_id)
{
	json_object *post_obj, *req_obj;
	const char *tmp;
	char *buf;

	post_obj = json_object_new_object();
	req_obj = json_object_new_object();
	if (watch_id > 0)
		json_object_object_add(req_obj, "watch_id",
				       json_object_new_int64(watch_id));
	json_object_object_add(post_obj, "cancel_request", req_obj);

	tmp = json_object_to_json_string_ext(post_obj,
					     JSON_C_TO_STRING_PRETTY);

	buf = strdup(tmp);
	json_object_put(post_obj);
	return buf;
}

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

char *http_header =
	"POST /v3/watch HTTP/1.1\r\n"
	"Host: %s:%s\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/json\r\n"
	"Content-Length: %d\r\n\r\n";

int send_cancel(int sockfd, int64_t watch_id)
{
	char *hdr, *post;
	size_t postlen;
	int hdrlen, ret;

	post = format_cancel(watch_id);
	postlen = strlen(post);

	hdrlen = asprintf(&hdr, http_header,
		       default_hostname, default_port,
		       postlen);
	if (hdrlen < 0) {
		free(post);
		return -ENOMEM;
	}

	printf("http header (%d bytes)\n", hdrlen);
	ret = send_http(sockfd, hdr, hdrlen);
	free(hdr);
	if (ret != 0) {
		printf("error sending http header, %d bytes left\n", ret);
		free(post);
		return -errno;
	}
	printf("http post (%ld bytes)\n%s\n", postlen, post);
	ret = send_http(sockfd, post, postlen);
	free(post);
	if (ret != 0) {
		printf("error sending http post, %d bytes left\n", ret);
		return -errno;
	}
	return 0;
}

int parse_http_hdr(struct http_parser *http)
{
	if (sscanf(http->hdr, "HTTP/1.1 %03d %*s", &http->code) != 1) {
		fprintf(stderr, "invalid http header %s\n", http->hdr);
		return -EINVAL;
	}
	if (http->code != 200) {
		fprintf(stderr, "http code %d\n", http->code);
	}
	if (strstr(http->hdr, "Transfer-Encoding: chunked")) {
		http->chunked = true;
		printf("http code %d, chunked\n", http->code);
	} else {
		char *opt = strstr(http->hdr, "Content-Length:");
		if (opt) {
			char *end = strstr(opt, "\r\n");
			if (end)
				memset(end, 0, 4);
			if (sscanf(opt, "Content-Length: %ld",
				   &http->size) != 1) {
				printf("invalid hdr %s\n", opt);
			}
		}
		http->chunked = false;
		printf("http code %d, len %ld\n", http->code, http->size);
	}
	return 0;
}

int parse_http_chunk(char *buf, size_t *chunk_len)
{
	char *ptr, *eptr = NULL;
	unsigned long len;

	ptr = strstr(buf, "\r\n");
	if (!ptr) {
		fprintf(stderr, "http chunked data parsing error\n");
		return 0;
	}
	memset(ptr, 0, 2);
	if (ptr == buf) {
		*chunk_len = 0;
		return 0;
	}
	len = strtoul(buf, &eptr, 16);
	if (len == ULONG_MAX || buf == eptr) {
		fprintf(stderr, "http chunked data decoding error\n");
		return -EINVAL;
	}
	*chunk_len = len;
	return strlen(buf) + 2;
}

int parse_http_body(struct http_parser *http, char *body, size_t len)
{
	json_object *etcd_resp, *result_obj, *rev_obj, *header_obj, *event_obj;
	int num_kvs, i;
	char *key, *value;

	etcd_resp = json_tokener_parse(body);
	if (!etcd_resp) {
		printf("%s: invalid response\n'%s'\n",
		       __func__, body);
		return -EBADMSG;
	}

	printf("http data (%ld bytes)\n%s\n", len,
	       json_object_to_json_string_ext(etcd_resp,
					      JSON_C_TO_STRING_PRETTY));

	result_obj = json_object_object_get(etcd_resp, "result");
	if (!result_obj) {
		printf("%s: invalid response, 'result' not found\n",
		       __func__);
		goto out;
	}

	header_obj = json_object_object_get(result_obj, "header");
	if (!header_obj) {
		printf("%s: invalid response, 'header' not found\n",
		       __func__);
		goto out;
	}
	rev_obj = json_object_object_get(header_obj, "revision");
	if (rev_obj) {
		int64_t revision = json_object_get_int64(rev_obj);

		printf("%s: new revision %ld\n",
		       __func__, revision);
	}

	/* 'created' set in response to a 'WatchRequest', no data is pending */
	if (json_object_object_get(result_obj, "created"))
		goto out;

	event_obj = json_object_object_get(result_obj, "events");
	if (!event_obj) {
		printf("%s: invalid response, 'events' not found\n",
		       __func__);
		goto out;
	}

	num_kvs = json_object_array_length(event_obj);
	for (i = 0; i < num_kvs; i++) {
		struct json_object *kvs_obj, *kv_obj, *key_obj;
		struct json_object *type_obj, *value_obj;
		bool deleted = false;

		kvs_obj = json_object_array_get_idx(event_obj, i);
		type_obj = json_object_object_get(kvs_obj, "type");
		if (type_obj &&
		    strcmp(json_object_get_string(type_obj), "DELETE"))
			deleted = true;
		kv_obj = json_object_object_get(kvs_obj, "kv");
		if (!kv_obj)
			continue;
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj)
			continue;
		key = __b64dec(json_object_get_string(key_obj));
		value_obj = json_object_object_get(kv_obj, "value");
		if (!value_obj) {
			if (deleted)
				printf("key %s: deleted\n", key);
			else
				printf("key %s: <none>\n", key);
		} else {
			value = __b64dec(json_object_get_string(value_obj));
			printf("key %s: value '%s;\n", key, value);
		}
	}
out:
	json_object_put(etcd_resp);
	return 0;
}

int parse_http(struct http_parser *http, char *result, size_t result_size)
{
	char *body;
	size_t parsed = 0;
	int ret;

	printf("http raw hdr: %s\n", result);
	if (!http->hdr) {
		body = strstr(result, "\r\n\r\n");
		if (!body) {
			printf("http hdr retry\n");
			return 0;
		}
		memset(body, 0, 4);
		body += 4;
		http->hdr = strdup(result);
		ret = parse_http_hdr(http);
		if (ret < 0) {
			printf("http hdr parse error\n");
			return ret;
		}
		parsed = strlen(result) - strlen(body);
		result_size -= parsed;
		result = body;
		if (!result_size)
			return parsed;
	}
	printf("http (parsed %ld) raw body: %s\n", parsed, result);
	do {
		size_t chunk_len;
		char *next_chunk;

		if (http->chunked) {
			ret = parse_http_chunk(result, &chunk_len);
			if (ret < 0)
				return ret;
			printf("http chunk (%ld bytes of %ld bytes)\n",
			       chunk_len, result_size);
			result += ret;
			parsed += ret;
			result_size -= ret;
		} else {
			chunk_len = http->size;
		}
		printf("http raw chunk: %s\n", result);
		if (result_size < chunk_len) {
			printf("http chunk incomplete, parsed %ld bytes\n",
				parsed);
			return parsed;
		}
		if (strcmp(result + chunk_len, "\r\n")) {
			printf("http chunk parse error\n");
			ret = -EINVAL;
			break;
		}
		next_chunk = result + chunk_len;
		memset(next_chunk, 0, 2);
		if (!chunk_len) {
			parsed += 2;
			ret = 0;
			break;
		}
		next_chunk += 2;
		ret = parse_http_body(http, result, chunk_len);
		if (!ret) {
			printf("http chunk retry\n");
			return 0;
		}
		result = next_chunk;
		result_size -= chunk_len + 2;
		parsed += chunk_len + 2;
	} while (result_size);

	if (result_size) {
		printf("http parsing stopped, %ld/%ld bytes parsed\n",
		       parsed, result_size);
	} else {
		printf("http response complete, %ld bytes parsed\n",
			parsed);
		free(http->hdr);
		http->hdr = NULL;
	}
	return parsed;
}
	
int recv_http(int sockfd, struct http_parser *http)
{
	size_t alloc_size, result_inc = 64, result_size, data_left, len;
	char *result, *data_ptr;
	int ret, wait = 5;

	alloc_size = result_inc;
	result_size = 0;
	result = malloc(alloc_size);
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
			if (!--wait) {
				send_cancel(sockfd, 17);
				wait = 5;
			} else
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
		len = ret;
		result_size += len;
		data_ptr += len;
		data_left -= len;
		ret = parse_http(http, result, result_size);
		if (ret < 0) {
			fprintf(stderr, "http parse error %d\n", ret);
			break;
		}
		if (ret > 0) {
			int rem = result_size - ret;
			/* advance stream */
			printf("advance by %d bytes (%ld total)\n",
			       ret, result_size);
			tmp = result + ret;
			memmove(result, tmp, rem);
			data_left = alloc_size - rem;
			data_ptr = result + rem;
			memset(data_ptr, 0, data_left);
			printf("result %s\n", result);
			continue;
		}

		printf("read %ld bytes (%ld total)\n",
		       len, result_size);
		if (data_left)
			continue;
		printf("expand buffer, %ld bytes read\n", result_size);
		alloc_size += result_inc;
		tmp = realloc(result, alloc_size);
		if (!tmp) {
			fprintf(stderr,
				"failed to reallocate result\n");
			break;
		}
		result = tmp;
		data_ptr = result + result_size;
		data_left = result_inc;
		memset(data_ptr, 0, data_left);
	}
	free(result);
	return ret;
}

int main(int argc, char **argv)
{
	int sockfd, flags, ret, hdrlen;
	size_t postlen;
	char *hdr, *post;
	struct http_parser http;

	sockfd = etcd_connect(default_hostname, default_port);
	if (sockfd < 0)
		return 1;

	flags = fcntl(sockfd, F_GETFL);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	post = format_watch("nofuse/ports", 0, 17);
	postlen = strlen(post);

	hdrlen = asprintf(&hdr, http_header,
		       default_hostname, default_port,
		       postlen);
	if (hdrlen < 0) {
		free(post);
		return 1;
	}

	printf("sending http header (%d bytes)\n", hdrlen);
	ret = send_http(sockfd, hdr, hdrlen);
	free(hdr);
	if (ret != 0) {
		printf("error sending http header, %d bytes left\n", ret);
		free(post);
		close(sockfd);
		return 1;
	}
	printf("http post (%ld bytes)\n%s\n", postlen, post);
	ret = send_http(sockfd, post, postlen);
	free(post);
	if (ret != 0) {
		printf("error sending http post, %d bytes left\n", ret);
		close(sockfd);
		return 1;
	}
	http.hdr = NULL;
	http.chunked = false;
	ret = recv_http(sockfd, &http);
	close(sockfd);
	return 0;
}
