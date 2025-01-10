#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

static int etcd_connect(void)
{
	const char *hostname = "localhost";
	const char *port = "2379";
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
		if (connect(sockfd, aip->ai_addr, ai->ai_addrlen) == 0) {
			printf("connected\n");
			break;
		}
		printf("connection failed, error %d\n", errno);
		close(sockfd);
		sockfd = -ENOTCONN;
	}

	freeaddrinfo(ai);

	return sockfd;
}

const char http_header[] =
	"POST /v3/watch HTTP/1.1\r\n"
	"Host: localhost:2379\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/json\r\n"
	"Content-Length: 113\r\n\r\n";

const char http_post_watch[] =
	"{ \"create_request\": "
	"{ \"key\": \"bm9mdXNlL3BvcnRz\", "
	"\"range_end\": \"bm9mdXNlL3BvcnR0\", "
	"\"watch_id\": 140095673849537 } }";

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
		printf("read %d bytes (%ld total)\n%s\n",
		       ret, result_size + ret, data_ptr);
		data_left -= ret;
		data_ptr += ret;
		result_size += ret;
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

int main(int argc, char **argv)
{
	int sockfd, flags, ret;
	size_t buflen;
	char *buf;

	sockfd = etcd_connect();
	if (sockfd < 0)
		return 1;

	flags = fcntl(sockfd, F_GETFL);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	printf("sending http header (%ld bytes)\n",
	       strlen(http_header));
	ret = send_http(sockfd, http_header, strlen(http_header));
	if (ret != 0) {
		printf("error sending http header, %d bytes left\n", ret);
		close(sockfd);
		return 1;
	}
	printf("sending http post (%ld bytes)\n",
	       strlen(http_post_watch));
	ret = send_http(sockfd, http_post_watch, strlen(http_post_watch));
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
