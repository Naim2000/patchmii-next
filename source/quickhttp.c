#include "quickhttp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ogc/lwp_watchdog.h>
#include <fcntl.h>
#include <network.h>

#include "timeout.h"
#include "misc.h"

#define CRLF "\r\n"
#define TCP_BLOCKSIZE 0x800

int TCP_socket() {
	int ret;

	int socket = net_socket(PF_INET, SOCK_STREAM, 0);
	if (socket < 0) {
		error_log("net_socket failed (%d)", socket);
		return socket;
	}

	ret = net_fcntl(socket, F_GETFL, 0);
	if (ret < 0) {
		error_log("net_fcntl(F_GETFL) failed (%d)", ret);
		net_close(socket);
		return ret;
	}

	ret = net_fcntl(socket, F_SETFL, 0x4);
	if (ret < 0) {
		error_log("net_fcntl(F_SETFL) failed (%d)", ret);
		net_close(socket);
		return ret;
	}

	return socket;
}

int TCP_connect(const char* hostname, uint16_t port) {
	int ret = 0;

	struct hostent* host = net_gethostbyname(hostname);
	if (!host) {
		error_log("couldn't find out who %s is (errno=%d)", hostname, errno);
		return errno;
	}

	int socket = TCP_socket();
	if (socket < 0) return socket;

	struct sockaddr_in sockaddr = {
		.sin_family = PF_INET,
		.sin_len = sizeof(sockaddr),
		.sin_port = htons(port),
		.sin_addr = {
			.s_addr = *(uint32_t*)(host->h_addr_list[0])
		}
	};

	set_timeout(10);
	while (true) {
		if (timedout()) {
			error_log("net_connect took too long...");
			net_close(socket);
			return -ETIMEDOUT;
		}

		ret = net_connect(socket, (struct sockaddr*)&sockaddr, sizeof(sockaddr));

		if (!ret || ret == -EISCONN) break;
		else if (ret == -EINPROGRESS || ret == -EALREADY) {
			debug_log("hurry up net_connect...");
			sleep(1);
			continue;
		}
		else {
			error_log("net_connect failed (%d)", ret);
			net_close(socket);
			return ret;
		}
	}

	return socket;
}

int TCP_readln(int socket, char* buffer, size_t maxlen) {
	size_t c = 0;

	set_timeout(10);
	while (c < maxlen) {
		if (timedout()) {
			error_log("took too long...");
			return -ETIMEDOUT;
		}
		int ret = net_read(socket, buffer + c, 1);

		if (!ret || ret == -EAGAIN) {
			debug_log("going again...");
			sleep(1);
			continue;
		}
		else if (ret < 0) {
			error_log("net_read failed (%d)", ret);
			return ret;
		}

		if(buffer[c] == '\n') {
			buffer[c] = 0x00;
			return c <= 1 ? 0 : c;
		}
		c++;
	}

	return -EFBIG;
}

int TCP_read(int socket, void* buffer, size_t length) {
	size_t total = 0;
	int chunk = 0;

	set_timeout(10);
	while (total < length) {
		if(timedout()) {
			error_log("took too long (%u/%u)", total, length);
			return -ETIMEDOUT;
		}

		int ret = net_read(socket, buffer + total, MAXIMUM(TCP_BLOCKSIZE, length - total));
		if (!ret || ret == -EAGAIN) {
			debug_log("going again...");
			sleep(1);
			continue;
		}
		else if (ret < 0) {
			error_log("net_read failed (%d)", ret);
			return ret;
		}
		total += ret;

		if((total / TCP_BLOCKSIZE) > chunk) {
			set_timeout(10);
			chunk++;
		}
	}

	return 0;
}

int TCP_write(int socket, void* buffer, size_t length) {
	size_t total = 0;
	int chunk = 0;

	set_timeout(10);
	while (total < length) {
		if((total / TCP_BLOCKSIZE) > chunk) {
			set_timeout(10);
			chunk++;
		}

		if(timedout()) {
			error_log("took too long (%u/%u)", total, length);
			return -ETIMEDOUT;
		}

		int ret = net_write(socket, buffer + total, MAXIMUM(TCP_BLOCKSIZE, length - total));
		if (!ret || ret == -EAGAIN) {
			debug_log("going again...");
			sleep(1);
			continue;
		}
		else if (ret < 0) {
			error_log("net_write failed (%d)", ret);
			return ret;
		}
		total += ret;
	}

	return 0;
}

struct HTTP_response HTTP_request(const char* hostname, const char* path) {
	int ret = 0;
	struct HTTP_response res = {
		.status		= 404,
		.buffer		= NULL,
		.len 		= 0
	};

	ret = TCP_connect(hostname, 80);
	if (ret < 0) {
		error_log("TCP_connect failed (%d)", ret);
		return res;
	}
	int socket = ret;

	char request_header[0x200] = {};
	int len = sprintf(request_header,
			"GET %s HTTP/1.1" CRLF
			"Host: %s" CRLF
			"Cache-Control: no-cache" CRLF CRLF,
			path, hostname);

	ret = TCP_write(socket, request_header, len);
	if (ret < 0) {
		error_log("TCP_write failed (%d)", ret);
		return res;
	}

	for (int i = 0; i < 0x20; i++) { // TODO: why 32 lines
		char line[0x80] = {};
		ret = TCP_readln(socket, line, sizeof(line));
		if (ret < 0)
			res.status = 408;

		if (ret <= 0)
			break;

		debug_log("TCP_readln gave me %s", line);
		if (sscanf(line, "HTTP/1.%*u %u", &res.status))
			debug_log("Read status code: %u", res.status);

		else if (sscanf(line, "Content-Length: %u", &res.len))
			debug_log("Read content length: %u", res.len);
	}

	if (res.status == 200) {
		res.buffer = memalign(0x20, res.len);
		if (res.buffer) {
			ret = TCP_read(socket, res.buffer, res.len);
			if (ret < 0) {
				free(res.buffer);
				res.buffer = NULL;
				res.status = ret;
			}
		}
		else res.status = 413;
	}

	net_close(socket);
	return res;
}
