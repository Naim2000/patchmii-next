#include "tcp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ogc/lwp_watchdog.h>
#include <network.h>
#include <fcntl.h>

#include "misc.h"
#include "timeout.h"

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

	ret = net_fcntl(socket, F_SETFL, ret | 0x4);
	if (ret < 0) {
		error_log("net_fcntl(F_SETFL) failed (%d)", ret);
		net_close(socket);
		return ret;
	}

	return socket;
}

int TCP_connect(const char* hostname, uint16_t port) {
	int ret = 0;
	struct hostent* host = NULL;
	static struct hostent cached_host = {};
	static const char* last_hostname = NULL;

	if (last_hostname && (hostname == last_hostname || !strcmp(hostname, last_hostname))) host = &cached_host;
	else {
		host = net_gethostbyname(hostname);
		if (!host) {
			error_log("net_gethostbyname(%s) failed\n\"%s\"", hostname, strerror(errno));
			return -errno;
		}
		last_hostname = hostname;
		cached_host = *host;
	}


	int socket = TCP_socket();
	if (socket < 0) return socket;

	struct sockaddr_in sockaddr = {
		sizeof(sockaddr), PF_INET, htons(port),
		{ *(uint32_t*)(host->h_addr_list[0]) }
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
