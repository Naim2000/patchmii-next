#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <network.h>

#include "tcp.h"
#include "misc.h"

#define CRLF "\r\n"

int HTTP_request(const char* hostname, const char* path, void** buffer, size_t* size) {
	int ret, status, socket;

	ret = TCP_connect(hostname, 80);
	if (ret < 0) return ret;
	socket = ret;

	char request_header[0x180];
	ret = TCP_write(socket, request_header, sprintf(request_header,
			"GET %s HTTP/1.1" CRLF
			"Host: %s" CRLF CRLF,
			path, hostname));
	if (ret < 0) goto finish;

	for (int i = 0; i < 32; i++) { // NOTE: why 32 lines
		char line[0x80] = {};
		ret = TCP_readln(socket, line, sizeof(line));
		if (ret < 0)
			status = 408;

		if (ret <= 0)
			break;

	//	debug_log("TCP_readln gave me %s", line);
		if (sscanf(line, "HTTP/1.%*u %u", &status))
			debug_log("Read status code: %u", status);

		else if (sscanf(line, "Content-Length: %u", size))
			debug_log("Read content length: %u", *size);
	}

	if (status != 200) {
		ret = -status;
		goto finish;
	}

	*buffer = memalign(0x20, *size);
	if (!*buffer) {
		ret = -ENOMEM;
		goto finish;
	}

	ret = TCP_read(socket, *buffer, *size);

	if (ret < 0) {
		free(*buffer);
		*buffer = NULL;
	}

finish:
	net_close(socket);
	return ret;
}
