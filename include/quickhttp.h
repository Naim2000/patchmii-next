#include <stdint.h>
#include <stddef.h>

struct HTTP_response {
	unsigned int status;
	void* buffer;
	unsigned int len;
};

int TCP_socket();
int TCP_connect(const char*, uint16_t);
int TCP_readln(int, char*, size_t);
int TCP_read(int, void*, size_t);
int TCP_write(int, void*, size_t);

struct HTTP_response HTTP_request(const char*, const char*);
