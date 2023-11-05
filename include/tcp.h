#include <stdint.h>
#include <stddef.h>

int TCP_socket();
int TCP_connect(const char*, uint16_t);
int TCP_readln(int, char*, size_t);
int TCP_read(int, void*, size_t);
int TCP_write(int, void*, size_t);
