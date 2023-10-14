#include <stdlib.h>
#include <errno.h>
#include <gccore.h>
#include <ogc/isfs.h>

extern void* memalign(size_t, size_t);

static fstats file_stats ATTRIBUTE_ALIGN(0x20);

void* FS_Read(const char* filepath, unsigned int* filesize) {
    int ret = 0;

	ret = ISFS_Open(filepath, ISFS_OPEN_READ);
	if (ret < 0) {
        errno = ret;
        return NULL;
    }
	int fd = ret;

	if(! *filesize) {
		ret = ISFS_GetFileStats(fd, &file_stats);
		if(ret < 0) {
            errno = ret;
            return NULL;
        }
		*filesize = file_stats.file_length;
	}
	unsigned char *buffer = memalign(0x20, *filesize);
	if(!buffer) {
		errno = -ENOMEM;
		return buffer;
	}

	ret = ISFS_Read(fd, buffer, *filesize);
	if(ret < *filesize) {
		free(buffer);
		buffer = NULL;
		if(ret > 0) errno = -EIO;
        else errno = ret;
	}

	ISFS_Close(fd);
	return buffer;
}
