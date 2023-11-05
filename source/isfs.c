#include <stdlib.h>
#include <errno.h>
#include <gccore.h>
#include <ogc/isfs.h>

#include "misc.h"

static fstats file_stats ATTRIBUTE_ALIGN(0x20);

int FS_Read(const char* filepath, unsigned char** buffer, size_t* filesize) {
	if (((uintptr_t)*buffer) % 0x20 || (*buffer && !*filesize)) return -EINVAL;

	int ret = ISFS_Open(filepath, ISFS_OPEN_READ);
	if (ret < 0) return ret;
	int fd = ret;

	if(! *filesize) {
		ret = ISFS_GetFileStats(fd, &file_stats);
		if(ret < 0) return ret;
		*filesize = file_stats.file_length;
	}
	if (!*buffer) *buffer = memalign(0x20, *filesize);
	if (!*buffer) return ENOMEM;

	ret = ISFS_Read(fd, *buffer, *filesize);
	ISFS_Close(fd);

	if(ret < *filesize) {
		free(*buffer);
		*buffer = NULL;
		if (ret > 0) return -EIO;
        else return ret;
	}

	return 0;
}
