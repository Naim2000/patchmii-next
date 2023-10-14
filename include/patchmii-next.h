// typedef int (*content_patcher)(unsigned int cid, void* buffer, size_t length);
int PatchMii_Install(const uint64_t tid, int version, const uint64_t tid_new, uint32_t ios_new /*, content_patcher content_cb */);
