#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <ogc/es.h>
#include <ogc/isfs.h>

#include "quickhttp.h"
#include "aes.h"
#include "isfs_shenanigans.h"
#include "misc.h"

#define NUS_SERVER "ccs.cdn.shop.wii.com"

typedef const uint64_t tid_t;

const aeskey wii_ckey = {0xEB, 0xE4, 0x2A, 0x22, 0x5E, 0x85, 0x93, 0xE4, 0x48, 0xD9, 0xC5, 0x45, 0x73, 0x81, 0xAA, 0xF7};

void* NUS_Download(tid_t tid, const char* obj, unsigned int* size) {
	char path[80];
	sprintf(path, "/ccs/download/%016llx/%s", tid, obj);

	struct HTTP_response res = HTTP_request(NUS_SERVER, path);
	if (res.status != 200)
		errno = res.status;
	else
		errno = 0;

	*size = res.len;
	return res.buffer;
}
/*
inline void get_titlekey(tik* ticket, aeskey out) {
	struct AES_ctx aes = {};
	aeskey iv = {};

	memcpy(out, ticket->cipher_title_key, sizeof(aeskey));
	error_log("cipher tkey: %016llx%016llx", *(uint64_t*) out, *((uint64_t*) out + 1));
	*(uint64_t*) iv = ticket->titleid;

	AES_init_ctx_iv(&aes, wii_ckey, iv);
	AES_CBC_decrypt_buffer(&aes, out, sizeof(aeskey));
	error_log("deciph tkey: %016llx%016llx", *(uint64_t*) out, *((uint64_t*) out + 1));
}

inline void change_tid(tmd* tmd, tik* ticket, tid_t tid_new) {
	struct AES_ctx aes = {};
	aeskey iv = {}, title_key = {};

	get_titlekey(ticket, title_key);
	ticket->titleid = tid_new;
	*(uint64_t*)iv = tid_new;

	AES_init_ctx_iv(&aes, wii_ckey, iv);
	AES_CBC_encrypt_buffer(&aes, title_key, sizeof(aeskey));
	error_log("cipher tkey: %016llx%016llx", *(uint64_t*) title_key, *((uint64_t*) title_key + 1));
	memcpy(ticket->cipher_title_key, title_key, sizeof(aeskey));

	tmd->title_id = tid_new;
}
*/
int purge_title(tid_t tid) {
	int ret = 0;
	unsigned int viewcnt = 0;

	ret = ES_GetNumTicketViews(tid, &viewcnt);
	if (!viewcnt) return ret ? ret : ENOENT;

	tikview
		view ATTRIBUTE_ALIGN(0x20) = {},
		views[viewcnt] ATTRIBUTE_ALIGN(0x20) = {};

	ret = ES_GetTicketViews(tid, views, viewcnt);
	if (ret < 0) return ret;
	for (int i = 0; i < viewcnt; i++) {
		memcpy(&view, views + i, sizeof(tikview));
		ret = ES_DeleteTicket(&view);
		if (ret < 0) return ret;
	}

	ES_DeleteTitleContent(tid);
	return ES_DeleteTitle(tid);
}

int PatchMii_Install(tid_t tid, int version, tid_t tid_new, uint32_t ios_new) {
	int ret = 0;
	char obj[10];
	unsigned int certs_size = 0, tmd_size = 0, tik_size = 0;
	struct _tmd* p_tmd = NULL;
	struct _tik* p_tik = NULL;

	error_log("(%016llx, %d, %016llx, %08x)", tid, version, tid_new, ios_new);

	void* certs = FS_Read("/sys/cert.sys", &certs_size);
	if (!certs) return errno;

	if (version > 0)
		sprintf(obj, "tmd.%hu", version);
	else
		sprintf(obj, "tmd");

	signed_blob* s_tmd = NUS_Download(tid, obj, &tmd_size);
	if (!s_tmd) return errno;
	p_tmd = SIGNATURE_PAYLOAD(s_tmd);

	sprintf(obj, "cetk");
	signed_blob* s_tik = NUS_Download(tid, obj, &tik_size);
	if (!s_tik) return errno;
	p_tik = SIGNATURE_PAYLOAD(s_tik);

	if (tid_new) {
		struct AES_ctx tkey = {};
		aeskey title_key = {}, iv = {};
		memcpy(title_key, p_tik->cipher_title_key, sizeof(aeskey));
		*(uint64_t*)iv = p_tik->titleid;

		AES_init_ctx_iv(&tkey, wii_ckey, iv);
		AES_CBC_decrypt_buffer(&tkey, title_key, sizeof(aeskey));

		p_tik->titleid = tid_new;
		p_tmd->title_id = tid_new;
		*(uint64_t*)iv = tid_new;

		AES_ctx_set_iv(&tkey, iv);
		AES_CBC_encrypt_buffer(&tkey, title_key, sizeof(aeskey));

		memcpy(p_tik->cipher_title_key, title_key, sizeof(aeskey));

	}
	if (ios_new)
		p_tmd->sys_version = 1LL<<32 | ios_new;

	error_log("purging title");
	ret = purge_title(tid_new ? tid_new : tid);
	if (ret < 0) return ret;

	error_log("installing ticket");
	ret = ES_AddTicket(s_tik, STD_SIGNED_TIK_SIZE, certs, certs_size, NULL, 0);
	if (ret < 0) return ret;

	error_log("installing tmd");
	ret = ES_AddTitleStart(s_tmd, SIGNED_TMD_SIZE(s_tmd), certs, certs_size, NULL, 0);
	if (ret < 0) return ret;

	for (int i = 0; i < p_tmd->num_contents; i++) {
		struct _tmd_content* content = p_tmd->contents + i;
		unsigned int cid = content->cid, _csize = 0;

		sprintf(obj, "%08x", cid);
		error_log("downloading content #%02d", cid);
		unsigned char* buffer = NUS_Download(tid, obj, &_csize);
		if (!buffer) {
			ES_AddTitleCancel();
			return errno;
		}

		ret = ES_AddContentStart(p_tmd->title_id, cid);
		if (ret < 0) {
			ES_AddTitleCancel();
			free(buffer);
			return ret;
		}
		int cfd = ret;

		ES_AddContentData(cfd, buffer, _csize);
		ret = ES_AddContentFinish(cfd);
		free(buffer);
		if (ret < 0) {
			ES_AddTitleCancel();
			return ret;
		}
	}

	error_log("finishing...");
	ret = ES_AddTitleFinish();
	if (ret < 0) ES_AddTitleCancel();
	return ret;
}
