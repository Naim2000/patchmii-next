#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <gctypes.h>
#include <ogc/es.h>
#include <ogc/isfs.h>

#include "http.h"
#include "aes.h"
#include "sha1.c"
#include "isfs.h"
#include "misc.h"

#define NUS_SERVER "ccs.cdn.shop.wii.com"

const aeskey wii_ckey = {0xEB, 0xE4, 0x2A, 0x22, 0x5E, 0x85, 0x93, 0xE4, 0x48, 0xD9, 0xC5, 0x45, 0x73, 0x81, 0xAA, 0xF7};

int NUS_Download(u64 tid, const char* obj, void** buffer, size_t* size) {
	char path[80];
	sprintf(path, "/ccs/download/%016llx/%s", tid, obj);

	int ret = HTTP_request(NUS_SERVER, path, buffer, size);
	return ret;
}

static inline void zero_sig(signed_blob* blob) {
	memset(SIGNATURE_SIG(blob), 0, SIGNATURE_SIZE(blob));
}

static bool fakesign(signed_blob* s_tik, signed_blob* s_tmd) {
	sha1 hash;
	if (s_tik) {
		zero_sig(s_tik);

		tik* p_tik = SIGNATURE_PAYLOAD(s_tik);
		for (p_tik->padding = 0; p_tik->padding < (1 << 16) - 1; p_tik->padding++) {
			SHA1((void*)p_tik, sizeof(tik), hash);
			if (!hash[0]) break;
		}
		if (hash[0]) return false;
	}

	if (s_tmd) {
		zero_sig(s_tmd);

		tmd* p_tmd = SIGNATURE_PAYLOAD(s_tmd);
		for (p_tmd->fill3 = 0; p_tmd->fill3 < (1 << 16) - 1; p_tmd->fill3++) {
			SHA1((void*)p_tmd, TMD_SIZE(p_tmd), hash);
			if (!hash[0]) break;
		}
		if (hash[0]) return false;
	}

	return true;
}

static int get_title_rev(u64 tid) {
	u32 view_size = 0;
	int ret = ES_GetTMDViewSize(tid, &view_size);
	if (ret < 0) return ret;

	unsigned char _buffer[view_size];
	ret = ES_GetTMDView(tid, _buffer, view_size);
	if (ret < 0) return ret;

	tmd_view* view = (tmd_view*)_buffer;
	return view->title_version;
}

static int purge_title(u64 tid) {
	int ret;
	unsigned int viewcnt = 0;

	ret = ES_GetNumTicketViews(tid, &viewcnt);
	if (!viewcnt) return ret ? ret : ENOENT;

	[[gnu::aligned(0x20)]] tikview view, views[viewcnt];

	ret = ES_GetTicketViews(tid, views, viewcnt);
	if (ret < 0) return ret;
	for (int i = 0; i < viewcnt; i++) {
		view = views[i];
		ret = ES_DeleteTicket(&view);
		if (ret < 0) return ret;
	}

	ES_DeleteTitleContent(tid);
	return ES_DeleteTitle(tid);
}

int PatchMii_Install(u64 tid, int version, u64 tid_new, u8 ios_new) {
	int ret;
	char obj[10];
	size_t certs_size = 0xA00, tmd_size = 0, tik_size = 0;
	signed_blob *certs = NULL,
				*s_tmd = NULL,
				*s_tik = NULL;
	struct _tmd *p_tmd = NULL;
	struct _tik *p_tik = NULL;
	bool forge = (tid_new || ios_new);
	int version_installed = get_title_rev(tid);
	aeskey title_key = {}, iv = {};

	if (!forge && (version_installed > 0) && version_installed == version)
		return EEXIST;

//	error_log("(%016llx, %d, %016llx, %08x)", tid, version, tid_new, ios_new);

	ret = FS_Read("/sys/cert.sys", (void**)&certs, &certs_size);
	if (ret < 0)
		return ret;

	if (version > 0)
		sprintf(obj, "tmd.%hu", version);
	else
		sprintf(obj, "tmd");

	ret = NUS_Download(tid, obj, (void**)&s_tmd, &tmd_size);
	if (ret < 0)
		return ret;

	p_tmd = SIGNATURE_PAYLOAD(s_tmd);
	version = p_tmd->title_version;

	sprintf(obj, "cetk");
	ret = NUS_Download(tid, obj, (void**)&s_tik, &tik_size);
	if (ret < 0)
		return ret;

	p_tik = SIGNATURE_PAYLOAD(s_tik);

	struct AES_ctx tkey = {};

	memcpy(title_key, p_tik->cipher_title_key, sizeof(aeskey));
	*(u64*)iv = p_tik->titleid;

	AES_init_ctx_iv(&tkey, wii_ckey, iv);
	AES_CBC_decrypt_buffer(&tkey, title_key, sizeof(aeskey));

	if (tid_new) {
		aeskey _title_key = {};
		memcpy(_title_key, title_key, sizeof(aeskey));
		p_tik->titleid = tid_new;
		p_tmd->title_id = tid_new;
		*(u64*)iv = tid_new;

		AES_ctx_set_iv(&tkey, iv);
		AES_CBC_encrypt_buffer(&tkey, _title_key, sizeof(aeskey));

		memcpy(p_tik->cipher_title_key, _title_key, sizeof(aeskey));
	}

	if (ios_new) {
		p_tmd->sys_version = 1LL << 32 | ios_new;
	}

	if (forge && !fakesign(s_tik, s_tmd)) return -1030002011;

	if (forge || (version_installed > version)) {
		ret = purge_title(tid_new ? tid_new : tid);
		if (ret < 0)
			return ret;
	}

	ret = ES_AddTicket(s_tik, STD_SIGNED_TIK_SIZE, certs, certs_size, NULL, 0);
	if (ret < 0)
		return ret;

	ret = ES_AddTitleStart(s_tmd, SIGNED_TMD_SIZE(s_tmd), certs, certs_size, NULL, 0);
	if (ret < 0)
		return ret;

	for (int i = 0; i < p_tmd->num_contents; i++) {
		struct _tmd_content* content = p_tmd->contents + i;
		void* buffer = NULL;
		u32 cid = content->cid, _csize = 0;

		ret = ES_AddContentStart(p_tmd->title_id, cid);
		if (ret < 0)
			break;

		int cfd = ret;

		sprintf(obj, "%08x", cid);
		ret = NUS_Download(tid, obj, &buffer, &_csize);
		if (ret < 0)
			break;

		ES_AddContentData(cfd, buffer, _csize);
		ret = ES_AddContentFinish(cfd);
		free(buffer);
		if (ret < 0)
			break;
	}

	if (!ret)
		ret = ES_AddTitleFinish();
	if (ret < 0)
		ES_AddTitleCancel();

	free(certs);
	free(s_tmd);
	free(s_tik);
	return ret;
}
