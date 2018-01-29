/**
 * sip - secure image packer utility
 * Author: Edvinas Stunzenas <edvinas.stunzenas@gmail.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "spak.h"

#ifndef CONFIG_SPAK_KEY_FILE
#define SIP_SIGN_KEY "sign-sip.key"
#else
#define SIP_SIGN_KEY CONFIG_SPAK_KEY_FILE
#endif

#ifndef CONFIG_SPAK_CRT_FILE
#define SIP_SIGN_CRT "sign-sip.crt"
#else
#define SIP_SIGN_CRT CONFIG_SPAK_CRT_FILE
#endif

static char sipack_magic[] = { 0x1B, 'S', 'P', '1' };

struct sipack_header {
	unsigned char magic[4];
	unsigned int size;
	char mark[16];
	unsigned short keylen;
	unsigned char keydata[];
};

int
sip_check(const char *srcfile)
{
	struct sipack_header sph;
	struct stat srcinfo;
	FILE *fp;
	size_t flen;

	if (stat(srcfile, &srcinfo)) {
		printf("Status: Fail\n");
		return -1;
	}

	fp = fopen(srcfile, "r");
	if (!fp) {
		printf("Status: Fail\n");
		return -1;
	}

	flen = fread(&sph, 1, sizeof(sph), fp);
	if (flen != sizeof(sph)) {
		printf("Status: Fail\n");
		return -1;
	}

	/* TODO(edzius): support for various magic types */
	if (memcmp(sph.magic, sipack_magic, sizeof(sph.magic))) {
		printf("Status: Fail\n");
		return -1;
	}

	if (sph.keylen > 4096) {
		printf("Status: Fail\n");
		return -1;
	}

	printf("Status: Pass\n");
	printf("Mark: %s\n", sph.mark);
	return 0;
}

int
sip_encode(const char *srcfile, const char *dstfile, const char *mark)
{
	struct sipack_header sph = {0};
	struct spak_opts so;
	struct stat srcinfo;
	FILE *fp, *ofp;
	char passbuf[64];
	unsigned char cryptbuf[4096];
	size_t cryptlen;
	int ret;

	if (stat(srcfile, &srcinfo)) {
		printf("No such file: %s\n", srcfile);
		return -1;
	}

	fp = fopen(srcfile, "r");
	if (!fp) {
		printf("Can't open file for reading: %s\n", srcfile);
		return -1;
	}

	if (sp_rand_base64(passbuf, sizeof(passbuf))) {
		printf("Can't generate pass\n");
		fclose(fp);
		return -1;
	}

	strcpy(so.s_key_file, SIP_SIGN_KEY);

	cryptlen = sp_key_encrypt_data((unsigned char *)passbuf, strlen(passbuf), cryptbuf, &so);
	if (cryptlen <= 0) {
		printf("Failed to encrypt pass\n");
		fclose(fp);
		return -1;
	}

	sph.size = srcinfo.st_size;
	memcpy(sph.magic, sipack_magic, sizeof(sph.magic));
	if (mark)
		strncpy(sph.mark, mark, sizeof(sph.mark));

	sph.keylen = cryptlen;

	ofp = fopen(dstfile, "w");
	if (!ofp) {
		printf("Can't open file for writing: %s\n", dstfile);
		fclose(fp);
		return -1;
	}

	fwrite(&sph, 1, sizeof(sph), ofp);
	fwrite(cryptbuf, 1, cryptlen, ofp);
	fseek(fp, 0, SEEK_SET);

	ret = sp_pass_encrypt_data(fp, ofp, passbuf);

	fclose(ofp);
	fclose(fp);

	if (ret < 0) {
		unlink(dstfile);
		return -1;
	}

	return 0;
}

int
sip_decode(const char *srcfile, const char *dstfile)
{
	struct sipack_header sph;
	struct spak_opts so;
	size_t flen;
	FILE *fp, *ofp;
	unsigned char cryptbuf[4096];
	char passbuf[2048/8];
	size_t passlen;
	int ret;

	if (access(srcfile, F_OK)) {
		printf("No such file: %s\n", srcfile);
		return -1;
	}

	fp = fopen(srcfile, "r");
	if (!fp) {
		printf("Can't open file for reading: %s\n", srcfile);
		return -1;
	}

	flen = fread(&sph, 1, sizeof(sph), fp);
	if (flen != sizeof(sph)) {
		printf("Wrong file header size: %lu\n", flen);
		return -1;
	}

	/* TODO(edzius): support for various magic types */
	if (memcmp(sph.magic, sipack_magic, sizeof(sph.magic))) {
		printf("Invalid file magic\n");
		return -1;
	}

	if (sph.keylen > 4096) {
		printf("Invalid file size\n");
		return -1;
	}

	flen = fread(cryptbuf, 1, sph.keylen, fp);
	if (flen != sph.keylen) {
		printf("Invalid key size\n");
		return -1;
	}

	strcpy(so.s_cert_file, SIP_SIGN_CRT);

	passlen = sp_key_decrypt_data(cryptbuf, sph.keylen, (unsigned char *)passbuf, &so);
	if (passlen <= 0) {
		printf("Failed to decrypt data\n");
		return -1;
	}

	ofp = fopen(dstfile, "w");
	if (!ofp) {
		printf("Can't open file for writing: %s\n", dstfile);
		return -1;
	}

	fseek(fp, sizeof(sph) + sph.keylen, SEEK_SET);

	ret = sp_pass_decrypt_data(fp, ofp, passbuf);

	fclose(ofp);
	fclose(fp);

	if (ret < 0) {
		unlink(dstfile);
		return -1;
	}

	return 0;
}
