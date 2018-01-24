/**
 * sipdec - secure image decrypt utility
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

#ifndef CONFIG_SIP_SIGN_CRT
#define SIP_SIGN_CRT "sign-sip.crt"
#else
#define SIP_SIGN_CRT CONFIG_SIP_SIGN_CRT
#endif

static char sipack_magic[] = { 0x1B, 'S', 'P', '1' };

struct sipack_header {
	unsigned char magic[4];
	unsigned int size;
	char mark[16];
	unsigned short keylen;
	unsigned char keydata[];
};

static int
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

static int
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

static void
sip_usage(void)
{
	fprintf(stderr, "Usage: sipenc [-c] <source-file> <output-file>\n");
}

int
main(int argc, char *argv[])
{
	int opt;
	char *srcfile;
	char *dstfile;
	int check = 0;

	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c':
			check = 1;
			break;
		default:
			sip_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		sip_usage();
		exit(EXIT_FAILURE);
	}

	if (check) {
		if (argc - optind < 1) {
			sip_usage();
			return 1;
		}

		srcfile = argv[optind];

		if (sip_check(srcfile)) {
			return 1;
		}
	} else {
		if (argc - optind < 2) {
			sip_usage();
			return 1;
		}

		srcfile = argv[optind];
		dstfile = argv[optind + 1];

		if (sip_decode(srcfile, dstfile)) {
			return 1;
		}
	}

	return 0;
}
