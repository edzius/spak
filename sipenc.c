/**
 * sipenc - secure image encrypt utility
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

#ifndef CONFIG_SIP_SIGN_KEY
#define SIP_SIGN_KEY "sign-sip.key"
#else
#define SIP_SIGN_KEY CONFIG_SIP_SIGN_KEY
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

static void
sip_usage(void)
{
	fprintf(stderr, "Usage: sipenc [-m MARK] <source-file> <output-file>\n");
}

int
main(int argc, char *argv[])
{
	int opt;
	char *srcfile;
	char *dstfile;
	char *mark = NULL;

	while ((opt = getopt(argc, argv, "m:")) != -1) {
		switch (opt) {
		case 'm':
			mark = optarg;
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

	if (argc - optind < 2) {
		sip_usage();
		exit(EXIT_FAILURE);
	}

	srcfile = argv[optind];
	dstfile = argv[optind + 1];

	if (sip_encode(srcfile, dstfile, mark)) {
		return 1;
	}

	return 0;
}
