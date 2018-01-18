
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sexpak.h"

#define SIGN_KEY "sexpak.key"
#define SIGN_CRT "sexpak.crt"

struct sexpak_head {
	unsigned char magic[4];
	unsigned int size;
	char mark[16];
	unsigned short keylen;
	unsigned char keydata[];
};

int fcopy(FILE *ifp, FILE *ofp)
{
	char buffer[8192];
	size_t nread, nwrite;
	size_t total = 0;

	while (1) {
		nread = fread(buffer, 1, sizeof(buffer), ifp);
		if (!nread)
			break;

		nwrite = fwrite(buffer, 1, nread, ofp);
		if (nread != nwrite) {
			printf("Content copy error %u/%u\n", nread, nwrite);
			return -1;
		}

		total += nwrite;
	}
	return total;
}

int sp_build(const char *srcfile, const char *dstfile, const char *mark)
{
	struct sexpak_head sph;
	struct sex_opts so;
	struct stat srcinfo;
	FILE *fp, *ofp;
	char keydata[BUFSIZE];
	size_t keylen = sizeof(keydata);
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

	strcpy(so.s_key_file, SIGN_KEY);

	if (sp_sign_file(fp, keydata, &keylen, &so)) {
		printf("Failed to generate file signature\n");
		fclose(fp);
		return -1;
	}

	sph.magic[0] = 'S';
	sph.magic[1] = 'X';
	sph.magic[2] = 'P';
	sph.magic[3] = 'K';
	sph.size = srcinfo.st_size;
	strncpy(sph.mark, mark, sizeof(sph.mark));
	sph.keylen = keylen;

	ofp = fopen(dstfile, "w");
	if (!ofp) {
		printf("Can't open file for writing: %s\n", dstfile);
		fclose(fp);
		return -1;
	}

	fwrite(&sph, 1, sizeof(sph), ofp);
	fwrite(keydata, 1, keylen, ofp);
	fseek(fp, 0, SEEK_SET);

	ret = fcopy(fp, ofp);

	fclose(ofp);
	fclose(fp);

	if (ret < 0) {
		unlink(dstfile);
		return -1;
	}

	return 0;
}

int sp_parse(const char *srcfile, const char *dstfile)
{
	struct sexpak_head sph;
	struct sex_opts so;
	size_t flen;
	FILE *fp, *ofp;
	char keydata[BUFSIZE];
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
		printf("Wrong file header size: %u\n", flen);
		return -1;
	}

	if (sph.magic[0] != 'S' || sph.magic[1] != 'X' ||
	    sph.magic[2] != 'P' || sph.magic[3] != 'K') {
		printf("Invalid file magic\n");
		return -1;
	}

	if (sph.keylen > BUFSIZE) {
		printf("Invalid file size\n");
		return -1;
	}

	flen = fread(keydata, 1, sph.keylen, fp);
	if (flen != sph.keylen) {
		printf("Invalid key size\n");
		return -1;
	}

	fseek(fp, sizeof(sph) + sph.keylen, SEEK_SET);

	strcpy(so.s_cert_file, SIGN_CRT);

	if (sp_verfiy_file(fp, keydata, sph.keylen, &so)) {
		fclose(fp);
		return -1;
	}

	ofp = fopen(dstfile, "w");
	if (!ofp) {
		printf("Can't open file for writing: %s\n", dstfile);
		return -1;
	}

	fseek(fp, sizeof(sph) + sph.keylen, SEEK_SET);
	ret = fcopy(fp, ofp);

	fclose(ofp);
	fclose(fp);

	if (ret < 0) {
		unlink(dstfile);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 4) {
		printf("Missing aruments\n");
		return -1;
	}

	if (!strcmp(argv[1], "b")) {
		if (argc < 5) {
			printf("Missing build/bundle aruments\n");
			return -1;
		}

		ret = sp_build(argv[2], argv[3], argv[4]);
		if (ret)
			printf("FAIL\n");

		return ret;
	} else if (!strcmp(argv[1], "v")) {
		ret = sp_parse(argv[2], argv[3]);
		if (!ret)
			printf("PASS\n");
		else
			printf("FAIL\n");

		return ret;
	} else {
		printf("Unknown command\n");
		exit(-1);
	}
}
