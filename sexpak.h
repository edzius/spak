#ifndef __SEXPAK_H__
#define __SEXPAK_H__

#define BUFSIZE 1024*8
#define FILELEN 64

struct sex_opts {
	union {
		char s_cert_file[FILELEN];
		char s_key_file[FILELEN];
	};
};

int sign_format(FILE *srcfp, char *outbuf, size_t *outlen, struct sex_opts *opts);
int sign_verify(FILE *srcfp, char *signbuf, size_t signlen, struct sex_opts *opts);

#endif //__SEXPAK_H__
