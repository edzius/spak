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

int sp_sign_file(FILE *srcfp, char *outbuf, size_t *outlen, struct sex_opts *opts);
int sp_verfiy_file(FILE *srcfp, char *signbuf, size_t signlen, struct sex_opts *opts);

int sp_key_decrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct sex_opts *opts);
int sp_key_encrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct sex_opts *opts);

int sp_pass_encrypt_data(const char *infile, const char *outfile, const char *pass);
int sp_pass_decrypt_data(const char *infile, const char *outfile, const char *pass);

#endif //__SEXPAK_H__
