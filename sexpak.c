
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "sexpak.h"

#define log_info printf
#define log_error printf

EVP_PKEY *
load_pvt_key(const char *file)
{
	EVP_PKEY *privkey;
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) {
		log_info("Failed to open key file\n");
		return NULL;
	}

	if (!(privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		log_info("Failed to read key\n");

	fclose(fp);

	return privkey;
}

EVP_PKEY *
load_cert_key(const char *file)
{
	EVP_PKEY *pkey = NULL;
	BIO *certbio = NULL;
	X509 *cert = NULL;

	/* ---------------------------------------------------------- *
	 * Create the Input/Output BIO's.                             *
	 * ---------------------------------------------------------- */
	certbio = BIO_new(BIO_s_file());

	/* ---------------------------------------------------------- *
	 * Load the certificate from file (PEM).                      *
	 * ---------------------------------------------------------- */
	if (!BIO_read_filename(certbio, file)) {
		log_info("Failed to open cert\n");
		BIO_free_all(certbio);
		return NULL;
	}

	if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		log_info("Failed to read cert\n");
		BIO_free_all(certbio);
		return NULL;
	}

	/* ---------------------------------------------------------- *
	 * Extract the certificate's public key data.                 *
	 * ---------------------------------------------------------- */
	if (!(pkey = X509_get_pubkey(cert)))
		log_info("Failed to get public key from certificate\n");

	X509_free(cert);
	BIO_free_all(certbio);

	return pkey;
}

static int
sign_build_BIO(BIO *in_data, BIO *out_data, struct sex_opts *opts)
{
	BIO *bmd = NULL;
	BIO *in = in_data, *out = out_data;
	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY *sigkey = NULL;
	const EVP_MD *md = NULL;
	int tmp, ret = 1;
	unsigned char buf[BUFSIZE];
	size_t buflen = BUFSIZE;

	if (!strlen(opts->s_key_file)) {
		log_error("Missing KEY file\n");
		return -1;
	}

	md = EVP_sha256();
	bmd = BIO_new(BIO_f_md());
	if (!md || !bmd) {
		log_error("Internal error\n");
		goto end;
	}

	BIO_push(bmd, in);

	sigkey = load_pvt_key(opts->s_key_file);
	if (!sigkey) {
		log_error("Failed to load KEY file %s\n", opts->s_key_file);
		goto end;
	}

	if (!BIO_get_md_ctx(bmd, &mctx)) {
		log_error("Error getting context\n");
		goto end;
	}
	if (!EVP_DigestSignInit(mctx, NULL, md, NULL, sigkey)) {
		log_error("Error initializing context\n");
		goto end;
	}

	/* XXX(edzius): why? ..signing/verify does not work well without it */
	for (;;) {
		tmp = BIO_read(bmd, (char *)buf, BUFSIZE);
		if (tmp < 0) {
			log_error("Error reading contents from input file\n");
			goto end;
		}
		if (tmp == 0)
			break;
	}

	if (!EVP_DigestSignFinal(mctx, buf, &buflen)) {
		log_error("Error signing content\n");
		goto end;
	}

	BIO_write(out, buf, buflen);
	(void)BIO_reset(bmd);

	ret = 0;
end:
	EVP_PKEY_free(sigkey);
	BIO_free(bmd);
	return ret;
}

static int
sign_verify_BIO(BIO *in_data, BIO *sig_data, struct sex_opts *opts)
{
	BIO *bmd = NULL;
	BIO *in = in_data;
	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY *sigkey = NULL;
	const EVP_MD *md = NULL;
	size_t siglen = 0;
	int tmp, ret = 1;
	unsigned char buf[BUFSIZE], *sigbuf = NULL;

	if (!opts->s_cert_file) {
		log_error("Missing CERT file\n");
		goto end;
	}

	md = EVP_sha256();
	bmd = BIO_new(BIO_f_md());
	if (!md || !bmd) {
		log_error("Internal error\n");
		goto end;
	}

	BIO_push(bmd, in);

	sigkey = load_cert_key(opts->s_cert_file);
	if (!sigkey) {
		log_error("Failed to load CERT file %s\n", opts->s_key_file);
		goto end;
	}

	siglen = EVP_PKEY_size(sigkey);
	sigbuf = malloc(siglen);
	siglen = BIO_read(sig_data, sigbuf, siglen);
	BIO_free(sig_data);
	if (siglen <= 0) {
		log_error("Error reading signature file\n");
		goto end;
	}

	if (!BIO_get_md_ctx(bmd, &mctx)) {
		log_error("Error getting context\n");
		goto end;
	}
	if (!EVP_DigestVerifyInit(mctx, NULL, md, NULL, sigkey)) {
		log_error("Error initializing context\n");
		goto end;
	}

	/* XXX(edzius): why? ..signing/verify does not work well without it */
	for (;;) {
		tmp = BIO_read(bmd, (char *)buf, BUFSIZE);
		if (tmp < 0) {
			log_error("Error reading contents from input file\n");
			goto end;
		}
		if (tmp == 0)
			break;
	}

        ret = EVP_DigestVerifyFinal(mctx, sigbuf, siglen);
        if (ret > 0) {
		/* Pass */
		ret = 0;
	} else if (ret == 0) {
		/* Fail */
		ret = 1;
		goto end;
        } else {
		/* Error */
		ret = 2;
		goto end;
        }

	(void)BIO_reset(bmd);

	ret = 0;
end:
	free(sigbuf);
	EVP_PKEY_free(sigkey);
	BIO_free(bmd);
	return ret;
}


int
sp_sign_file(FILE *srcfp, char *outbuf, size_t *outlen, struct sex_opts *opts)
{
	int ret;
	char *tmp;
	BIO *in = NULL;
	BIO *out = NULL;

	OpenSSL_add_all_algorithms();

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_mem());
	if (!in || !out)
		return -1;

	BIO_set_fp(in, srcfp, BIO_NOCLOSE);

	ret = sign_build_BIO(in, out, opts);
	if (!ret) {
		*outlen = BIO_get_mem_data(out, &tmp);
		memcpy(outbuf, tmp, *outlen);
	}

	BIO_free(out);
	BIO_free(in);

	return ret;
}

int
sp_verfiy_file(FILE *srcfp, char *signbuf, size_t signlen, struct sex_opts *opts)
{
	int ret;
	BIO *in = NULL;
	BIO *sig = NULL;

	OpenSSL_add_all_algorithms();

	in = BIO_new(BIO_s_file());
	sig = BIO_new_mem_buf(signbuf, signlen);
	if (!in || !sig)
		return -1;

	BIO_set_fp(in, srcfp, BIO_NOCLOSE);

	ret = sign_verify_BIO(in, sig, opts);

	BIO_free(sig);
	BIO_free(in);

	return ret;
}

int
sp_encrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct sex_opts *opts)
{
	int retlen;
	EVP_PKEY *pkey;
	RSA *rsa;

	OpenSSL_add_all_algorithms();

	pkey = load_pvt_key(opts->s_key_file);
	if (!pkey) {
		return -1;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (!rsa) {
		log_error("Failed to get KEY RSA\n");
		return -1;
	}

	retlen = RSA_private_encrypt(srclen, srcbuf, dstbuf, rsa, RSA_PKCS1_PADDING);
	RSA_free(rsa);
	return retlen;
}

int
sp_decrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct sex_opts *opts)
{
	int retlen;
	EVP_PKEY *pkey;
	RSA *rsa;

	OpenSSL_add_all_algorithms();

	pkey = load_cert_key(opts->s_cert_file);
	if (!pkey) {
		return -1;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (!rsa) {
		log_error("Failed to get KEY RSA\n");
		return -1;
	}

	retlen = RSA_public_decrypt(srclen, srcbuf, dstbuf, rsa, RSA_PKCS1_PADDING);
	RSA_free(rsa);
	return retlen;
}
