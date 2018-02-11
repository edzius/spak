
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "spak.h"
#ifdef CONFIG_SPAK_STATIC_CERT
#include "spakcert.h"
#endif

#define log_info printf
#define log_error printf

#define CRYPT_BUFSIZE   (8*1024)
static const char magic[] = "Salted__";

static EVP_PKEY *
load_pvt_key(const char *file)
{
	EVP_PKEY *privkey;
	BIO *keybio;

#ifndef CONFIG_SPAK_STATIC_CERT
	keybio = BIO_new(BIO_s_file());

	if (!BIO_read_filename(keybio, file)) {
		log_info("Failed to open key\n");
		BIO_free(keybio);
		return NULL;
	}
#else
	(void)file;

	keybio = BIO_new_mem_buf(spak_key_data, -1);
	BIO_set_close(keybio, BIO_NOCLOSE);
#endif

	if (!(privkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL)))
		log_info("Failed to read key\n");

	BIO_free(keybio);

	return privkey;
}

static EVP_PKEY *
load_cert_key(const char *file)
{
	EVP_PKEY *pkey;
	BIO *certbio;
	X509 *cert;

#ifndef CONFIG_SPAK_STATIC_CERT
	certbio = BIO_new(BIO_s_file());

	if (!BIO_read_filename(certbio, file)) {
		log_info("Failed to open cert\n");
		BIO_free_all(certbio);
		return NULL;
	}
#else
	(void)file;

	certbio = BIO_new_mem_buf(spak_crt_data, -1);
	BIO_set_close(certbio, BIO_NOCLOSE);
#endif

	if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		log_info("Failed to read cert\n");
		BIO_free(certbio);
		return NULL;
	}

	if (!(pkey = X509_get_pubkey(cert)))
		log_info("Failed to get public key from certificate\n");

	X509_free(cert);
	BIO_free(certbio);

	return pkey;
}

static int
sign_build_BIO(BIO *in_data, BIO *out_data, struct spak_opts *opts)
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
sign_verify_BIO(BIO *in_data, BIO *sig_data, struct spak_opts *opts)
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
sp_sign_file(FILE *srcfp, char *outbuf, size_t *outlen, struct spak_opts *opts)
{
	int ret;
	char *tmp;
	BIO *in = NULL;
	BIO *out = NULL;

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
sp_verfiy_file(FILE *srcfp, char *signbuf, size_t signlen, struct spak_opts *opts)
{
	int ret;
	BIO *in = NULL;
	BIO *sig = NULL;

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
sp_key_encrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct spak_opts *opts)
{
	int retlen;
	EVP_PKEY *pkey;
	RSA *rsa;

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
sp_key_decrypt_data(unsigned char *srcbuf, size_t srclen, unsigned char *dstbuf, struct spak_opts *opts)
{
	int retlen;
	EVP_PKEY *pkey;
	RSA *rsa;

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

int
sp_pass_encrypt_data(FILE *srcfp, FILE *dstfp, const char *pass)
{
	BIO *benc = NULL, *rbio = NULL, *wbio = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = NULL;
	int ret = 1;
	int rlen;
	int buffsize = CRYPT_BUFSIZE;
	unsigned char buff[EVP_ENCODE_LENGTH(buffsize)];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char salt[PKCS5_SALT_LEN];

	cipher = EVP_aes_256_cbc();

	rbio = BIO_new(BIO_s_file());
	wbio = BIO_new(BIO_s_file());
	if (!rbio || !wbio) {
		log_error("Internal error\n");
		return -1;
	}

	BIO_set_fp(rbio, srcfp, BIO_NOCLOSE);
	BIO_set_fp(wbio, dstfp, BIO_NOCLOSE);

	if (RAND_bytes(salt, sizeof(salt)) <= 0) {
		log_error("Error generating random data\n");
		goto end;
	}

	if (!EVP_BytesToKey(cipher, EVP_sha256(), salt,
			    (unsigned char *)pass, strlen(pass), 1, key, iv)) {
		log_error("Failed EVP_BytesToKey\n");
		goto end;
	}

	if ((BIO_write(wbio, magic, sizeof(magic) - 1) != sizeof(magic) - 1 ||
	     BIO_write(wbio, salt, sizeof(salt)) != sizeof(salt))) {
		log_error("Error writing output file\n");
		goto end;
	}

	benc = BIO_new(BIO_f_cipher());
	if (!benc) {
		log_error("Internal error\n");
		goto end;
	}

	BIO_get_cipher_ctx(benc, &ctx);

	if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1)) {
		log_error("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
		goto end;
	}

	if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)) {
		log_error("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
		goto end;
	}

	wbio = BIO_push(benc, wbio);

	for (;;) {
		rlen = BIO_read(rbio, (char *)buff, buffsize);
		if (rlen <= 0)
			break;
		if (BIO_write(wbio, (char *)buff, rlen) != rlen) {
			log_error("Error writing output file\n");
			goto end;
		}
	}

	if (!BIO_flush(wbio)) {
		log_info("Bad encrypt\n");
		goto end;
	}

	ret = 0;
end:
	BIO_free(rbio);
	BIO_free_all(wbio);
	BIO_free(benc);
	return (ret);
}

int
sp_pass_decrypt_data(FILE *srcfp, FILE *dstfp, const char *pass)
{
	BIO *benc = NULL, *rbio = NULL, *wbio = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = NULL;
	char mbuf[sizeof(magic) - 1];
	int ret = 1;
	int rlen;
	int buffsize = CRYPT_BUFSIZE;
	unsigned char buff[EVP_ENCODE_LENGTH(buffsize)];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char salt[PKCS5_SALT_LEN];

	cipher = EVP_aes_256_cbc();

	rbio = BIO_new(BIO_s_file());
	wbio = BIO_new(BIO_s_file());
	if (!rbio || !wbio) {
		log_error("Internal error\n");
		return -1;
	}

	BIO_set_fp(rbio, srcfp, BIO_NOCLOSE);
	BIO_set_fp(wbio, dstfp, BIO_NOCLOSE);

	if (BIO_read(rbio, mbuf, sizeof(mbuf)) != sizeof(mbuf) ||
	    BIO_read(rbio, salt, sizeof(salt)) != sizeof(salt)) {
		log_error("Error reading input file\n");
		goto end;
	}

	if (memcmp(mbuf, magic, sizeof(magic) - 1)) {
		log_error("Bad magic number\n");
		goto end;
	}

	if (!EVP_BytesToKey(cipher, EVP_sha256(), salt,
			    (unsigned char *)pass, strlen(pass), 1, key, iv)) {
		printf("Failed EVP_BytesToKey\n");
		goto end;
	}

	benc = BIO_new(BIO_f_cipher());
	if (!benc) {
		log_error("Internal error\n");
		goto end;
	}

	BIO_get_cipher_ctx(benc, &ctx);

	if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0)) {
		log_error("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
		goto end;
	}

	if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0)) {
		log_error("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
		goto end;
	}

	/* Only encrypt/decrypt as we write the file */
	wbio = BIO_push(benc, wbio);

	for (;;) {
		rlen = BIO_read(rbio, (char *)buff, buffsize);
		if (rlen <= 0)
			break;
		if (BIO_write(wbio, (char *)buff, rlen) != rlen) {
			log_error("Error writing output file\n");
			goto end;
		}
	}

	if (!BIO_flush(wbio)) {
		log_info("Bad decrypt\n");
		goto end;
	}

	ret = 0;
end:
	BIO_free(rbio);
	BIO_free_all(wbio);
	BIO_free(benc);
	return (ret);
}

int
sp_rand_base64(char *buf, size_t len)
{
	BIO *out, *b64;
	char *tmp;
	int left = len / 2;
	int ret = 1;

	out = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	if (!out || !b64)
		goto end;
	out = BIO_push(b64, out);
	BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

	while (left > 0) {
		unsigned char buf[4096];
		size_t chunk;

		chunk = left;
		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		if (RAND_bytes(buf, chunk) <= 0)
			goto end;
		if (BIO_write(out, buf, chunk) != chunk)
			goto end;
		left -= chunk;
	}
	if (BIO_flush(out) <= 0)
		goto end;

	left = BIO_get_mem_data(out, &tmp);
	memcpy(buf, tmp, left);
	buf[left] = 0;

	ret = 0;
end:
	BIO_free_all(out);
	return ret;
}
