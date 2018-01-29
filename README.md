
# About

The signed packaging library / utilities package based on OpenSSL.

# Usage

## Prepare

Generate self signed key/certificate pair.
```
openssl req -x509 -newkey rsa:4096 -keyout sign-sip.key -out sign-sip.crt -days 365 -nodes
```

## Build

Build time options:

* CONFIG_SPAK_KEY_FILE -- private key file name
* CONFIG_SPAK_CRT_FILE -- certificate file name
* CONFIG_SPAK_STATIC_CERT -- compile-in certs statically
* CONFIG_SPAK_SHARED_LIB -- build shared libaray instead of static linkink

Note: default key file names can be changed during build time passing CFLAGS

Build shared library/utilities:

```
CONFIG_SPAK_SHARED_LIBRARY=1 make
CONFIG_SPAK_STATIC_CERT=1 CONFIG_SPAK_KEY_FILE=sign-sip.key CONFIG_SPAK_CRT_FILE=sign-sip.crt make
```

## Run

Run utility, you will need to provide mandatory input and output file arguments
```
./sip
```

Available options
```
Usage: sip [options] <source-file> <output-file>
  -e, --encode             Image encode operation
  -d, --decode             Image decode operation
  -c, --check              Validate provided image
  -m, --mark [MARK]        Encoding specific mark
```

# References

## Command line

https://raymii.org/s/tutorials/Encrypt_and_decrypt_files_to_public_keys_via_the_OpenSSL_Command_Line.html

## Programmic API

http://www.czeskis.com/random/openssl-encrypt-file.html
http://krisjordan.com/essays/encrypting-with-rsa-key-pairs
http://hayageek.com/rsa-encryption-decryption-openssl-c/#private-encrypt
https://eclipsesource.com/blogs/2016/09/07/tutorial-code-signing-and-verification-with-openssl/
https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
http://fm4dd.com/openssl/certpubkey.htm
http://fm4dd.com/openssl/keytest.htm
https://gist.github.com/mythosil/1292999
https://gist.github.com/mythosil/1292328
https://gist.github.com/mythosil/1292283
https://gist.github.com/barrysteyn/7308212
