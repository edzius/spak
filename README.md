
# About

The signed packaging library / utilities package based on OpenSSL.

# Usage

Generate self signed key/certificate pair.
```
openssl req -x509 -newkey rsa:4096 -keyout sign-sip.key -out sign-sip.crt -days 365 -nodes
```

Note: default key names can be changed during build time passing CFLAGS

* CONFIG_SIP_SIGN_KEY -- private key file name
* CONFIG_SIP_SIGN_KEY -- certificate file name

Build library/utility:

Statically linked utility:
```
make
```

Shared library and utility:
```
CONFIG_SHARED_LIBRARY=1 make
```

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
