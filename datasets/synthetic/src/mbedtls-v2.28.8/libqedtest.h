// libqedtest.h
#ifndef LIBQEDTEST_H
#define LIBQEDTEST_H


#include <stdio.h>
#include <string.h>

#define MESSAGE "Hello, World!"
#define PRIVATE_KEY_FILE "private_key.pem"
#define PUBLIC_KEY_FILE "public_key.pem"

#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>


#include <mbedtls/dhm.h>


//#define _POSIX_C_SOURCE 200112L

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#if defined(MBEDTLS_CIPHER_C) && defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_FS_IO)
#include "mbedtls/cipher.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  crypt_and_hash <mode> <input filename> <output filename> <cipher> <mbedtls_md> <key>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: crypt_and_hash 0 file file.aes AES-128-CBC SHA1 hex:E76B2413958B00E193\n" \
    "\n"

int dh_test();
int ecdsa_test();
int rsa_test();
int aes_test(int argc, char *argv[]);
int sha512_test(int argc, char *argv[]);

#endif // LIBQEDTEST_H