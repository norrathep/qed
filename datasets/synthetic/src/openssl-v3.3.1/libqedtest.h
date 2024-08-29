// libqedtest.h
#ifndef LIBQEDTEST_H
#define LIBQEDTEST_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <openssl/decoder.h>

int dh_test();
int ecdsa_test();
int rsa_test();
int aes_test();
int sha512_test();

#endif // LIBQEDTEST_H
