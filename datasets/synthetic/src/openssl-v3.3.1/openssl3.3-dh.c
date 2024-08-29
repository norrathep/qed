#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>

void generate_dh_params(EVP_PKEY **pkey) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_PKEY_paramgen(pctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    EVP_PKEY_CTX_free(pctx);
}

void print_dh_params(const EVP_PKEY *pkey) {
    EVP_PKEY_print_params_fp(stdout, pkey, 0, NULL);
}

int main() {
    EVP_PKEY *pkey = NULL;

    generate_dh_params(&pkey);
    if (pkey) {
        print_dh_params(pkey);
        EVP_PKEY_free(pkey);
    } else {
        printf("Failed to generate DH parameters.\n");
    }
    
    printf(">> DH App.c Successful\n");
    return 0;
}