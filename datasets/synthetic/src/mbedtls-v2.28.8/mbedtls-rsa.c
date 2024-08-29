#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>

int rsa_generate_key_pair(mbedtls_rsa_context *rsa, mbedtls_ctr_drbg_context *ctr_drbg) {
    int ret;
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

    ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, ctr_drbg, 2048, 65537);
    if (ret != 0) {
        return -1;
    }
    return 0;
}

int rsa_sign(const unsigned char *message, size_t message_len,
             unsigned char *signature, size_t *signature_len,
             mbedtls_rsa_context *rsa, mbedtls_ctr_drbg_context *ctr_drbg) {
    int ret;
    unsigned char hash[32];
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        return -1;
    }

    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, message, message_len);
    mbedtls_md_finish(&md_ctx, hash);

    ret = mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PRIVATE,
                                 MBEDTLS_MD_SHA256, 32, hash, signature);
    if (ret != 0) {
        return -1;
    }

    *signature_len = mbedtls_rsa_get_len(rsa);
    mbedtls_md_free(&md_ctx);
    return 0;
}

int main() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa;
    unsigned char signature[512];
    size_t signature_len;
    const char *pers = "rsa_example";
    unsigned char message[] = "Hello, world!";
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    // Seed the random number generator
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *) pers, strlen(pers)) != 0) {
        printf("    # Failed to seed random number generator\n");
        return -1;
    }

    // Generate RSA key pair
    if (rsa_generate_key_pair(&rsa, &ctr_drbg) != 0) {
        printf("    # Failed to generate RSA key pair\n");
        return -1;
    }

    // Sign the message
    if (rsa_sign(message, sizeof(message) - 1, signature, &signature_len, &rsa, &ctr_drbg) != 0) {
        printf("    # Failed to sign message\n");
        return -1;
    }

    printf("    # Message signed successfully\n");

    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}