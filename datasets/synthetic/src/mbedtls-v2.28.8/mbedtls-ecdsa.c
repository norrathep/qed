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

static mbedtls_ctr_drbg_context ctr_drbg;  // Random number generator context
static mbedtls_entropy_context entropy;     // Entropy context

int ec_sign(const unsigned char *input, size_t input_len, unsigned char *sig, size_t *sig_len, const char *private_key_file) {
    int ret;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    mbedtls_ecdsa_init(&ecdsa);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Initialize the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        printf("    # Error initializing random number generator: %d\n", ret);
        return ret;
    }

    // Load private key
    ret = mbedtls_pk_parse_keyfile(&pk, private_key_file, NULL);
    if (ret != 0) {
        printf("    # Error loading private key: %d\n", ret);
        return ret;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        printf("    # Key is not an EC key\n");
        return -1;
    }

    // Set up ECDSA context from pk
    mbedtls_ecdsa_context *ecdsa_ctx = mbedtls_pk_ec(pk);

    // Sign the message
    ret = mbedtls_ecdsa_write_signature(ecdsa_ctx, MBEDTLS_MD_SHA256, input, input_len, sig, sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("    # Error signing message: %d\n", ret);
        return ret;
    }

    mbedtls_ecdsa_free(ecdsa_ctx);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

int ec_verify(const unsigned char *input, size_t input_len, const unsigned char *sig, size_t sig_len, const char *public_key_file) {
    int ret;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    mbedtls_ecdsa_init(&ecdsa);

    // Load public key
    ret = mbedtls_pk_parse_public_keyfile(&pk, public_key_file);
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        printf("    # Error loading public key: %d (%s)\n", ret, error_buf);
        return ret;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        printf("    # Key is not an EC key\n");
        return -1;
    }

    // Set up ECDSA context from pk
    mbedtls_ecdsa_context *ecdsa_ctx = mbedtls_pk_ec(pk);

    // Verify the message
    ret = mbedtls_ecdsa_read_signature(ecdsa_ctx, input, input_len, sig, sig_len);
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        printf("    # Error verifying signature: %d (%s)\n", ret, error_buf);
        return ret;
    }

    mbedtls_ecdsa_free(ecdsa_ctx);
    mbedtls_pk_free(&pk);

    return 0;
}

int main() {
    unsigned char signature[512];
    size_t signature_len = sizeof(signature);
    int ret;

    // Sign the message
    ret = ec_sign((const unsigned char *)MESSAGE, strlen(MESSAGE), signature, &signature_len, PRIVATE_KEY_FILE);
    if (ret != 0) {
        printf("    # Error signing message\n");
        return 1;
    }

    printf("    # Message signed successfully\n");

    // Verify the signature
    ret = ec_verify((const unsigned char *)MESSAGE, strlen(MESSAGE), signature, signature_len, PUBLIC_KEY_FILE);
    if (ret != 0) {
        printf("    # EC signature verification failed.\n");
        return 1;
    }

    printf("    # EC signature verified successfully.\n");
    return 0;
}