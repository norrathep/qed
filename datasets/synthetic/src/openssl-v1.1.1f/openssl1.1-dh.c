#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

DH* create_dh_key() {
    
    printf("creating key..\n");
    DH *dh = DH_new();
    if (dh == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set DH parameters
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        DH_free(dh);
        return NULL;
    }

    if (DH_generate_key(dh) != 1) {
        ERR_print_errors_fp(stderr);
        DH_free(dh);
        return NULL;
    }

    return dh;
}

void print_dh_key(DH *dh) {

    printf("\nprinting key..\n");
    const BIGNUM *pub_key, *priv_key;
    DH_get0_key(dh, &pub_key, &priv_key);

    printf("Public Key: ");
    BN_print_fp(stdout, pub_key);
    printf("\n");

    printf("\nPrivate Key: ");
    BN_print_fp(stdout, priv_key);
    printf("\n");
}

void print_dh_params(DH *dh) {

    printf("printing parameter..\n");
    const BIGNUM *p, *g;
    DH_get0_pqg(dh, &p, NULL, &g);

    printf("DH Parameters:\n");
    printf(">> P: ");
    BN_print_fp(stdout, p);
    printf("\n");

    printf(">> G: ");
    BN_print_fp(stdout, g);
    printf("\n");
}

unsigned char* generate_shared_secret(DH *dh, const BIGNUM *peer_pub_key, size_t *secret_size) {
    int size = DH_size(dh);
    
    printf("\n# generating shared secret..\n");
    unsigned char *secret = malloc(size);
    if (secret == NULL) {
        fprintf(stderr, "Failed to allocate memory for shared secret\n");
        return NULL;
    }

    int len = DH_compute_key(secret, peer_pub_key, dh);
    if (len < 0) {
        ERR_print_errors_fp(stderr);
        free(secret);
        return NULL;
    }

    *secret_size = len;
    return secret;
}

void free_dh(DH *dh) {
    if (dh != NULL) {
        DH_free(dh);
    }
}
int main() {
    DH *dh = create_dh_key();
    if (dh == NULL) {
        fprintf(stderr, "Failed to create DH key\n");
        return 1;
    }

    print_dh_params(dh);
    print_dh_key(dh);

    // For demonstration, we use the same key as the peer key
    const BIGNUM *pub_key;
    DH_get0_key(dh, &pub_key, NULL);

    size_t secret_size;
    unsigned char *shared_secret = generate_shared_secret(dh, pub_key, &secret_size);
    if (shared_secret == NULL) {
        fprintf(stderr, "Failed to generate shared secret\n");
        free_dh(dh);
        return 1;
    }

    printf("Shared Secret: ");
    for (size_t i = 0; i < secret_size; i++) {
        printf("%02X", shared_secret[i]);
    }
    printf("\n");
    printf("\n>> DH App.c Successful\n");

    free(shared_secret);
    free_dh(dh);

    return 0;
}