#include <mbedtls/dhm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <stdio.h>
#include <string.h>

void dh_key_exchange(unsigned char *shared_secret, size_t *secret_len) {
    mbedtls_dhm_context dhm;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "dh";

    mbedtls_dhm_init(&dhm);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

    // For simplicity, we'll use predefined parameters
    mbedtls_mpi_read_string(&dhm.P, 16, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
    mbedtls_mpi_read_string(&dhm.G, 16, "02");

    mbedtls_dhm_make_public(&dhm, (int) *secret_len, shared_secret, *secret_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_dhm_calc_secret(&dhm, shared_secret, *secret_len, secret_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_dhm_free(&dhm);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int main() {
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);

    dh_key_exchange(shared_secret, &secret_len);
    printf("    # DH key exchange completed. \n    # Shared secret length: %zu\n", secret_len);

    return 0;
}