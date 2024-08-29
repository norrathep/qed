#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

// Function to create a new EC key pair and print the public key
void generate_ec_key(FILE *out) {
    EC_KEY *ec_key = NULL;
    const EC_POINT *pub_key = NULL;
    char *pub_key_hex = NULL;
    size_t key_size;

    // Create a new EC key pair
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        fprintf(out, "Error creating EC key\n");
        ERR_print_errors_fp(out);
        return;
    }

    // Generate the EC key pair
    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(out, "Error generating EC key\n");
        ERR_print_errors_fp(out);
        EC_KEY_free(ec_key);
        return;
    }

    // Get the public key
    pub_key = EC_KEY_get0_public_key(ec_key);
    if (pub_key == NULL) {
        fprintf(out, "Error getting EC public key\n");
        EC_KEY_free(ec_key);
        return;
    }

    // Get the size needed to store the public key in octet format
    key_size = EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);

    // Allocate memory for the public key in hexadecimal format
    pub_key_hex = (char *)malloc(key_size * 2 + 1);
    if (pub_key_hex == NULL) {
        fprintf(out, "Memory allocation error\n");
        EC_KEY_free(ec_key);
        return;
    }
    
    // Convert the public key to octet format
    unsigned char *pub_key_oct = (unsigned char *)malloc(key_size);
    if (pub_key_oct == NULL) {
        fprintf(out, "Memory allocation error\n");
        free(pub_key_hex);
        EC_KEY_free(ec_key);
        return;
    }

    EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_oct, key_size, NULL);

    // Convert the octet format to hexadecimal format
    for (size_t i = 0; i < key_size; ++i) {
        snprintf(pub_key_hex + (i * 2), 3, "%02x", pub_key_oct[i]);
    }
    pub_key_hex[key_size * 2] = '\0'; // Null-terminate the string

    // Print the public key
    fprintf(out, "EC Public Key: %s\n", pub_key_hex);

    // Clean up
    free(pub_key_oct);
    free(pub_key_hex);
    EC_KEY_free(ec_key);
}

int main() {
    generate_ec_key(stdout);
    printf(">> EC App.c successfully\n");
    return 0;
}