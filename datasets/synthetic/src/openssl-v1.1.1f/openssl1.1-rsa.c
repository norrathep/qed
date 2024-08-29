// app.c
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *create_rsa_key(void) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (bn == NULL || rsa == NULL) {
        handle_errors();
    }
    if (BN_set_word(bn, RSA_F4) != 1) {
        handle_errors();
    }
    printf("Generating RSA key...\n");
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        handle_errors();
    }
    printf("RSA key generated successfully.\n");

    // Print key details
    printf("RSA Key Details:\n");
    printf("Key Size: %d bits\n", RSA_size(rsa) * 8);

    BN_free(bn);
    return rsa;
}

void print_rsa_key(RSA *rsa) {
    if (rsa == NULL) {
        printf("RSA key is NULL\n");
        return;
    }

    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (bio == NULL) {
        handle_errors();
    }
    printf("RSA Key (PEM format):\n");
    PEM_write_bio_RSAPublicKey(bio, rsa);
    BIO_free_all(bio);
}

void rsa_key_to_file(RSA *rsa, const char *filename) {
    BIO *bio = BIO_new_file(filename, "w+");
    if (bio == NULL) {
        handle_errors();
    }
    printf("Writing RSA public key to file: %s\n", filename);
    if (PEM_write_bio_RSAPublicKey(bio, rsa) != 1) {
        handle_errors();
    }
    printf("RSA public key written to %s successfully.\n", filename);
    BIO_free_all(bio);
}

void rsa_sign_message(RSA *rsa, const unsigned char *message, size_t message_len, unsigned char *signature, unsigned int *sig_len) {
    printf("Signing message...\n");
    if (RSA_sign(NID_sha256, message, message_len, signature, sig_len, rsa) != 1) {
        handle_errors();
    }
    printf("Message signed successfully.\n");
}

int rsa_verify_message(RSA *rsa, const unsigned char *message, size_t message_len, const unsigned char *signature, unsigned int sig_len) {
    printf("Verifying signature...\n");
    int result = RSA_verify(NID_sha256, message, message_len, signature, sig_len, rsa);
    if (result == 1) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }
    return result;
}

int main(void) {
    // Create RSA key
    RSA *rsa = create_rsa_key();
    rsa_key_to_file(rsa, "public_key.pem");

    // Sign a message
    const char *message = "Hello, world!";
    unsigned char signature[256];
    unsigned int sig_len;
    rsa_sign_message(rsa, (const unsigned char *)message, strlen(message), signature, &sig_len);

    // Verify the signature
    int verify = rsa_verify_message(rsa, (const unsigned char *)message, strlen(message), signature, sig_len);
    if (verify == 1) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }

    RSA_free(rsa);
    return 0;
}