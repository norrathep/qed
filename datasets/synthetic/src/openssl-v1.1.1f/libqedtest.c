#include "libqedtest.h"

// ================================== DH

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
int dh_test() {
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

// =============================================================== ECDSA

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

int ecdsa_test() {
    generate_ec_key(stdout);
    printf(">> EC App.c successfully\n");
    return 0;
}

// ====================================== RSA

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

int rsa_test(void) {
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

// =============================== AES
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int aes_test(void)
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
                         };

    /* A 128 bit IV */
    unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
                        };

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);


    return 0;
}

// =============================== SHA512

#define DIGEST_NAME "sha512-256"

int sha512_test() {
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  char mess1[] = "Test Message\n";
  char mess2[] = "Hello World\n";
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname(DIGEST_NAME);
  if(!md) {
    printf("Unknown message digest %s\n", DIGEST_NAME);
    exit(1);
  }
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
  EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  printf("Digest %s is: ", DIGEST_NAME);
  for(i = 0; i < md_len; i++)
    printf("%02x", md_value[i]);
  printf("\n");

  /* Call this once before exit. */
  EVP_cleanup();
  exit(0);
}