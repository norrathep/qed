#include "libqedtest.h"

// ================================== RSA

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

int rsa_test() {
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

// ============================== ECDSA

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

int ecdsa_test() {
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

// =================================== DH

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

int dh_test() {
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);

    dh_key_exchange(shared_secret, &secret_len);
    printf("    # DH key exchange completed. \n    # Shared secret length: %zu\n", secret_len);

    return 0;
}

// ========================================  AES


#if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_FS_IO)
int aes_test(void)
{
    mbedtls_printf("MBEDTLS_CIPHER_C and/or MBEDTLS_MD_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit(0);
}
#else


int aes_test(int argc, char *argv[])
{
    int ret = 1, i;
    unsigned n;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    int mode;
    size_t keylen, ilen, olen;
    FILE *fkey, *fin = NULL, *fout = NULL;

    char *p;
    unsigned char IV[16];
    unsigned char key[512];
    unsigned char digest[MBEDTLS_MD_MAX_SIZE];
    unsigned char buffer[1024];
    unsigned char output[1024];
    unsigned char diff;

    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_cipher_mode_t cipher_mode;
    unsigned int cipher_block_size;
    unsigned char md_size;
#if defined(_WIN32_WCE)
    long filesize, offset;
#elif defined(_WIN32)
    LARGE_INTEGER li_size;
    __int64 filesize, offset;
#else
    off_t filesize, offset;
#endif

    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_md_init(&md_ctx);

    /*
     * Parse the command-line arguments.
     */
    if (argc != 7) {
        const int *list;

        mbedtls_printf(USAGE);

        mbedtls_printf("Available ciphers:\n");
        list = mbedtls_cipher_list();
        while (*list) {
            cipher_info = mbedtls_cipher_info_from_type(*list);
            mbedtls_printf("  %s\n", cipher_info->name);
            list++;
        }

        mbedtls_printf("\nAvailable message digests:\n");
        list = mbedtls_md_list();
        while (*list) {
            md_info = mbedtls_md_info_from_type(*list);
            mbedtls_printf("  %s\n", mbedtls_md_get_name(md_info));
            list++;
        }

#if defined(_WIN32)
        mbedtls_printf("\n  Press Enter to exit this program.\n");
        fflush(stdout); getchar();
#endif

        goto exit;
    }

    mode = atoi(argv[1]);

    if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
        mbedtls_fprintf(stderr, "invalid operation mode\n");
        goto exit;
    }

    if (strcmp(argv[2], argv[3]) == 0) {
        mbedtls_fprintf(stderr, "input and output filenames must differ\n");
        goto exit;
    }

    if ((fin = fopen(argv[2], "rb")) == NULL) {
        mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[2]);
        goto exit;
    }

    if ((fout = fopen(argv[3], "wb+")) == NULL) {
        mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[3]);
        goto exit;
    }

    /*
     * Read the Cipher and MD from the command line
     */
    cipher_info = mbedtls_cipher_info_from_string(argv[4]);
    if (cipher_info == NULL) {
        mbedtls_fprintf(stderr, "Cipher '%s' not found\n", argv[4]);
        goto exit;
    }
    if ((ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info)) != 0) {
        mbedtls_fprintf(stderr, "mbedtls_cipher_setup failed\n");
        goto exit;
    }

    md_info = mbedtls_md_info_from_string(argv[5]);
    if (md_info == NULL) {
        mbedtls_fprintf(stderr, "Message Digest '%s' not found\n", argv[5]);
        goto exit;
    }

    if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0) {
        mbedtls_fprintf(stderr, "mbedtls_md_setup failed\n");
        goto exit;
    }

    /*
     * Read the secret key from file or command line
     */
    if ((fkey = fopen(argv[6], "rb")) != NULL) {
        keylen = fread(key, 1, sizeof(key), fkey);
        fclose(fkey);
    } else {
        if (memcmp(argv[6], "hex:", 4) == 0) {
            p = &argv[6][4];
            keylen = 0;

            while (sscanf(p, "%02X", (unsigned int *) &n) > 0 &&
                   keylen < (int) sizeof(key)) {
                key[keylen++] = (unsigned char) n;
                p += 2;
            }
        } else {
            keylen = strlen(argv[6]);

            if (keylen > (int) sizeof(key)) {
                keylen = (int) sizeof(key);
            }

            memcpy(key, argv[6], keylen);
        }
    }

#if defined(_WIN32_WCE)
    filesize = fseek(fin, 0L, SEEK_END);
#else
#if defined(_WIN32)
    /*
     * Support large files (> 2Gb) on Win32
     */
    li_size.QuadPart = 0;
    li_size.LowPart  =
        SetFilePointer((HANDLE) _get_osfhandle(_fileno(fin)),
                       li_size.LowPart, &li_size.HighPart, FILE_END);

    if (li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR) {
        mbedtls_fprintf(stderr, "SetFilePointer(0,FILE_END) failed\n");
        goto exit;
    }

    filesize = li_size.QuadPart;
#else
    if ((filesize = lseek(fileno(fin), 0, SEEK_END)) < 0) {
        perror("lseek");
        goto exit;
    }
#endif
#endif

    if (fseek(fin, 0, SEEK_SET) < 0) {
        mbedtls_fprintf(stderr, "fseek(0,SEEK_SET) failed\n");
        goto exit;
    }

    md_size = mbedtls_md_get_size(md_info);
    cipher_block_size = mbedtls_cipher_get_block_size(&cipher_ctx);

    if (mode == MODE_ENCRYPT) {
        /*
         * Generate the initialization vector as:
         * IV = MD( filesize || filename )[0..15]
         */
        for (i = 0; i < 8; i++) {
            buffer[i] = (unsigned char) (filesize >> (i << 3));
        }

        p = argv[2];

        if (mbedtls_md_starts(&md_ctx) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_starts() returned error\n");
            goto exit;
        }
        if (mbedtls_md_update(&md_ctx, buffer, 8) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_update() returned error\n");
            goto exit;
        }
        if (mbedtls_md_update(&md_ctx, (unsigned char *) p, strlen(p))
            != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_update() returned error\n");
            goto exit;
        }
        if (mbedtls_md_finish(&md_ctx, digest) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_finish() returned error\n");
            goto exit;
        }

        memcpy(IV, digest, 16);

        /*
         * Append the IV at the beginning of the output.
         */
        if (fwrite(IV, 1, 16, fout) != 16) {
            mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 16);
            goto exit;
        }

        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset(digest, 0,  32);
        memcpy(digest, IV, 16);

        for (i = 0; i < 8192; i++) {
            if (mbedtls_md_starts(&md_ctx) != 0) {
                mbedtls_fprintf(stderr,
                                "mbedtls_md_starts() returned error\n");
                goto exit;
            }
            if (mbedtls_md_update(&md_ctx, digest, 32) != 0) {
                mbedtls_fprintf(stderr,
                                "mbedtls_md_update() returned error\n");
                goto exit;
            }
            if (mbedtls_md_update(&md_ctx, key, keylen) != 0) {
                mbedtls_fprintf(stderr,
                                "mbedtls_md_update() returned error\n");
                goto exit;
            }
            if (mbedtls_md_finish(&md_ctx, digest) != 0) {
                mbedtls_fprintf(stderr,
                                "mbedtls_md_finish() returned error\n");
                goto exit;
            }

        }

        if (mbedtls_cipher_setkey(&cipher_ctx, digest, cipher_info->key_bitlen,
                                  MBEDTLS_ENCRYPT) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_setkey() returned error\n");
            goto exit;
        }
        if (mbedtls_cipher_set_iv(&cipher_ctx, IV, 16) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_set_iv() returned error\n");
            goto exit;
        }
        if (mbedtls_cipher_reset(&cipher_ctx) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_reset() returned error\n");
            goto exit;
        }

        if (mbedtls_md_hmac_starts(&md_ctx, digest, 32) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_hmac_starts() returned error\n");
            goto exit;
        }

        /*
         * Encrypt and write the ciphertext.
         */
        for (offset = 0; offset < filesize; offset += cipher_block_size) {
            ilen = ((unsigned int) filesize - offset > cipher_block_size) ?
                   cipher_block_size : (unsigned int) (filesize - offset);

            if (fread(buffer, 1, ilen, fin) != ilen) {
                mbedtls_fprintf(stderr, "fread(%ld bytes) failed\n", (long) ilen);
                goto exit;
            }

            if (mbedtls_cipher_update(&cipher_ctx, buffer, ilen, output, &olen) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_cipher_update() returned error\n");
                goto exit;
            }

            if (mbedtls_md_hmac_update(&md_ctx, output, olen) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_hmac_update() returned error\n");
                goto exit;
            }

            if (fwrite(output, 1, olen, fout) != olen) {
                mbedtls_fprintf(stderr, "fwrite(%ld bytes) failed\n", (long) olen);
                goto exit;
            }
        }

        if (mbedtls_cipher_finish(&cipher_ctx, output, &olen) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_finish() returned error\n");
            goto exit;
        }
        if (mbedtls_md_hmac_update(&md_ctx, output, olen) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_hmac_update() returned error\n");
            goto exit;
        }

        if (fwrite(output, 1, olen, fout) != olen) {
            mbedtls_fprintf(stderr, "fwrite(%ld bytes) failed\n", (long) olen);
            goto exit;
        }

        /*
         * Finally write the HMAC.
         */
        if (mbedtls_md_hmac_finish(&md_ctx, digest) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_hmac_finish() returned error\n");
            goto exit;
        }

        if (fwrite(digest, 1, md_size, fout) != md_size) {
            mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", md_size);
            goto exit;
        }
    }

    if (mode == MODE_DECRYPT) {
        /*
         *  The encrypted file must be structured as follows:
         *
         *        00 .. 15              Initialization Vector
         *        16 .. 31              Encrypted Block #1
         *           ..
         *      N*16 .. (N+1)*16 - 1    Encrypted Block #N
         *  (N+1)*16 .. (N+1)*16 + n    Hash(ciphertext)
         */
        if (filesize < 16 + md_size) {
            mbedtls_fprintf(stderr, "File too short to be encrypted.\n");
            goto exit;
        }

        if (cipher_block_size == 0) {
            mbedtls_fprintf(stderr, "Invalid cipher block size: 0. \n");
            goto exit;
        }

        /*
         * Check the file size.
         */
        cipher_mode = cipher_info->mode;
        if (cipher_mode != MBEDTLS_MODE_GCM &&
            cipher_mode != MBEDTLS_MODE_CTR &&
            cipher_mode != MBEDTLS_MODE_CFB &&
            cipher_mode != MBEDTLS_MODE_OFB &&
            ((filesize - md_size) % cipher_block_size) != 0) {
            mbedtls_fprintf(stderr, "File content not a multiple of the block size (%u).\n",
                            cipher_block_size);
            goto exit;
        }

        /*
         * Subtract the IV + HMAC length.
         */
        filesize -= (16 + md_size);

        /*
         * Read the IV and original filesize modulo 16.
         */
        if (fread(buffer, 1, 16, fin) != 16) {
            mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", 16);
            goto exit;
        }

        memcpy(IV, buffer, 16);

        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset(digest, 0,  32);
        memcpy(digest, IV, 16);

        for (i = 0; i < 8192; i++) {
            if (mbedtls_md_starts(&md_ctx) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_starts() returned error\n");
                goto exit;
            }
            if (mbedtls_md_update(&md_ctx, digest, 32) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_update() returned error\n");
                goto exit;
            }
            if (mbedtls_md_update(&md_ctx, key, keylen) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_update() returned error\n");
                goto exit;
            }
            if (mbedtls_md_finish(&md_ctx, digest) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_finish() returned error\n");
                goto exit;
            }
        }

        if (mbedtls_cipher_setkey(&cipher_ctx, digest, cipher_info->key_bitlen,
                                  MBEDTLS_DECRYPT) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_setkey() returned error\n");
            goto exit;
        }

        if (mbedtls_cipher_set_iv(&cipher_ctx, IV, 16) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_set_iv() returned error\n");
            goto exit;
        }

        if (mbedtls_cipher_reset(&cipher_ctx) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_reset() returned error\n");
            goto exit;
        }

        if (mbedtls_md_hmac_starts(&md_ctx, digest, 32) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_hmac_starts() returned error\n");
            goto exit;
        }

        /*
         * Decrypt and write the plaintext.
         */
        for (offset = 0; offset < filesize; offset += cipher_block_size) {
            ilen = ((unsigned int) filesize - offset > cipher_block_size) ?
                   cipher_block_size : (unsigned int) (filesize - offset);

            if (fread(buffer, 1, ilen, fin) != ilen) {
                mbedtls_fprintf(stderr, "fread(%u bytes) failed\n",
                                cipher_block_size);
                goto exit;
            }

            if (mbedtls_md_hmac_update(&md_ctx, buffer, ilen) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_md_hmac_update() returned error\n");
                goto exit;
            }
            if (mbedtls_cipher_update(&cipher_ctx, buffer, ilen, output,
                                      &olen) != 0) {
                mbedtls_fprintf(stderr, "mbedtls_cipher_update() returned error\n");
                goto exit;
            }

            if (fwrite(output, 1, olen, fout) != olen) {
                mbedtls_fprintf(stderr, "fwrite(%ld bytes) failed\n", (long) olen);
                goto exit;
            }
        }

        /*
         * Verify the message authentication code.
         */
        if (mbedtls_md_hmac_finish(&md_ctx, digest) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_md_hmac_finish() returned error\n");
            goto exit;
        }

        if (fread(buffer, 1, md_size, fin) != md_size) {
            mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", md_size);
            goto exit;
        }

        /* Use constant-time buffer comparison */
        diff = 0;
        for (i = 0; i < md_size; i++) {
            diff |= digest[i] ^ buffer[i];
        }

        if (diff != 0) {
            mbedtls_fprintf(stderr, "HMAC check failed: wrong key, "
                                    "or file corrupted.\n");
            goto exit;
        }

        /*
         * Write the final block of data
         */
        if (mbedtls_cipher_finish(&cipher_ctx, output, &olen) != 0) {
            mbedtls_fprintf(stderr, "mbedtls_cipher_finish() returned error\n");
            goto exit;
        }

        if (fwrite(output, 1, olen, fout) != olen) {
            mbedtls_fprintf(stderr, "fwrite(%ld bytes) failed\n", (long) olen);
            goto exit;
        }
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    if (fin) {
        fclose(fin);
    }
    if (fout) {
        fclose(fout);
    }

    /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[6]. */
    for (i = 0; i < argc; i++) {
        mbedtls_platform_zeroize(argv[i], strlen(argv[i]));
    }

    mbedtls_platform_zeroize(IV,     sizeof(IV));
    mbedtls_platform_zeroize(key,    sizeof(key));
    mbedtls_platform_zeroize(buffer, sizeof(buffer));
    mbedtls_platform_zeroize(output, sizeof(output));
    mbedtls_platform_zeroize(digest, sizeof(digest));

    mbedtls_cipher_free(&cipher_ctx);
    mbedtls_md_free(&md_ctx);

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_CIPHER_C && MBEDTLS_MD_C && MBEDTLS_FS_IO */


// =============================== SHA512

#if !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_FS_IO)
int sha512_test(void)
{
    mbedtls_printf("MBEDTLS_MD_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit(0);
}
#else


static int generic_wrapper(const mbedtls_md_info_t *md_info, char *filename, unsigned char *sum)
{
    int ret = mbedtls_md_file(md_info, filename, sum);

    if (ret == 1) {
        mbedtls_fprintf(stderr, "failed to open: %s\n", filename);
    }

    if (ret == 2) {
        mbedtls_fprintf(stderr, "failed to read: %s\n", filename);
    }

    return ret;
}

static int generic_print(const mbedtls_md_info_t *md_info, char *filename)
{
    int i;
    unsigned char sum[MBEDTLS_MD_MAX_SIZE];

    if (generic_wrapper(md_info, filename, sum) != 0) {
        return 1;
    }

    for (i = 0; i < mbedtls_md_get_size(md_info); i++) {
        mbedtls_printf("%02x", sum[i]);
    }

    mbedtls_printf("  %s\n", filename);
    return 0;
}

static int generic_check(const mbedtls_md_info_t *md_info, char *filename)
{
    int i;
    size_t n;
    FILE *f;
    int nb_err1, nb_err2;
    int nb_tot1, nb_tot2;
    unsigned char sum[MBEDTLS_MD_MAX_SIZE];
    char line[1024];
    char diff;
#if defined(__clang_analyzer__)
    char buf[MBEDTLS_MD_MAX_SIZE * 2 + 1] = { };
#else
    char buf[MBEDTLS_MD_MAX_SIZE * 2 + 1];
#endif

    if ((f = fopen(filename, "rb")) == NULL) {
        mbedtls_printf("failed to open: %s\n", filename);
        return 1;
    }

    nb_err1 = nb_err2 = 0;
    nb_tot1 = nb_tot2 = 0;

    memset(line, 0, sizeof(line));

    n = sizeof(line);

    while (fgets(line, (int) n - 1, f) != NULL) {
        n = strlen(line);

        if (n < (size_t) 2 * mbedtls_md_get_size(md_info) + 4) {
            mbedtls_printf("No '%s' hash found on line.\n", mbedtls_md_get_name(md_info));
            continue;
        }

        if (line[2 * mbedtls_md_get_size(md_info)] != ' ' ||
            line[2 * mbedtls_md_get_size(md_info) + 1] != ' ') {
            mbedtls_printf("No '%s' hash found on line.\n", mbedtls_md_get_name(md_info));
            continue;
        }

        if (line[n - 1] == '\n') {
            n--; line[n] = '\0';
        }
        if (line[n - 1] == '\r') {
            n--; line[n] = '\0';
        }

        nb_tot1++;

        if (generic_wrapper(md_info, line + 2 + 2 * mbedtls_md_get_size(md_info), sum) != 0) {
            nb_err1++;
            continue;
        }

        nb_tot2++;

        for (i = 0; i < mbedtls_md_get_size(md_info); i++) {
            sprintf(buf + i * 2, "%02x", sum[i]);
        }

        /* Use constant-time buffer comparison */
        diff = 0;
        for (i = 0; i < 2 * mbedtls_md_get_size(md_info); i++) {
            diff |= line[i] ^ buf[i];
        }

        if (diff != 0) {
            nb_err2++;
            mbedtls_fprintf(stderr, "wrong checksum: %s\n", line + 66);
        }

        n = sizeof(line);
    }

    if (nb_err1 != 0) {
        mbedtls_printf("WARNING: %d (out of %d) input files could "
                       "not be read\n", nb_err1, nb_tot1);
    }

    if (nb_err2 != 0) {
        mbedtls_printf("WARNING: %d (out of %d) computed checksums did "
                       "not match\n", nb_err2, nb_tot2);
    }

    fclose(f);

    return nb_err1 != 0 || nb_err2 != 0;
}

int sha512_test(int argc, char *argv[])
{
    int ret = 1, i;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);

    if (argc < 2) {
        const int *list;

        mbedtls_printf("print mode:  generic_sum <mbedtls_md> <file> <file> ...\n");
        mbedtls_printf("check mode:  generic_sum <mbedtls_md> -c <checksum file>\n");

        mbedtls_printf("\nAvailable message digests:\n");
        list = mbedtls_md_list();
        while (*list) {
            md_info = mbedtls_md_info_from_type(*list);
            mbedtls_printf("  %s\n", mbedtls_md_get_name(md_info));
            list++;
        }

#if defined(_WIN32)
        mbedtls_printf("\n  Press Enter to exit this program.\n");
        fflush(stdout); getchar();
#endif

        mbedtls_exit(exit_code);
    }

    /*
     * Read the MD from the command line
     */
    md_info = mbedtls_md_info_from_string(argv[1]);
    if (md_info == NULL) {
        mbedtls_fprintf(stderr, "Message Digest '%s' not found\n", argv[1]);
        mbedtls_exit(exit_code);
    }
    if (mbedtls_md_setup(&md_ctx, md_info, 0)) {
        mbedtls_fprintf(stderr, "Failed to initialize context.\n");
        mbedtls_exit(exit_code);
    }

    ret = 0;
    if (argc == 4 && strcmp("-c", argv[2]) == 0) {
        ret |= generic_check(md_info, argv[3]);
        goto exit;
    }

    for (i = 2; i < argc; i++) {
        ret |= generic_print(md_info, argv[i]);
    }

    if (ret == 0) {
        exit_code = MBEDTLS_EXIT_SUCCESS;
    }

exit:
    mbedtls_md_free(&md_ctx);

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_MD_C && MBEDTLS_FS_IO */