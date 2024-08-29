/* dh-pg-ka.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include "libqedtest.h"

#define MAX_DH_BITS       4096
#define MAX_DH_Q_SIZE     256
#define DEF_DH_SIZE       2048
#define DEF_KA_CHECKS     512
#define DEF_PARAMS_GEN    8

int load_dh_params(DhKey* key1, DhKey* key2, WC_RNG* rng)
{
    int ret;

    ret = wc_DhSetCheckKey(key1, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g),
                           dh_q, sizeof(dh_q), 0, rng);
    if (ret == 0) {
        ret = wc_DhSetCheckKey(key2, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g),
                               NULL, 0, 0, rng);
    }

    return ret;
}

/* Print the buffer as bytes */
void print_data(char *name, unsigned char *data, int len)
{
    int i;
    printf("static unsigned char %s[%d] = {\n", name, len);
    for (i = 0; i < len; i++) {
        if ((i & 7) == 0) {
            printf("    ");
        }
        printf("0x%02x, ", data[i]);
        if ((i & 7) == 7) {
            printf("\n");
        }
    }
    if ((i & 7) != 0) {
        printf("\n");
    }
    printf("};\n");
}

/* Print the DH parameters */
void print_dh(DhKey *key)
{
    int ret;
    static unsigned char p[MAX_DH_BITS/8];
    static unsigned char g[MAX_DH_BITS/8];
    static unsigned char q[MAX_DH_Q_SIZE/8];
    word32 p_len, g_len, q_len;

    /* Export the DH parameters */
    p_len = sizeof(p);
    g_len = sizeof(g);
    q_len = sizeof(q);
    ret = wc_DhExportParamsRaw(key, p, &p_len, q, &q_len, g, &g_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to export parameters\n");
        return;
    }

    /* Print out parameters. */
    printf("\n");
    print_data("dh_p", p, p_len);
    print_data("dh_g", g, g_len);
    print_data("dh_q", q, q_len);
}

int dh_test()
{
    int ec = 0;
    int ret;
    static DhKey key1, key2;
    const DhParams *dhparams;
    WC_RNG rng;
    static unsigned char p[MAX_DH_BITS/8];
    static unsigned char g[MAX_DH_BITS/8];
    static unsigned char q[MAX_DH_Q_SIZE/8];
    word32 p_len, g_len, q_len;
    static unsigned char priv1[MAX_DH_BITS/8];
    static unsigned char priv2[MAX_DH_BITS/8];
    word32 priv1_len, priv2_len;
    static unsigned char pub1[MAX_DH_BITS/8];
    static unsigned char pub2[MAX_DH_BITS/8];
    word32 pub1_len, pub2_len;
    static unsigned char secret1[MAX_DH_BITS/8];
    static unsigned char secret2[MAX_DH_BITS/8];
    word32 secret1_len, secret2_len;
    int i, cnt;
    int bits = DEF_DH_SIZE;
    int numParams = DEF_PARAMS_GEN;
    int checks = DEF_KA_CHECKS;
    int gen_params = 1;
    int load_params = 0;

    /* Initialise a random number generator for generation */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize random\n");
        return 1;
    }

    /* Initialise DH key */
    ret = wc_InitDhKey(&key1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        fprintf(stderr, "Failed to initialize DH key\n");
        return 1;
    }
    /* Initialise DH key for key agreement */
    ret = wc_InitDhKey(&key2);
    if (ret != 0) {
        wc_FreeDhKey(&key1);
        wc_FreeRng(&rng);
        fprintf(stderr, "Failed to initialize DH key\n");
        return 1;
    }

    /* Perform operations for specified number of parameters */
    for (cnt = 0; cnt < numParams; cnt++) {
        if (gen_params) {
            fprintf(stderr, "%d: ", cnt + 1);

            /* Generate a set of DH parameters */
            ret = wc_DhGenerateParams(&rng, bits, &key1);
            if (ret != 0) {
                fprintf(stderr, "Failed to generate DH params\n");
                fprintf(stderr, "%d\n", ret);
                ec = 1;
                break;
            }

            /* Export DH parameters */
            p_len = sizeof(p);
            q_len = sizeof(q);
            g_len = sizeof(g);
            ret = wc_DhExportParamsRaw(&key1, p, &p_len, q, &q_len, g, &g_len);
            if (ret != 0) {
                fprintf(stderr, "Failed to export DH params\n");
                ec = 1;
                break;
            }

            /* Set only p and g and check key */
            ret = wc_DhSetCheckKey(&key2, p, p_len, g, g_len, NULL, 0, 0, &rng);
            if (ret != 0) {
                fprintf(stderr, "Failed to set/check DH params\n");
                ec = 1;
                break;
            }
        }
        else if (!load_params) {
            /* Set p and g - trust key */
            ret = wc_DhSetCheckKey(&key2, dhparams->p, dhparams->p_len,
                                   dhparams->g, dhparams->g_len, NULL, 0, 1,
                                   &rng);
            if (ret != 0) {
                fprintf(stderr, "Failed to set/check DH params\n");
                ec = 1;
                break;
            }
        }
        else {
            /* Set p and g - trust key */
            ret = load_dh_params(&key1, &key2, &rng);
            if (ret != 0) {
                fprintf(stderr, "Failed to load DH params\n");
                ec = 1;
                break;
            }
        }

        /* Perform a number of key agreements with parameters */
        for (i = 0; i < checks; i++) {
            /* Generate first peer's key */
            priv1_len = sizeof(priv1);
            pub1_len = sizeof(pub1);
            ret = wc_DhGenerateKeyPair(&key2, &rng, priv1, &priv1_len, pub1,
                                       &pub1_len);
            if (ret != 0) {
                fprintf(stderr, "Failed to generate key pair\n");
                print_dh(&key1);
                ec = 1;
                break;
            }
    
            /* Generate second peer's key */
            priv2_len = sizeof(priv2);
            pub2_len = sizeof(pub2);
            ret = wc_DhGenerateKeyPair(&key2, &rng, priv2, &priv2_len, pub2,
                                       &pub2_len);
            if (ret != 0) {
                fprintf(stderr, "Failed to generate key pair\n");
                print_dh(&key1);
                ec = 1;
                break;
            }
    
            /* Calculate first peer's secret */
            secret1_len = sizeof(secret1);
            ret = wc_DhAgree(&key2, secret1, &secret1_len, priv1, priv1_len,
                             pub2, pub2_len);
            if (ret != 0) {
                fprintf(stderr, "Failed to calculate secret\n");
                print_dh(&key1);
                ec = 1;
                break;
            }
    
            /* Calculate second peer's secret */
            secret2_len = sizeof(secret2);
            ret = wc_DhAgree(&key2, secret2, &secret2_len, priv2, priv2_len,
                             pub1, pub1_len);
            if (ret != 0) {
                fprintf(stderr, "Failed to calculate secret\n");
                print_dh(&key1);
                ec = 1;
                break;
            }

            /* Secret's should be the same */
            if ((secret1_len != secret2_len) || (XMEMCMP(secret1, secret2,
                                                         secret1_len) != 0)) {
                fprintf(stderr, "Secrets different\n");
                print_dh(&key1);
                ec = 1;
                break;
            }
    
            fprintf(stderr, ".");
        }

        /* Error  during key generation or key agreement */
        if (ec) {
            break;
        }

        fprintf(stderr, "\n");
    }

    /* Free allocated items */
    wc_FreeDhKey(&key1);
    wc_FreeDhKey(&key1);
    wc_FreeRng(&rng);
    return 0;
}

// ========================= AES 

#define SALT_SIZE 8

/*
 * Makes a cryptographically secure key by stretching a user entered key
 */
int GenerateKey(WC_RNG* rng, byte* key, int size, byte* salt, int pad)
{
    int ret;

    ret = wc_RNG_GenerateBlock(rng, salt, SALT_SIZE);
    if (ret != 0)
        return -1020;

    if (pad == 0)
        salt[0] = 0;
    /* salt[0] == 0 should only be used if pad == 0 */
    else if (salt[0] == 0)
        salt[0] = 1;

    /* stretches key */
    ret = wc_PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096,
        size, WC_SHA256);
    if (ret != 0)
        return -1030;

    return 0;
}

/*
 * Encrypts a file using AES
 */
int AesEncrypt(Aes* aes, byte* key, int size, FILE* inFile, FILE* outFile)
{
    WC_RNG     rng;
    byte    iv[AES_BLOCK_SIZE];
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     i = 0;
    int     ret = 0;
    int     inputLength;
    int     length;
    int     padCounter = 0;

    fseek(inFile, 0, SEEK_END);
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    length = inputLength;
    /* pads the length until it evenly matches a block / increases pad number*/
    while (length % AES_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    input = malloc(length);
    output = malloc(length);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1030;
    }

    /* reads from inFile and writes whatever is there to the input array */
    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = inputLength; i < length; i++) {
        /* pads the added characters with the number of pads */
        input[i] = padCounter;
    }

    ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    if (ret != 0)
        return -1020;

    /* stretches key to fit size */
    ret = GenerateKey(&rng, key, size, salt, padCounter);
    if (ret != 0)
        return -1040;

    /* inits aes structure */
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("AesInit returned: %d\n", ret);
        return -1001;
    }

    /* sets key */
    ret = wc_AesSetKey(aes, key, size, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("SetKey returned: %d\n", ret);
        return -1001;
    }

    /* encrypts the message to the output based on input length + padding */
    ret = wc_AesCbcEncrypt(aes, output, input, length);
    if (ret != 0)
        return -1005;

    /* writes to outFile */
    fwrite(salt, 1, SALT_SIZE, outFile);
    fwrite(iv, 1, AES_BLOCK_SIZE, outFile);
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, length);
    memset(output, 0, length);
    memset(key, 0, size);
    free(input);
    free(output);
    free(key);
    fclose(inFile);
    fclose(outFile);
    wc_FreeRng(&rng);

    return ret;
}

/*
 * Decrypts a file using AES
 */
int AesDecrypt(Aes* aes, byte* key, int size, FILE* inFile, FILE* outFile)
{
    WC_RNG     rng;
    byte    iv[AES_BLOCK_SIZE];
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     i = 0;
    int     ret = 0;
    int     length;
    int     aSize;

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    aSize = length;

    input = malloc(aSize);
    output = malloc(aSize);

    wc_InitRng(&rng);

    /* reads from inFile and writes whatever is there to the input array */
    ret = fread(input, 1, length, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = 0; i < SALT_SIZE; i++) {
        /* finds salt from input message */
        salt[i] = input[i];
    }
    for (i = SALT_SIZE; i < AES_BLOCK_SIZE + SALT_SIZE; i++) {
        /* finds iv from input message */
        iv[i - SALT_SIZE] = input[i];
    }

    /* replicates old key if keys match */
    ret = wc_PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096,
        size, WC_SHA256);
    if (ret != 0)
        return -1050;

    /* inits aes structure */
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("AesInit returned: %d\n", ret);
        return -1001;
    }

    /* sets key */
    ret = wc_AesSetKey(aes, key, size, iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("SetKey returned: %d\n", ret);
        return -1002;
    }

    /* change length to remove salt/iv block from being decrypted */
    length -= (AES_BLOCK_SIZE + SALT_SIZE);
    for (i = 0; i < length; i++) {
        /* shifts message: ignores salt/iv on message*/
        input[i] = input[i + (AES_BLOCK_SIZE + SALT_SIZE)];
    }
    /* decrypts the message to output based on input length + padding*/
    ret = wc_AesCbcDecrypt(aes, output, input, length);
    if (ret != 0)
        return -1006;

    if (salt[0] != 0) {
        /* reduces length based on number of padded elements */
        length -= output[length-1];
    }
    /* writes output to the outFile based on shortened length */
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, aSize);
    memset(output, 0, aSize);
    memset(key, 0, size);
    free(input);
    free(output);
    free(key);
    fclose(inFile);
    fclose(outFile);
    wc_FreeRng(&rng);

    return 0;
}

/*
 * temporarily disables echoing in terminal for secure key input
 */
int NoEcho(char* key, int size)
{
    struct termios oflags, nflags;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error: tcsetattr failed to disable terminal echo\n");
        return -1060;
    }

    printf("Unique Password: ");
    if (fgets(key, size, stdin) == NULL) {
        printf("Error: fgets failed to retrieve secure key input\n");
        return -1070;
    }

    key[strlen(key) - 1] = 0;

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error: tcsetattr failed to enable terminal echo\n");
        return -1080;
    }
    return 0;
}

int aes_test(int option, int ret, int size, int inCheck, int outCheck, char choice, FILE*  inFile, FILE*  outFile) {

    Aes    aes;
    byte*  key;       /* user entered key */

    if (inCheck == 0 || outCheck == 0) {
            printf("Must have both input and output file");
            printf(": -i filename -o filename\n");
    }
    else if (ret == 0 && choice != 'n' && inFile != NULL) {
        key = malloc(size);    /* sets size memory of key */
        ret = NoEcho((char*)key, size);
        if (choice == 'e')
            AesEncrypt(&aes, key, size, inFile, outFile);
        else if (choice == 'd')
            AesDecrypt(&aes, key, size, inFile, outFile);
    }
    else if (choice == 'n') {
        printf("Must select either -e[128, 192, 256] or -d[128, 192, 256] \
                for encryption and decryption\n");
        ret = -110;
    }

    return ret;
}


// =========================================== RSA ===========================================

static void print_buf(char *str, byte *buf, int blen)
{
   int i, j;

   printf("%s\n", str);
   for (i = 0, j = 0; i < blen; i++)
   {
      printf("%02X ", *buf++);
      if (++j == 16)
      {
         j = 0;
         printf("\n");
      }
   }
   printf("\n");
}

int rsa_test()
{
    int ret = 0;
    WC_RNG rng;
    byte DER_buf[2048]; word32 DER_len = 0;
    byte Sig_buf[SIGNED_LEN]; word32 Sig_len = sizeof(Sig_buf);
    byte Hash_buf[SHA1_HASH_LEN]; word32 Hash_len = sizeof(Hash_buf);
    byte Digest_buf[SHA1_HASH_LEN+DATA_BLOCK_LEN]; word32 Digest_len = sizeof(Digest_buf);
    byte DigestVer_buf[SHA1_HASH_LEN+DATA_BLOCK_LEN]; word32 DigestVer_len = sizeof(DigestVer_buf);
    word32 inOutIdx=0;
    RsaKey rsakey;
    byte pemPublic = 0;
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA;
    enum wc_SignatureType sig_type = WC_SIGNATURE_TYPE_RSA_W_ENC;

    /* Create input data (44 bytes) */
    print_buf("Digest Input Data:", Digest_given, DATA_BLOCK_LEN);

    /* Init */
    wc_InitRng(&rng);

    /* Init Rsa Key */
    wc_InitRsaKey(&rsakey, NULL);

    XMEMSET(DER_buf, 0, sizeof(DER_buf));
    
#ifndef DEMO_RSA_VERIFY_ONLY
    ret = wc_KeyPemToDer((const byte*)privPemKey, strlen(privPemKey), 
        DER_buf, sizeof(DER_buf), NULL);
    if (ret < 0)
#endif
    {
        pemPublic = 1;

#ifdef WOLFSSL_CERT_EXT
        /* Needs WOLFSSL_CERT_EXT defined or --enable-certgen --enable-certext  */
        ret = wc_PubKeyPemToDer((const byte*)pubPemKey, strlen(pubPemKey), 
            DER_buf, sizeof(DER_buf));
#else
        ret = 0; /* NOT_COMPILED_IN */
#endif
    }
    if (ret >= 0) {
        DER_len = ret;
    }
    printf("Key Pem to Der ret %d\n", ret);

    if (ret < 0) goto exit;
    if (DER_len > 0) {
        printf("DER_len = %d DER_buf:\n", DER_len);
        print_buf("DER:", DER_buf, DER_len);
    }

    /* PEM key selection */
    if (!pemPublic) {
        ret = wc_RsaPrivateKeyDecode(DER_buf, &inOutIdx, &rsakey, DER_len);
    }
    else {
        /* Three Examples for loading an RSA public key */

        /* 1. Decode DER key */
        if (DER_len > 0) {
            ret = wc_RsaPublicKeyDecode(DER_buf, &inOutIdx, &rsakey, DER_len);
        }
        else {
        #if 1
            /* 2. Decode Raw: Example for loading RSA public key with modulus and exponenet only */
            ret = wc_RsaPublicKeyDecodeRaw(pubKeyModulus, sizeof(pubKeyModulus), 
                pubKeyExponent, sizeof(pubKeyExponent), &rsakey);
        #else
            /* 3. Manual Math: Manually setting with math API's */
            ret = mp_set_int(&rsakey.e, pubKeyExponentLong);
            if (ret == 0) {
                ret = mp_read_unsigned_bin(&rsakey.n, pubKeyModulus, 
                    sizeof(pubKeyModulus));
            }
        #endif
        }
    }
    printf("decode %s key =%d\n", pemPublic ? "public" : "private", ret);

    /* Get signature length and allocate buffer */
    ret = wc_SignatureGetSize(sig_type, &rsakey, sizeof(rsakey));
    printf("Sig Len: %d\n", ret);
    if (ret < 0) goto exit;
    Sig_len = ret;

    /* Get Hash length */
    ret = wc_HashGetDigestSize(hash_type);
    printf("Hash Digest Len: %d\n", ret);
    if (ret < 0) goto exit;
    Hash_len = ret;

    /* Hash digest with SHA1 */
    ret = wc_Hash(hash_type, Digest_given, sizeof(Digest_given), Hash_buf, Hash_len);
    printf("Digest SHA1 Hash: %d\n", ret);
    if (ret < 0) goto exit;
    print_buf("Digest Output 20 Data:", Hash_buf, Hash_len);

    /* Add ASN digest info header */
    ret = wc_EncodeSignature(Digest_buf, Hash_buf, Hash_len, SHAh);
    printf("Digest Header: %d\n", ret);
    if (ret <= 0) goto exit;
    Digest_len = ret;
    print_buf("Signed data results:", Digest_buf, Digest_len);

    if (!pemPublic) {
        /* Perform hash and sign to create signature */
        ret = wc_RsaSSL_Sign(Digest_buf, Digest_len, Sig_buf, Sig_len, &rsakey, &rng);
        printf("RSA Sign Result: %d\n", ret);
        if (ret < 0) goto exit;
        Sig_len = ret;

        print_buf("RSA Sign Data:", Sig_buf, Sig_len);

        ret = wc_SignatureGenerate(hash_type, sig_type, 
            Digest_given, sizeof(Digest_given),
            Sig_buf, &Sig_len,
            &rsakey, sizeof(rsakey), &rng);
        printf("Sig Generation: ret %d, Sig_len=%d\n", ret, Sig_len);
        print_buf("Sign Data:", Sig_buf, Sig_len);

        /* Verify against expected signature */
        print_buf("Expected Signature:", expected_signed_results, sizeof(expected_signed_results));
        if (XMEMCMP(Sig_buf, expected_signed_results, Sig_len) == 0) {
            printf("Signatures match!\n");
        }
        else {
            printf("Signature invalid!\n");
        }
    }
    else {
        /* Use digest for RSA verify */
        ret = wc_RsaSSL_Verify(expected_signed_results, sizeof(expected_signed_results), 
            DigestVer_buf, DigestVer_len, &rsakey);
        if (ret != Digest_len || XMEMCMP(DigestVer_buf, Digest_buf, Digest_len) != 0) {
            printf("RSA Verify Failed! %d\n", ret);
        }
        else {
            printf("RSA Verify Success!\n");
            ret = 0;
        }
        print_buf("Expected Verify Data:", DigestVer_buf, DigestVer_len);
        print_buf("RSA Verify Data:", Digest_buf, Digest_len);

        if (ret == 0) {
            ret = wc_SignatureVerify(hash_type, sig_type, 
                Digest_given, sizeof(Digest_given),
                expected_signed_results, sizeof(expected_signed_results),
                &rsakey, sizeof(rsakey));
            printf("Sig Verify: %s (%d)\n", (ret == 0) ? "Pass" : "Fail", ret);

            /* Example for validating hash directly */
            ret = wc_SignatureVerifyHash(hash_type, sig_type, 
                Digest_buf, Digest_len,
                expected_signed_results, sizeof(expected_signed_results),
                &rsakey, sizeof(rsakey));
            printf("Sig Verify Hash: %s (%d)\n", (ret == 0) ? "Pass" : "Fail", ret);
        }
    }

exit:
    wc_FreeRsaKey(&rsakey);
    wc_FreeRng(&rng);
    return 0;
}

// ============================== ECDSA
int ecdsa_test()
{
    int ret = 0;
    ret = do_sig_ver_test(ECC_KEY_SIZE_112);
    CHECK_RET(ret, 0, finished, "112 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_128);
    CHECK_RET(ret, 0, finished, "128 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_160);
    CHECK_RET(ret, 0, finished, "160 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_192);
    CHECK_RET(ret, 0, finished, "192 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_224);
    CHECK_RET(ret, 0, finished, "224 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_239);
    CHECK_RET(ret, 0, finished, "239 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_256);
    CHECK_RET(ret, 0, finished, "256 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_320);
    CHECK_RET(ret, 0, finished, "320 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_384);
    CHECK_RET(ret, 0, finished, "384 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_512);
    CHECK_RET(ret, 0, finished, "512 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_521);
    CHECK_RET(ret, 0, finished, "521 test");
finished:
    return ret;
}

int do_sig_ver_test(int eccKeySz)
{
    int ret;
    /* sha256 hash of the string "A 32-bit string to test signing" */
    unsigned char hash[32] = {
                                0x3b, 0x07, 0x54, 0x5c, 0xfd, 0x4f, 0xb7, 0xb5,
                                0xaf, 0xa7, 0x7a, 0x25, 0x33, 0xa5, 0x50, 0x70,
                                0x4a, 0x65, 0x3e, 0x72, 0x7e, 0xcd, 0xd4, 0x5b,
                                0x1b, 0x36, 0x96, 0x96, 0xca, 0x4f, 0x9b, 0x6f
                              };
    ecc_key key;
    byte* sig = NULL; // get rid of this magic number
    WC_RNG rng;
    int verified = 0;

    /*
     * for odd curve sizes account for mod EG:
     * Case 1) curve field of 256:
     *                 (256/8) + (256%8 != 0 ? 1:0) == 32 + 0 = 32
     *
     * Case 2) curve field of 521:
     *                 (521/8 = 65.125 (rounds to 65) + (521%8 != 0 ? 1:0) ==
                                                                    65 + 1 = 66
     *
     * Algorithm: (C / B) + (C % B != 0 ? 1:0)
     *
     * This remainder is a natural result of the calculation:
     * Algorithm: (C / (B-1)) / (B)
     */
    int byteField = (eccKeySz + (BYTE_SZ - 1)) / BYTE_SZ;
    word32 maxSigSz = ECC_MAX_SIG_SIZE;

    printf("Key size is %d, byteField = %d\n", eccKeySz, byteField);

    sig = (byte*) XMALLOC(maxSigSz * sizeof(byte), NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);

    if (sig == NULL) {
        printf("Failed to allocate sig buff\n");
        return -1001;
    }

    wolfCrypt_Init();


    ret = wc_ecc_init(&key);
    CHECK_RET(ret, 0, sig_done, "wc_ecc_init()");

    ret = wc_InitRng(&rng);
    CHECK_RET(ret, 0, key_done, "wc_InitRng()");

    ret = wc_ecc_make_key(&rng, byteField, &key);
    CHECK_RET(ret, 0, rng_done, "wc_ecc_make_key()");

    ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &maxSigSz, &rng, &key);
    CHECK_RET(ret, 0, rng_done, "wc_ecc_sign_hash()");

#ifdef SHOW_SIGS_IN_EXAMPLE
    hexdump(sig, maxSigSz, 16);
#endif

    ret = wc_ecc_verify_hash(sig, maxSigSz, hash, sizeof(hash), &verified,
                             &key);
    CHECK_RET(ret, 0, rng_done, "wc_ecc_verify_hash()");
    CHECK_RET(verified, 1, rng_done, "verification check");

    printf("Successfully verified signature w/ ecc key size %d!\n", eccKeySz);

rng_done:
    wc_FreeRng(&rng);
key_done:
    wc_ecc_free(&key);
sig_done:
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#ifdef SHOW_SIGS_IN_EXAMPLE
static void hexdump(const void *buffer, word32 len, byte cols)
{
   word32 i;

   for (i = 0; i < len + ((len % cols) ? (cols - len % cols) : 0); i++) {
      /* print hex data */
      if (i < len)
         printf("%02X ", ((byte*)buffer)[i] & 0xFF);

      if (i % cols == (cols - 1))
         printf("\n");
   }
}
#endif


void sha512_test(FILE* inputStream, int fileLength) {
    int ret = -1;
    wc_Sha512 sha512;
    byte  hash[WC_SHA512_DIGEST_SIZE];
    byte  rawInput[CHUNK_SIZE];

    int i, chunkSz;

    ret = wc_InitSha512(&sha512);

    if (ret != 0) {
        printf("Failed to initialize sha structure\n");
        fclose(inputStream);
    }

    /* Loop reading a block at a time, finishing with any excess */
    for (i = 0; i < fileLength; i += CHUNK_SIZE) {
        chunkSz = CHUNK_SIZE;
        if (chunkSz > fileLength - i)
            chunkSz = fileLength - i;

        ret = fread(rawInput, 1, chunkSz, inputStream);
        if (ret != chunkSz) {
            printf("ERROR: Failed to read the appropriate amount\n");
            ret = -1;
            break;
        }

        ret = wc_Sha512Update(&sha512, rawInput, chunkSz);
        if (ret != 0) {
            printf("Failed to update the hash\n");
            break;
        }
    }

    if (ret == 0) {
        ret = wc_Sha512Final(&sha512, hash);
    }
    if (ret != 0) {
        printf("ERROR: Hash operation failed");
    }
    else {
        printf("Hash result is: ");
        for (i = 0; i < WC_SHA512_DIGEST_SIZE; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }

    fclose(inputStream);
    wc_Sha512Free(&sha512);
}