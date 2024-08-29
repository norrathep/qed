
/* aes-file-encrypt.c
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

#if defined(HAVE_PBKDF2) && !defined(NO_PWDBASED)

int SizeCheck(int *size)
{
    int ret = 0;

    /* Use key size values (size/8) */
    if (*size == 128) {
        *size = AES_128_KEY_SIZE;
    }
    else if (*size == 192) {
        *size = AES_192_KEY_SIZE;
    }
    else if (*size == 256) {
        *size = AES_256_KEY_SIZE;
    }
    else {
        /* if the entered size does not match acceptable size */
        printf("Invalid AES key size\n");
        ret = -1080;
    }

    return ret;
}

/*
 * help message
 */
void help()
{
    printf("\n~~~~~~~~~~~~~~~~~~~~|Help|~~~~~~~~~~~~~~~~~~~~~\n\n");
    printf("Usage: ./aes-file-encrypt <-option> <KeySize> <-i file.in> "
        "<-o file.out>\n\n");
    printf("Options\n");
    printf("-d    Decryption\n-e    Encryption\n-h    Help\n");
}

int main(int argc, char** argv)
{

    const char* in;
    const char* out;
    FILE*  inFile = NULL;
    FILE*  outFile = NULL;

    int    option;    /* choice of how to run program */
    int    ret = 0;   /* return value */
    int    size = 0;
    int    inCheck = 0;
    int    outCheck = 0;
    char   choice = 'n';

    while ((option = getopt(argc, argv, "d:e:i:o:h")) != -1) {
        switch (option) {
            case 'd': /* if entered decrypt */
                size = atoi(optarg);
                ret = SizeCheck(&size);
                choice = 'd';
                break;
            case 'e': /* if entered encrypt */
                size = atoi(optarg);
                ret = SizeCheck(&size);
                choice = 'e';
                break;
            case 'h': /* if entered 'help' */
                help();
                break;
            case 'i': /* input file */
                in = optarg;
                inCheck = 1;
                inFile = fopen(in, "r");
                break;
            case 'o': /* output file */
                out = optarg;
                outCheck = 1;
                outFile = fopen(out, "w");
                break;
            case '?':
                if (optopt) {
                    printf("Ending Session\n");
                    return -111;
                }
            default:
                abort();
        }
    }
    
    ret = aes_test(option, ret, size, inCheck, outCheck, choice, inFile, outFile);

    return ret;
}

#else
int main()
{
    printf("pwdbased and HAVE_PBKDF2 not compiled in\n");
    return 0;
}
#endif
