/* sha512-hash.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include "libqedtest.h"

#ifndef NO_SHA512
void usage(void)
{
    printf("./sha512-hash <file to hash>\n");
    exit(-99);
}
#endif

int main(int argc, char** argv)
{
#ifndef NO_SHA512
    FILE* inputStream;
    char* fName = NULL;
    int fileLength = 0;

    if (argc < 2)
        usage();
    fName = argv[1];
    printf("Hash input file %s\n", fName);

    inputStream = fopen(fName, "rb");
    if (inputStream == NULL) {
        printf("ERROR: Unable to open file\n");
        return -1;
    }

    /* find length of the file */
    fseek(inputStream, 0, SEEK_END);
    fileLength = (int) ftell(inputStream);
    fseek(inputStream, 0, SEEK_SET);

    sha512_test(inputStream, fileLength);
#else
    printf("Please enable sha512 (--enable-sha512) in wolfCrypt\n");
#endif
    return 0;
}
