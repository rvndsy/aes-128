#include <stdio.h>
#include <stdlib.h>
#include "filecrypto.h"
#include "aes.h"
#include "definitions.h"
#include "utils.h"

#define MAX_FILE_SIZE 4294967296

void padBuffer(byte * b, int dataEnd, int padSize) {
    b[dataEnd] = padSize;
    for (int i = padSize; i > 0; i--) {
        b[dataEnd+i] = padSize;
    }
}

byte *readFileToByteArray(FILE *fptr, long *fsize) {
    if (!fptr) {
        fprintf(stderr, "readFileToByteArray: Invalid file pointer");
        return NULL;
    }

    fseek(fptr, 0L, SEEK_END);

    *fsize = ftell(fptr);

    rewind(fptr);

    byte * fbuf;
    int difference = 16 - (*fsize % 16);
    fbuf = (byte*)malloc(*fsize+difference);

    size_t bytesRead = fread(fbuf, 1, *fsize, fptr);
    if (bytesRead != *fsize) {
        fprintf(stderr, "readFileToByteArray: Error, only %ld of %ld bytes successfully read", bytesRead, *fsize);
        free(fbuf);
        return NULL;
    }

    padBuffer(fbuf, *fsize, difference);

    *fsize += difference;

    return fbuf;
}

int writeByteArrayToFile(byte * fbuf, FILE * fptr, long fbufSize) {
    if (!fptr) {
        fprintf(stderr, "writeByteArrayToFile: Invalid file pointer");
        return 1;
    }

    rewind(fptr);

    fseek(fptr, 0L, SEEK_CUR);

    fwrite(fbuf, 1, fbufSize, fptr);

    return 0;
}

void encryptFile(FILE * fptrRead, FILE * fptrWrite, const byte * key, const byte * iv, uint8_t mode) {
    long fbufSize;
    byte * fbuf = readFileToByteArray(fptrRead, &fbufSize);

    if (fbuf == NULL) {
        fprintf(stderr, "encryptFile: Cannot read file into byte array");
        free(fbuf);
        return;
    }

    switch (mode) {
        case ECB: 
            encryptECB(fbuf, key, fbufSize);
            break;
        case CBC:
            encryptCBC(fbuf, key, iv, fbufSize);
            break;
    }

    writeByteArrayToFile(fbuf, fptrWrite, fbufSize);

    free(fbuf);
}

void decryptFile(FILE * fptrRead, FILE * fptrWrite, const byte * key, const byte * iv, uint8_t mode) {
    long fbufSize;
    byte * fbuf = readFileToByteArray(fptrRead, &fbufSize);

    if (fbuf == NULL) {
        fprintf(stderr, "encryptFile: Cannot read file into byte array");
        free(fbuf);
        return;
    }

    switch (mode) {
        case ECB: 
            decryptECB(fbuf, key, fbufSize);
            break;
        case CBC:
            decryptCBC(fbuf, key, iv, fbufSize);
            break;
    }

    writeByteArrayToFile(fbuf, fptrWrite, fbufSize);

    free(fbuf);
}
