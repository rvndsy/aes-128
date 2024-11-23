#include <stdlib.h>
#include <string.h>
#include "filecrypt.h"
#include "definitions.h"
#include "utils.h"

static void (*operationModeFunc)(filecrypt_ctx *, byte *);

static unsigned long fsizeInBytes, bufferDataEnd, bytesWritten;
static unsigned int stateSize;
static unsigned char isFirstBlock = 1, isFinalBlock = 0;
static byte * carryOverBuffer, * copyBuffer;

void prepareFileCtx(filecrypt_ctx *fileCtx, cipher_ctx *cctx,
                    unsigned char operationMode, long readFileBlockSize) {
    fileCtx->cipherCtx = cctx;
    fileCtx->operationMode = operationMode;
    fileCtx->readFileBlockSize = readFileBlockSize;
}

void addPadding(filecrypt_ctx * fileCtx, byte *buf) {
    byte padSize = stateSize - bufferDataEnd % stateSize;
    for (size_t i = 0; i < padSize; i++) {
        buf[bufferDataEnd + i] = padSize;
    }
    bufferDataEnd += padSize;
}

void xorByteArrays(byte *a, const byte *b, int length) {
    for (int i = 0; i < length; i++) {
        a[i] ^= b[i];
    }
}

unsigned long readFileSize(FILE *fptr) {
    if (!fptr) {
        fprintf(stderr, "readFileToByteArray: Invalid file pointer");
        return 0;
    }

    fseek(fptr, 0L, SEEK_END);
    long fsize = ftell(fptr);
    rewind(fptr);

    if (fsize == 0) {
        fprintf(stderr, "encryptFile: Error reading file size");
        return 0;
    }

    return fsize;
}

void encryptECB(filecrypt_ctx *fileCtx, byte *buffer) {
    if (isFinalBlock) {
        addPadding(fileCtx ,buffer);
    }
    for (long i = 0; i < bufferDataEnd; i += stateSize) {
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, &buffer[i]);
    }
}

void decryptECB(filecrypt_ctx *fileCtx, byte *buffer) {
    for (long i = 0; i < bufferDataEnd; i += stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, &buffer[i]);
    }
    if (isFinalBlock) {
        bufferDataEnd -= buffer[bufferDataEnd - 1];
    }
}

void encryptCBC(filecrypt_ctx *fileCtx, byte *buffer) {
    if (isFirstBlock) {
        xorByteArrays(buffer, fileCtx->cipherCtx->iv, stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer);
        isFirstBlock = 0;
    } else {
        xorByteArrays(buffer, carryOverBuffer, stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer);
    }

    if (isFinalBlock) {
        addPadding(fileCtx ,buffer);
    }

    for (long i = 16; i < bufferDataEnd; i += stateSize) {
        xorByteArrays(buffer+i, buffer+i-stateSize, stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer+i);
    }

    memcpy(carryOverBuffer, buffer+bufferDataEnd-stateSize, stateSize);
}

void decryptCBC(filecrypt_ctx *fileCtx, byte *buffer) {
    if (isFirstBlock) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer);
        xorByteArrays(buffer, fileCtx->cipherCtx->iv, stateSize);
        isFirstBlock = 0;
    } else {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer);
        xorByteArrays(buffer, carryOverBuffer, stateSize);
    }

    for (long i = 16; i < bufferDataEnd; i += stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer+i);
        xorByteArrays(buffer+i, copyBuffer+i-stateSize, stateSize);
    }
    if (isFinalBlock) {
        bufferDataEnd -= buffer[bufferDataEnd - 1];
        return;
    }
    memcpy(carryOverBuffer, copyBuffer+bufferDataEnd-stateSize, stateSize);
}

void fileCipher(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile,
                unsigned char cipherMode) {
    if (fileCtx->readFileBlockSize < stateSize) {
        fprintf(stderr, "fencryptECB: Read block size cannot be smaller than the "
                "cipher state size");
        return;
    }

    fsizeInBytes = readFileSize(readFile);

    if (fileCtx->readFileBlockSize > fsizeInBytes) {
        fprintf(stdout, "fsizeInBytes: readFileBlockSize %ld is larger than the file size in bytes %ld",
                fileCtx->readFileBlockSize, fsizeInBytes);
    }

    byte *buffer = (byte *)malloc(sizeof(byte) * fileCtx->readFileBlockSize);

    if (!buffer) {
        fprintf(stderr, "fencryptECB: Failed to allocate buffer");
        return;
    }

    long blockCount = (fsizeInBytes / fileCtx->readFileBlockSize) + 1;

    stateSize = fileCtx->cipherCtx->stateSize;

    switch (cipherMode | fileCtx->operationMode) {
        case (ENCRYPT | ECB):
            operationModeFunc = encryptECB;
            break;
        case (DECRYPT | ECB):
            operationModeFunc = decryptECB;
            break;
        case (ENCRYPT | CBC):
            operationModeFunc = encryptCBC;
            carryOverBuffer = malloc(sizeof(byte) * stateSize);
            break;
        case (DECRYPT | CBC):
            operationModeFunc = decryptCBC;
            copyBuffer = malloc(sizeof(byte) * fileCtx->readFileBlockSize);
            carryOverBuffer = malloc(sizeof(byte) * stateSize);
            break;
    }

    if (fileCtx->operationMode != ENCRYPT) {
        isFirstBlock = 1;
    } 

    for (int curBlock = 1; curBlock <= blockCount; curBlock++) {
        bufferDataEnd = fread(buffer, sizeof(byte), fileCtx->readFileBlockSize, readFile);

        if (copyBuffer != NULL) {
            memcpy(copyBuffer, buffer, fileCtx->readFileBlockSize);
        }

        isFinalBlock = (curBlock == blockCount);

        operationModeFunc(fileCtx, buffer);

        bytesWritten = fwrite(buffer, sizeof(byte), bufferDataEnd, writeFile);
    }

    isFinalBlock = 0;
    free(buffer);
    if (carryOverBuffer != NULL) {
        free(carryOverBuffer);
    }
    if (copyBuffer != NULL) {
        free(copyBuffer);
    }
}

void encryptFile(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile) {
    fileCipher(fileCtx, readFile, writeFile, ENCRYPT);
}

void decryptFile(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile) {
    fileCipher(fileCtx, readFile, writeFile, DECRYPT);
}


// NOTE: Things below are not used outside some testing...

void byteCipher(filecrypt_ctx *fileCtx, byte *b, long size,
                unsigned char cipherMode) {
    bufferDataEnd = size;

    if (fileCtx->readFileBlockSize < stateSize) {
        fprintf(stderr, "fencryptECB: Read block size cannot be smaller than the "
                "cipher state size");
        return;
    }

    switch (cipherMode | fileCtx->operationMode) {
        case (ENCRYPT | ECB):
            printf("ENCRYPTING ECB:\n");
            encryptECB(fileCtx, b);
            break;
        case (DECRYPT | ECB):
            printf("DECRYPTING ECB:\n");
            decryptECB(fileCtx, b);
            break;
    }

    printByteArrayPretty(b, size);

    return;
}

void encryptBytes(filecrypt_ctx *fileCtx, byte *b, long size) {
    byteCipher(fileCtx, b, size, ENCRYPT);
}

void decryptBytes(filecrypt_ctx *fileCtx, byte *b, long size) {
    byteCipher(fileCtx, b, size, DECRYPT);
}
