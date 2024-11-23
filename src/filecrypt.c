#include <stdlib.h>
#include <string.h>
#include "../include/filecrypt.h"
#include "../include/definitions.h"

// Definitions:
// file block - A block of bytes that is read into the buffer, encrypted/decrypted and written to a file. One buffer is processed at a time. Block size determined by fileCtx->readFileBlockSize.
// cipher state - The largest array of bytes that the cipher can encrypt/decrypt at a time. For AES-128 it is 16 bytes.

// Global variables that are certainly make this not thread-safe!
static unsigned long fsizeInBytes;   // Size of the read file in bytes
static unsigned long bufferDataEnd;  // The position of the final byte - used for the final file-read which doesn't fill the buffer
static unsigned long bytesWritten;   // How many bytes are successfully written from buffer to write file - currently unused
static unsigned char isFirstByte = 1, isFinalBlock = 0;   // Flags for the first byte of the first file block (for start of ECB, CBC...) and the final file block (for adding and removing padding)
static byte * carryOverBuffer;       // For carrying over a state of plaintext/ciphertext to the next read file block
static byte * copyBuffer;            // For storing a copy of the read file block (used for decrypting CBC to avoid excessive memcpy's per cipher state)

static void (*operationModeFunc)(filecrypt_ctx *, byte *);

// Prepare filecrypt_ctx mode of operation (ECB, CBC...), used cipher context (AES), and the size of file read/write buffer in bytes.
void prepareFileCtx(filecrypt_ctx *fileCtx, cipher_ctx *cctx, unsigned char operationMode, long readFileBlockSize) {
    if (fileCtx == NULL || cctx == NULL) return;
    fileCtx->cipherCtx = cctx;
    fileCtx->operationMode = operationMode;
    fileCtx->readFileBlockSize = readFileBlockSize;
}

// Mainly for allocation of iv, it is allowed to change it manually
void addFileCtxIV(filecrypt_ctx * fileCtx, const byte * iv, int ivSize) {
    if (fileCtx == NULL) return;
    fileCtx->ivSize = ivSize;
    if (fileCtx->iv == NULL) {
        fileCtx->iv = malloc(sizeof(byte)*fileCtx->ivSize);
    } else {
        fileCtx->iv = realloc(fileCtx->iv, sizeof(byte)*fileCtx->ivSize);
    }
    if (iv != NULL){
        memcpy(fileCtx->iv, iv, sizeof(byte) * fileCtx->ivSize);
    }
}

// Free filecrypt_ctx from memory, just free(fileCtx) won't free iv
void freeFileCtx(filecrypt_ctx * fileCtx) {
    if (fileCtx == NULL) return;
    if (fileCtx->iv != NULL) free(fileCtx->iv);
    free(fileCtx);
}

void addPadding(filecrypt_ctx * fileCtx, byte *buf) {
    byte padSize = fileCtx->cipherCtx->stateSize - bufferDataEnd % fileCtx->cipherCtx->stateSize;
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
    for (long i = 0; i < bufferDataEnd; i += fileCtx->cipherCtx->stateSize) {
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, &buffer[i]);
    }
}

void decryptECB(filecrypt_ctx *fileCtx, byte *buffer) {
    for (long i = 0; i < bufferDataEnd; i += fileCtx->cipherCtx->stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, &buffer[i]);
    }
    if (isFinalBlock) {
        bufferDataEnd -= buffer[bufferDataEnd - 1];
    }
}

void encryptCBC(filecrypt_ctx *fileCtx, byte *buffer) {
    if (isFirstByte) {
        xorByteArrays(buffer, fileCtx->iv, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer);
        isFirstByte = 0;
    } else {
        xorByteArrays(buffer, carryOverBuffer, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer);
    }

    if (isFinalBlock) {
        addPadding(fileCtx, buffer);
    }

    for (long i = 16; i < bufferDataEnd; i += fileCtx->cipherCtx->stateSize) {
        xorByteArrays(buffer+i, buffer+i-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx, buffer+i);
    }

    if (!isFinalBlock) {
        memcpy(carryOverBuffer, buffer+bufferDataEnd-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
}

void decryptCBC(filecrypt_ctx *fileCtx, byte *buffer) {
    if (isFirstByte) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer);
        xorByteArrays(buffer, fileCtx->iv, fileCtx->cipherCtx->stateSize);
        isFirstByte = 0;
    } else {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer);
        xorByteArrays(buffer, carryOverBuffer, fileCtx->cipherCtx->stateSize);
    }

    for (long i = 16; i < bufferDataEnd; i += fileCtx->cipherCtx->stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx, buffer+i);
        xorByteArrays(buffer+i, copyBuffer+i-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
    if (isFinalBlock) {
        bufferDataEnd -= buffer[bufferDataEnd - 1];
        return;
    }

    if (!isFinalBlock) {
        memcpy(carryOverBuffer, copyBuffer+bufferDataEnd-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
}

void fileCipher(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile, unsigned char cipherMode) {
    if (fileCtx->readFileBlockSize < fileCtx->cipherCtx->stateSize) {
        fprintf(stderr, "fileCipher: Read block size cannot be smaller than the cipher state size");
        return;
    }

    fsizeInBytes = readFileSize(readFile);

    if (fileCtx->readFileBlockSize > fsizeInBytes) {
        fprintf(stdout, "fileCipher - long fsizeInBytes: readFileBlockSize %ld is larger than the file size in bytes %ld",
                fileCtx->readFileBlockSize, fsizeInBytes);
    }

    byte *buffer = (byte *)malloc(sizeof(byte) * fileCtx->readFileBlockSize);

    if (!buffer) {
        fprintf(stderr, "fileCipher: Failed to allocate buffer");
        return;
    }

    long blockCount = (fsizeInBytes / fileCtx->readFileBlockSize) + 1;

    switch (cipherMode | fileCtx->operationMode) {
        case (ENCRYPT | ECB):
            operationModeFunc = encryptECB;
            break;
        case (DECRYPT | ECB):
            operationModeFunc = decryptECB;
            break;
        case (ENCRYPT | CBC):
            operationModeFunc = encryptCBC;
            carryOverBuffer = malloc(sizeof(byte) * fileCtx->cipherCtx->stateSize);
            break;
        case (DECRYPT | CBC):
            operationModeFunc = decryptCBC;
            copyBuffer = malloc(sizeof(byte) * fileCtx->readFileBlockSize);
            carryOverBuffer = malloc(sizeof(byte) * fileCtx->cipherCtx->stateSize);
            break;
    }

    if (fileCtx->operationMode != ENCRYPT) {
        isFirstByte = 1;
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


// NOTE: Things below are not used outside some testing... maybe for CTR?

void byteCipher(filecrypt_ctx *fileCtx, byte *b, long size, unsigned char cipherMode) {
    bufferDataEnd = size;

    if (fileCtx->readFileBlockSize < fileCtx->cipherCtx->stateSize) {
        fprintf(stderr, "byteCipher: Read block size cannot be smaller than the cipher state size");
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
        case (ENCRYPT | CBC):
            printf("ENCRYPTING CBC:\n");
            isFinalBlock = isFirstByte = 1;
            encryptCBC(fileCtx, b);
            break;
        case (DECRYPT | CBC):
            printf("DECRYPTING CBC:\n");
            isFinalBlock = isFirstByte = 1;
            copyBuffer = malloc(sizeof(byte) * fileCtx->readFileBlockSize);
            decryptCBC(fileCtx, b);
            break;
    }

    if (copyBuffer != NULL) { 
        free(copyBuffer);
    }

    return;
}

void encryptBytes(filecrypt_ctx *fileCtx, byte *b, long size) {
    byteCipher(fileCtx, b, size, ENCRYPT);
}

void decryptBytes(filecrypt_ctx *fileCtx, byte *b, long size) {
    byteCipher(fileCtx, b, size, DECRYPT);
}
