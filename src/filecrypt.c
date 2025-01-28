#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/filecrypt.h"
#include "../include/definitions.h"

typedef void (*_operationModeFunc)(filecrypt_ctx *, void *, byte *);

// Update filecrypt_ctx mode of operation (ECB, CBC...), used cipher context (AES), and the size of file read/write buffer in bytes.
void updateFileCtx(filecrypt_ctx *fileCtx, cipher_ctx *cctx, unsigned char operationMode, long readFileBlockSize) {
    if (fileCtx == NULL || cctx == NULL) return;
    fileCtx->cipherCtx = cctx;
    fileCtx->operationMode = operationMode;
    fileCtx->readFileBlockSize = readFileBlockSize;
}
// Safely create a file context with values
filecrypt_ctx * createFileCtx(cipher_ctx *cctx, unsigned char operationMode, long readFileBlockSize) {
    filecrypt_ctx * fileCtx = malloc(sizeof(filecrypt_ctx));
    fileCtx->iv = NULL;         // Setting allocated struct pointers to null is really really really really really important (if you dont want random crashes)
    fileCtx->cipherCtx = NULL;
    //fprintf(stdout, "addFileCtxIV: Mallocating fileCtx...\n");
    updateFileCtx(fileCtx, cctx, operationMode, readFileBlockSize);
    return fileCtx;
}

// Mainly for convenient allocation of iv, it is also allowed to change iv array manually
void addFileCtxIV(filecrypt_ctx * fileCtx, const byte * iv, int ivSize) {
    if (fileCtx == NULL) return;

    fileCtx->ivSize = ivSize;

    if (fileCtx->iv != NULL){
        //fprintf(stdout, "addFileCtxIV: Reallocating iv...\n");
        fileCtx->iv = realloc(fileCtx->iv, sizeof(byte) * fileCtx->ivSize);
    } else {
        //fprintf(stdout, "addFileCtxIV: Mallocating iv...\n");
        fileCtx->iv = malloc(sizeof(byte) * fileCtx->ivSize);
    }
    if (fileCtx->iv == NULL) { 
        //fprintf(stderr, "addFileCtxIV: Failed to allocate iv\n");
        return;
    }

    // If iv data given, copy it
    if (fileCtx->iv != NULL && iv != NULL) {
        //fprintf(stdout, "addFileCtxIV: Memcopying provided iv into fileCtx->iv...\n");
        memcpy(fileCtx->iv, iv, sizeof(byte) * fileCtx->ivSize);
    }
}
// Free filecrypt_ctx from memory, just free(fileCtx) won't free iv
void freeFileCtx(filecrypt_ctx * fileCtx) {
    if (fileCtx == NULL) return;
    if (fileCtx->iv != NULL) {
        //fprintf(stdout, "freeFileCtx: Freeing iv...\n");
        free(fileCtx->iv);
        fileCtx->iv = NULL;
    }
    //fprintf(stdout, "freeFileCtx: Freeing filecCtx...\n");
    free(fileCtx);
}
// Add padding in the final file block. Padding is PKCS7 that fills the final state with bytes equal to the count of missing bytes.
// Ex: DD DD DD DD DD DD DD DD DD DD DD DD 04 04 04 04
void addPadding(filecrypt_ctx * fileCtx, byte *buffer) {
    byte padSize = fileCtx->cipherCtx->stateSize - fileCtx->bufferDataEnd % fileCtx->cipherCtx->stateSize;
    for (size_t i = 0; i < padSize; i++) {
        buffer[fileCtx->bufferDataEnd + i] = padSize;
    }
    fileCtx->bufferDataEnd += padSize;
}
// Just XOR two arrays together, first one given is overriden
void xorByteArrays(byte *a, const byte *b, int length) {
    for (int i = 0; i < length; i++) {
        a[i] ^= b[i];
    }
}
// Read the file size, used for determining file block count
unsigned long readFileSize(FILE *fptr) {
    if (!fptr) {
        fprintf(stderr, "readFileToByteArray: Invalid file pointer\n");
        return 0;
    }

    fseek(fptr, 0L, SEEK_END);
    long fsize = ftell(fptr);
    rewind(fptr); //Not sure if this is necessary

    if (fsize == 0) {
        fprintf(stderr, "encryptFile: Error reading file size\n");
        return 0;
    }

    return fsize;
}
// Simple block by block encryption with the cipher
void encryptECB(filecrypt_ctx *fileCtx, void *tmpBuffer, byte *buffer) {
    if (fileCtx->isFinalBlock) {
        addPadding(fileCtx ,buffer);
    }
    size_t stateSize = fileCtx->cipherCtx->stateSize;
    for (long i = 0; i < fileCtx->bufferDataEnd; i += stateSize) {
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx->roundKeys, &buffer[i]);
    }
}
// Simple block by block decryption with the inverse cipher
void decryptECB(filecrypt_ctx *fileCtx, void *tmpBuffer, byte *buffer) {
    size_t stateSize = fileCtx->cipherCtx->stateSize;
    for (long i = 0; i < fileCtx->bufferDataEnd; i += stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx->roundKeys, &buffer[i]);
    }
    // Removing padding after decryption is the same as stepping back the end of data
    if (fileCtx->isFinalBlock) {
        fileCtx->bufferDataEnd -= buffer[fileCtx->bufferDataEnd - 1];
    }
}
// File encryption with cipher-block-chaining. carryOverBuffer is to carry over a single state over to the next read file block.
void encryptCBC(filecrypt_ctx *fileCtx, void *tmpBuffer, byte *buffer) {
    if (fileCtx->isFirstByte) {
        xorByteArrays(buffer, fileCtx->iv, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx->roundKeys, buffer);
        fileCtx->isFirstByte = 0;
    } else {
        xorByteArrays(buffer, tmpBuffer+fileCtx->readFileBlockSize, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx->roundKeys, buffer);
    }

    if (fileCtx->isFinalBlock) {
        addPadding(fileCtx, buffer);
    }

    size_t stateSize = fileCtx->cipherCtx->stateSize;
    for (long i = stateSize; i < fileCtx->bufferDataEnd; i += stateSize) {
        xorByteArrays(buffer+i, buffer+i-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
        fileCtx->cipherCtx->encryptFunc(fileCtx->cipherCtx->roundKeys, buffer+i);
    }
    // Should be called once per call
    if (!fileCtx->isFinalBlock) {
        memcpy(tmpBuffer+fileCtx->readFileBlockSize, buffer+fileCtx->bufferDataEnd-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
}
// File decryption with cipher-block-chaining. carryOverBuffer is to carry over a single state over to the next read file block.
// copyBuffer keeps a copy of the currently read file block (ciphertext). No need for executing memcpy for stateSize amount of bytes during every cipher call.
void decryptCBC(filecrypt_ctx *fileCtx, void *tmpBuffer, byte *buffer) {
    byte *copyBuffer = tmpBuffer;
    memcpy(copyBuffer, buffer, fileCtx->bufferDataEnd);
    byte *carryOverBuffer = tmpBuffer+fileCtx->readFileBlockSize;

    if (fileCtx->isFirstByte) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx->roundKeys, buffer);
        xorByteArrays(buffer, fileCtx->iv, fileCtx->cipherCtx->stateSize);
        fileCtx->isFirstByte = 0;
    } else {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx->roundKeys, buffer);
        xorByteArrays(buffer, carryOverBuffer, fileCtx->cipherCtx->stateSize);
    }

    for (long i = 16; i < fileCtx->bufferDataEnd; i += fileCtx->cipherCtx->stateSize) {
        fileCtx->cipherCtx->decryptFunc(fileCtx->cipherCtx->roundKeys, buffer+i);
        xorByteArrays(buffer+i, copyBuffer+i-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
    // Removing padding after decryption is the same as stepping back the end of data
    if (fileCtx->isFinalBlock) {
        fileCtx->bufferDataEnd -= buffer[fileCtx->bufferDataEnd - 1];
        return;
    }
    // Should be called once per call
    if (!fileCtx->isFinalBlock) {
        memcpy(carryOverBuffer, copyBuffer+fileCtx->bufferDataEnd-fileCtx->cipherCtx->stateSize, fileCtx->cipherCtx->stateSize);
    }
}

// IMPORTANT:
// *readFile must be at least in rb mode
// *writeFile must be at in wb+ mode
void fileCipher(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile, unsigned char cipherMode) {
    if (fileCtx->readFileBlockSize < fileCtx->cipherCtx->stateSize) {
        fprintf(stderr, "fileCipher: Read block size cannot be smaller than the cipher state size");
        return;
    }
    // Get the file size in bytes to determine the file block count (how many buffers?)
    unsigned long fsizeInBytes = readFileSize(readFile);

    if (fileCtx->readFileBlockSize > fsizeInBytes) {
        fprintf(stdout, "fileCipher - long fsizeInBytes: readFileBlockSize %ld is larger than the file size in bytes %ld",
                fileCtx->readFileBlockSize, fsizeInBytes);
    }
    // Create buffer for reading and writing data
    byte *buffer = (byte *)malloc(sizeof(byte) * fileCtx->readFileBlockSize);

    if (!buffer) {
        fprintf(stderr, "fileCipher: Failed to allocate buffer");
        return;
    }

    // Calculate file block count. it is +1 because the file size in bytes might be a multiplier of the readFileBlockSize
    long blockCount = (fsizeInBytes / fileCtx->readFileBlockSize) + 1;

    // Flags for the first byte of the first file block (for start of ECB, CBC...) and the final file block (for adding and removing padding)
    fileCtx->isFirstByte = TRUE;
    fileCtx->isFinalBlock = FALSE;

    // for carrying over a state of plaintext/ciphertext to the next read file block
    // and for storing a copy of the read file block (used in decrypting CBC to avoid excessive memcpy's per cipher state)
    void *tmpBuffer = NULL;

    unsigned long tmpBufferSize = 0;
    _operationModeFunc operationModeFunc = NULL;

    switch (cipherMode | fileCtx->operationMode) {
        case (ENCRYPT | ECB):
            operationModeFunc = encryptECB;
            break;
        case (DECRYPT | ECB):
            operationModeFunc = decryptECB;
            break;
        case (ENCRYPT | CBC):
            operationModeFunc = encryptCBC;
            tmpBufferSize = fileCtx->cipherCtx->stateSize;
            tmpBuffer = malloc(sizeof(byte) * tmpBufferSize);
            break;
        case (DECRYPT | CBC):
            operationModeFunc = decryptCBC;
            tmpBufferSize = fileCtx->readFileBlockSize+fileCtx->cipherCtx->stateSize;
            tmpBuffer = malloc(sizeof(byte) * tmpBufferSize);
            break;
        default: break;
    }
    // Run the cipher block by block.
    for (int curBlock = 1; curBlock <= blockCount; curBlock++) {
        // Read readFileBlockSize amount of bytes from file
        fileCtx->bufferDataEnd = fread(buffer, sizeof(byte), fileCtx->readFileBlockSize, readFile);

        fileCtx->isFinalBlock = (curBlock == blockCount);

        operationModeFunc(fileCtx, tmpBuffer, buffer);
        // Write fileCtx->bufferDataEnd amount of bytes from file. fileCtx->bufferDataEnd is used because of padding in the final file block

        fileCtx->bytesWritten = fwrite(buffer, sizeof(byte), fileCtx->bufferDataEnd, writeFile);
    }
    // Free what must be freed!
    free(buffer);
    if (tmpBuffer != NULL) {
        free(tmpBuffer);
        tmpBuffer = NULL;
    }
}
// In my opinion it is simpler to call encrypt or decrypt than to pass ENCRYPT or DECRYPT to fileCipher.
// Alternate solution could be set the operation mode function and allocations in here.
void encryptFile(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile) {
    fileCipher(fileCtx, readFile, writeFile, ENCRYPT);
}

void decryptFile(filecrypt_ctx *fileCtx, FILE *readFile, FILE *writeFile) {
    fileCipher(fileCtx, readFile, writeFile, DECRYPT);
}


// NOTE: Things below are not currently used outside testing. Can be used to encrypt regular text input.
void byteCipher(filecrypt_ctx *fileCtx, byte *buffer, long byteBufferDataEnd, unsigned char cipherMode) {
    fileCtx->bufferDataEnd = byteBufferDataEnd;

    if (fileCtx->readFileBlockSize < fileCtx->cipherCtx->stateSize) {
        fprintf(stderr, "byteCipher: Read block size cannot be smaller than the cipher state size");
        return;
    }

    fileCtx->isFinalBlock = fileCtx->isFirstByte = 1;

    void *tmpBuffer = NULL;
    switch (cipherMode | fileCtx->operationMode) {
        case (ENCRYPT | ECB):
            encryptECB(fileCtx, NULL, buffer);
            break;
        case (DECRYPT | ECB):
            decryptECB(fileCtx, NULL, buffer);
            break;
        case (ENCRYPT | CBC):
            encryptCBC(fileCtx, NULL, buffer);
            break;
        case (DECRYPT | CBC):
            tmpBuffer = malloc(sizeof(byte) * fileCtx->readFileBlockSize);
            decryptCBC(fileCtx, tmpBuffer, buffer);
            break;
    }

    if (tmpBuffer != NULL) { 
        free(tmpBuffer);
        tmpBuffer = NULL;
    }
}

void encryptBytes(filecrypt_ctx *fileCtx, unsigned long bufferDataEnd, byte *b) {
    byteCipher(fileCtx, b, bufferDataEnd, ENCRYPT);
}

void decryptBytes(filecrypt_ctx *fileCtx, unsigned long bufferDataEnd, byte *b) {
    byteCipher(fileCtx, b, bufferDataEnd, DECRYPT);
}
