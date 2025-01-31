#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //for memcpy...
#include "../include/filecrypt.h"
#include "../include/aes.h"
#include "../include/definitions.h"
#include "../include/utils.h"

#define VERBOSE 1
#define BENCHMARK 1

#if BENCHMARK == 1
#include <time.h>
#endif

#define TEXT_SIZE 64
#define KEY_SIZE 16
#define IV_SIZE 16

#define PDF 0x1
#define TXT 0x2

// Key is the same for ECB, CBC - 2b7e151628aed2a6abf7158809cf4f3c
const byte aesCore128Key[KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};


// iV - 000102030405060708090a0b0c0d0e0f
const byte iv[IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const char * plainPDFSample = "./samples/file.pdf";
const char * cipherPDFSample = "./samples/cfile.pdf";

const char * cipherTXTSample = "./samples/cfile.md";
const char * plainTXTSample = "./samples/file.md";
//const char * cipherIMGSample = "./samples/c-lorem-picsum-200.jpg";
//const char * plainIMGSample = "./samples/lorem-picsum-200.jpg";

static float startTime, endTime;

char * fileNameMaker(uint8_t mode, uint16_t version, uint8_t isEncrypt, uint8_t fileType) {
    char * fileName = malloc(sizeof(char) * 32);
    memset(fileName, '\0', 32);
    switch (mode) {
        case ECB:
            strcat(fileName, "ecb-");
            break;
        case CBC:
            strcat(fileName, "cbc-");
            break;
    }
    switch (version) {
        case 128:
            strcat(fileName, "128-");
            break;
        case 196:
            strcat(fileName, "196-");
            break;
        case 256:
            strcat(fileName, "256-");
            break;
    }
    switch (isEncrypt) {
        case ENCRYPT:
            strcat(fileName, "encrypted");
            break;
        case DECRYPT:
            strcat(fileName, "decrypted");
            break;
    }
    switch (fileType) {
        case PDF:
            strcat(fileName, ".pdf");
            break;
        case TXT:
            strcat(fileName, ".md");
            break;
    }
    return fileName;
}

void testFileEncryptDecrypt(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileReadBufferSize) {
    if (mode == ECB) {
        printf("AES-128 ECB ENCRYPT PDF TEST...\n");
    } else if (mode == CBC) {
        printf("AES-128 CBC ENCRYPT PDF TEST...\n");
    }

    char * fileNameEncrypt = fileNameMaker(mode, version, ENCRYPT, fileType);
    char * fileNameDecrypt = fileNameMaker(mode, version, DECRYPT, fileType);

    FILE * fptrReadPlain, * fptrWriteCipher, * fptrWritePlain;
    if (fileType == PDF) {
        fptrReadPlain = fopen(plainPDFSample, "rb");
    } else if (fileType == TXT) {
        fptrReadPlain = fopen(plainTXTSample, "rb");
    }
    fptrWriteCipher = fopen(fileNameEncrypt, "wb+");
    fptrWritePlain = fopen(fileNameDecrypt, "wb+");

    if (fptrReadPlain == NULL) fprintf(stderr, "Sample file %s does not exist", plainTXTSample);
    if (fptrWritePlain == NULL) fprintf(stderr, "Cannot open plaintext file to write");
    if (fptrWriteCipher == NULL) fprintf(stderr, "Cannot open ciphertext file to write");

    #if BENCHMARK == 1
        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    cipher_ctx * aes = createAESctx(aesCore128Key, version);
    filecrypt_ctx * fctx = createFileCtx(aes, mode, fileReadBufferSize);
    if (mode == CBC) {
        addFileCtxIV(fctx, iv, AES_STATE_SIZE);
    }

    encryptFile(fctx, fptrReadPlain, fptrWriteCipher);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Encrypt time: %fs\n", endTime - startTime);

        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    decryptFile(fctx, fptrWriteCipher, fptrWritePlain);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Decrypt time: %fs\n", endTime - startTime);
    #endif

    freeAESctx(aes);
    freeFileCtx(fctx);
    fclose(fptrReadPlain);
    fclose(fptrWritePlain);
    fclose(fptrWriteCipher);
}

void runTest(void (*testFuncPtr)(uint8_t, uint16_t, uint8_t, size_t), uint8_t mode, uint16_t version, uint8_t fileType, size_t fileReadBufferSize) {
    testFuncPtr(mode, version, fileType, fileReadBufferSize);
    printf("...TEST COMPLETE, CHECK FILES MANUALLY PLEASE!\n\n");
}

int main(int argc, char ** argv) {
    runTest(&testFileEncryptDecrypt, ECB, 128, PDF, 512);
    runTest(&testFileEncryptDecrypt, CBC, 128, PDF, 512);

    return 0;
}
