//test
//    Test samples from "Block Cipher Modes of Operation":
//    - ECB:
//    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
//    - CBC:
//    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //for memcpy...
#include "../include/aes.h"
#include "../include/definitions.h"
#include "../include/filecrypt.h"
#include "../include/utils.h"

#define VERBOSE 1
#define BENCHMARK 1

#if BENCHMARK == 1
#include <time.h>
#endif

#define TEXT_SIZE 64
#define KEY_SIZE 16
#define IV_SIZE 16

// Key is the same for ECB, CBC
const byte aesCore128Key[KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                      0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                      0x09, 0xcf, 0x4f, 0x3c};

// Plaintext is the same for ECB, CBC
const byte aesCore128Plaintext[TEXT_SIZE] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

// iV
const byte iv[IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

const byte ECB128Ciphertext[TEXT_SIZE] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
    0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
    0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
    0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
    0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
    0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

const byte CBC128Ciphertext[TEXT_SIZE] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
    0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
    0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73,
    0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
    0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
    0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};

static float startTime, endTime;
static float testMode;
static byte state[TEXT_SIZE];
static cipher_ctx * aes;
static filecrypt_ctx * fctx;

int testCipherEncrypt128EBC(byte *state, const byte *key) {
    printf("AES-128 DIRECT AES CIPHER ECB ENCRYPT TEST...\n");
    memcpy(state, aesCore128Plaintext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    cipher_ctx * aes = malloc(sizeof(cipher_ctx));
    prepareAESctx(aes, key, 128);

    for (size_t i = 0; i < TEXT_SIZE; i+=16) {
        cipher(aes, state+i);
    }

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    free(aes);

    return compareByteArrays(state, ECB128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testCipherDecrypt128EBC(byte *state, const byte *key) {
    printf("AES-128 DIRECT AES CIPHER ECB DECRYPT TEST...\n");
    memcpy(state, ECB128Ciphertext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    cipher_ctx * aes = malloc(sizeof(cipher_ctx));
    prepareAESctx(aes, key, 128);

    for (size_t i = 0; i < TEXT_SIZE; i+=16) {
        invCipher(aes, state+i);
    }

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, aesCore128Plaintext, TEXT_SIZE, VERBOSE);
}

int testFilecryptEncrypt128ECB(byte *state, const byte *key) {
    printf("AES-128 FILECRYPT ECB ENCRYPT TEST...\n");
    memcpy(state, aesCore128Plaintext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    prepareAESctx(aes, aesCore128Key, 128);
    prepareFileCtx(fctx, aes, ECB, TEXT_SIZE);
    encryptBytes(fctx, state, TEXT_SIZE);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, ECB128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testFilecryptDecrypt128ECB(byte *state, const byte *key) {
    printf("AES-128 FILECRYPT ECB ENCRYPT TEST...\n");
    memcpy(state, ECB128Ciphertext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    prepareAESctx(aes, aesCore128Key, 128);
    prepareFileCtx(fctx, aes, ECB, TEXT_SIZE);
    decryptBytes(fctx, state, TEXT_SIZE);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, aesCore128Plaintext, TEXT_SIZE, VERBOSE);
}

int testFilecryptEncrypt128CBC(byte *state, const byte *key) {
    printf("AES-128 FILECRYPT CBC ENCRYPT TEST...\n");
    memcpy(state, aesCore128Plaintext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    prepareAESctx(aes, aesCore128Key, 128);
    prepareFileCtx(fctx, aes, CBC, TEXT_SIZE);
    addFileCtxIV(fctx, iv, IV_SIZE);
    encryptBytes(fctx, state, TEXT_SIZE);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, CBC128Ciphertext, TEXT_SIZE, VERBOSE);
}

int testFilecryptDecrypt128CBC(byte *state, const byte *key) {
    printf("AES-128 FILECRYPT CBC DECRYPT TEST...\n");
    memcpy(state, CBC128Ciphertext, sizeof(byte) * TEXT_SIZE);
#if BENCHMARK == 1
    startTime = (float)clock() / CLOCKS_PER_SEC;
#endif

    prepareAESctx(aes, aesCore128Key, 128);
    prepareFileCtx(fctx, aes, CBC, TEXT_SIZE);
    addFileCtxIV(fctx, iv, IV_SIZE);
    decryptBytes(fctx, state, TEXT_SIZE);

#if BENCHMARK == 1
    endTime = (float)clock() / CLOCKS_PER_SEC;
    printf("Time: %f\n", endTime - startTime);
#endif

    return compareByteArrays(state, aesCore128Plaintext, TEXT_SIZE, VERBOSE);
}

void runTest(int (*testFuncPtr)(byte *, const byte *)) {
    int mismatchCount;

    memcpy(state, aesCore128Plaintext, sizeof(byte) * TEXT_SIZE);

    mismatchCount = testFuncPtr(state, aesCore128Key);

#if VERBOSE == 1
        printf("\n%d mismatching bytes\n", mismatchCount);
#endif

        if (mismatchCount == 0)
            printf("...PASSED\n\n");
        else
            printf("...FAILED\n\n");
}

int main(int argc, char **argv) {
    // Mixing some stuff up
    fctx = malloc(sizeof(filecrypt_ctx));
    aes = malloc(sizeof(cipher_ctx));

    runTest(&testCipherEncrypt128EBC);
    runTest(&testCipherDecrypt128EBC);

    addFileCtxIV(fctx, iv, 16);

    runTest(&testFilecryptEncrypt128ECB);
    runTest(&testFilecryptDecrypt128ECB);

    runTest(&testFilecryptEncrypt128CBC);
    runTest(&testFilecryptDecrypt128CBC);

    freeFileCtx(fctx);
    free(aes);
    return 0;
}
