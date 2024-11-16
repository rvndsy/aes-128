//
//    Test samples from "Block Cipher Modes of Operation Electronic Codebook ECB-AES128":
//    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
//
#include <stdio.h>
#include <string.h> //for memcpy...
#include "../aes.h"
#include "../definitions.h"
#include "../utils.h"

#define TEXT_SIZE 64
#define AES_128 128

const byte aesCore128PlainText[TEXT_SIZE] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

const byte aesCore128CipherText[TEXT_SIZE] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
};

const byte aesCore128Key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

int testEncrypt128(byte * state, const byte * key, uint16_t stateSize) {
    for (int i = 0; i < stateSize; i+=16) {
        aes128(&state[i], aesCore128Key, AES_128, 0);
    }
    return compareByteArrays(state, aesCore128CipherText, stateSize);
}

int testDecrypt128(byte * state, const byte * key, uint16_t stateSize) {
    for (int i = 0; i < stateSize; i+=16) {
        aes128(&state[i], aesCore128Key, AES_128, 1);
    }
    return compareByteArrays(state, aesCore128PlainText, stateSize);
}

int main(int argc, char** argv) {
    float testMode;
    if (argc == 1 || argc > 2) testMode = 0.5;
    else testMode = (float)*argv[1]-'0';
    byte state[TEXT_SIZE];
    int mismatchCount;

    //
    // Testing encryption
    // 
    if (testMode <= 0.5) {
        memcpy(state, aesCore128PlainText, sizeof(byte)*TEXT_SIZE);

        printf("\n\n=== STARTING AES-128 ENCRYPT TEST... ===\n\n");

        mismatchCount = testEncrypt128(state, aesCore128Key, TEXT_SIZE);
        printf("\n%d mismatches\n", mismatchCount);

        if (mismatchCount == 0) printf("\n\tTEST OK\n");
        else printf("\n\tTEST FAILED\n");

        printf("\n=== STOPPING AES-128 ENCRYPT TEST... ===\n");
    }

    //
    // Testing decryption
    // 
    mismatchCount = 0;
    if (testMode >= 0.5) {
        memcpy(state, aesCore128CipherText, sizeof(byte)*TEXT_SIZE);

        printf("\n\n=== STARTING AES-128 DECRYPT TEST... ===\n\n");

        mismatchCount = testDecrypt128(state, aesCore128Key, TEXT_SIZE);
        printf("\n%d mismatches\n", mismatchCount);

        if (mismatchCount == 0) printf("\n\tTEST OK\n");
        else printf("\n\tTEST FAILED\n");

        printf("\n=== STOPPING AES-128 DECRYPT TEST... ===\n");
    }

    return 0;
}
