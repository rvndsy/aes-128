// Implementation of AES-128. Based on NIST FIPS-197.
// Not particularly optimized or fast. It is meant for a study course as an exercise to understand AES.
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //for memory operations
#include "../include/definitions.h"
#include "../include/aes.h"

#define DEBUG_PRINT 0 //1 to print AddRoundKeys output for every round

#if DEBUG_PRINT == 1
#include <stdio.h>   //for printf
#include "../include/utils.h"
#endif

#define AES_128

#define EXPANDED_KEY_BYTE_COUNT_128 176 //44 32-bit words or (4*4*(NR+1))
#define NK_BYTES_128 16                     //Key size in bytes (NK*32/8)

#ifdef AES_128
#define NK 4                            //Number of 32-bit columns for the key - 4 for AES-128, 6 for 192, 8 for 256
#define NK_BYTES 16                     //Key size in bytes (NK*32/8)
#define EXPANDED_KEY_BYTE_COUNT 176     //44 32-bit words or (4*4*(NR+1))
#define NR 10                           //Number of rounds - 10 for AES-128, 12 for 192, 14 for 256
#endif // AES_128

static const byte sBox[256] = {  // x is vertical, y is horizontal
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const byte invSBox[256] = {  // x is vertical, y is horizontal
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const byte rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }; // not using word datatype

// Safely free memory in one function
void freeAESctx(cipher_ctx * aesCtx) {
    if (aesCtx == NULL) {
        return;
    }
    if (aesCtx->key != NULL) {
        //fprintf(stderr, "freeAESctx: Freeing key...\n");
        free(aesCtx->key);
        aesCtx->key = NULL;
    }
    if (aesCtx->roundKeys != NULL) {
        //fprintf(stderr, "freeAESctx: Freeing roundKeys...\n");
        free(aesCtx->roundKeys);
        aesCtx->roundKeys = NULL;
    }
    //fprintf(stderr, "freeAESctx: Freeing aesCtx...\n");
    free(aesCtx);
}
// Safely update values of AES cipher_ctx in one function
void updateAESctx(cipher_ctx * aesCtx, const byte * key, unsigned int version) {
    // Setting key based on AES version
    if (aesCtx == NULL) {
        //fprintf(stderr, "prepareAESctx: NULL pointer to aesCtx given\n");
        return;
    }
    if (key == NULL) {
        //fprintf(stderr, "prepareAESctx: NULL pointer to key given\n");
    }
    if (version == 128) {
        aesCtx->keySize = NK_BYTES_128;
        aesCtx->totalRoundKeySize = EXPANDED_KEY_BYTE_COUNT_128;
    } else {
        //fprintf(stderr, "prepareAESctx: Bad AES version given - %d - expected 128, 192 or 256\n", version);
        return;
    }

    if (aesCtx->key != NULL){
        //fprintf(stderr, "prepareAESctx: Reallocating key...\n");
        aesCtx->key = realloc(aesCtx->key, sizeof(byte) * aesCtx->keySize);
    } else {
        //fprintf(stderr, "prepareAESctx: Mallocating key...\n");
        aesCtx->key = malloc(sizeof(byte) * aesCtx->keySize);
    }
    if (aesCtx->key == NULL) {
        //fprintf(stderr, "prepareAESctx: Failed to allocate key\n");
        free(aesCtx);
        return;
    }
    //fprintf(stderr, "prepareAESctx: Memcopying key into aesCtx->key...\n");
    memcpy(aesCtx->key, key, sizeof(byte)*aesCtx->keySize);

    if (aesCtx->roundKeys != NULL){
        //fprintf(stderr, "prepareAESctx: Reallocating roundKeys...\n");
        aesCtx->roundKeys = realloc(aesCtx->roundKeys, sizeof(byte) * aesCtx->totalRoundKeySize);
    } else {
        //fprintf(stderr, "prepareAESctx: Mallocating roundKeys...\n");
        aesCtx->roundKeys = malloc(sizeof(byte) * aesCtx->totalRoundKeySize);
    }
    if (aesCtx->roundKeys == NULL) {
        //fprintf(stderr, "prepareAESctx: Failed to allocate roundKeys\n");
        //fprintf(stderr, "Freeing key...");
        free(aesCtx->key);
        //fprintf(stderr, "Freeing aesCtx...\n");
        free(aesCtx);
        return;
    }
    //fprintf(stderr, "prepareAESctx: Expanding roundKeys...\n");
    keyExpansion(aesCtx->key, aesCtx->roundKeys);

    // Setting pointers to AES encryption and decryption functions
    aesCtx->encryptFunc = cipher;
    aesCtx->decryptFunc = invCipher;

    aesCtx->stateSize = NB_BYTES;
}

// Safely create and update an cipher_ctx for AES with correct values
cipher_ctx * createAESctx(const byte * key, unsigned int version) {
    cipher_ctx * aesCtx = malloc(sizeof(cipher_ctx));
    if (aesCtx == NULL) {
        //fprintf(stderr, "createAESctx: aesCtx malloc failed, returning...\n");
        return NULL;
    }
    aesCtx->key = NULL;
    aesCtx->roundKeys = NULL;
    updateAESctx(aesCtx, key, version);
    if (aesCtx->key == NULL || aesCtx->roundKeys == NULL) {
        //fprintf(stderr, "createAESctx: Null from updateAESctx, freeing aesCtx...\n");
        freeAESctx(aesCtx);
        return NULL;
    }
    return aesCtx;
}
// Substition for Cipher
void subBytes(byte * state) {
    for (unsigned char i = 0; i < NB_BYTES; i++) {
        state[i] = sBox[state[i]];
    }
}
// Row shifting to the "right" for Cipher
void shiftRows(byte * state) {
    byte tmp0;
    for (unsigned char i = 1; i < NB; i++) {
        for (unsigned char j = i; j > 0; j--) {
            tmp0 = state[i];
            state[i] = state[4+i];
            state[4+i] = state[8+i];
            state[8+i] = state[12+i];
            state[12+i] = tmp0;
        }
    }
}
// Substition for invCipher
void invSubBytes(byte * state) {
    for (unsigned char i = 0; i < NB_BYTES; i++) {
        state[i] = invSBox[state[i]];
    }
}
// Row shifting to the "left" for invCipher
void invShiftRows(byte * state) {
    byte tmp0;
    for (unsigned char i = 1; i < NB; i++) {
        for (unsigned char j = i; j > 0; j--) {
            tmp0 = state[i];
            state[i] = state[12+i];
            state[12+i] = state[8+i];
            state[8+i] = state[4+i];
            state[4+i] = tmp0;
        }
    }
}
// Generate round keys for AES. Expanded key is 176 bytes for AES-128. This implementaiton uses a 1D array of bytes not words as the state.
void keyExpansion(const byte * key, byte * expandedKey) {
    if (key == NULL || expandedKey == NULL) return;
    int i = 0;
    while (i <= NK - 1) {
        expandedKey[4*i] = key[4*i];
        expandedKey[4*i+1] = key[4*i+1];
        expandedKey[4*i+2] = key[4*i+2];
        expandedKey[4*i+3] = key[4*i+3];
        i++;
    }
    byte tmp[4], tmp0;
    while (i <= 4 * NR + 3) {
        tmp[0] = expandedKey[4*(i-1)];
        tmp[1] = expandedKey[4*(i-1)+1];
        tmp[2] = expandedKey[4*(i-1)+2];
        tmp[3] = expandedKey[4*(i-1)+3];
        if (i % NK == 0) {
            tmp0 = tmp[0];
            tmp[0] = sBox[tmp[1]] ^ rcon[i/NK-1]; //rcon index requires -1 - not in fips
            tmp[1] = sBox[tmp[2]];
            tmp[2] = sBox[tmp[3]];
            tmp[3] = sBox[tmp0];
        } else if (NK > 6 && i % NK == 4) { //for AES-256
            tmp[0] = sBox[tmp[0]];
            tmp[1] = sBox[tmp[1]];
            tmp[2] = sBox[tmp[2]];
            tmp[3] = sBox[tmp[3]];
        }
        expandedKey[4*i] = expandedKey[(i-NK)*4] ^ tmp[0];
        expandedKey[4*i+1] = expandedKey[(i-NK)*4+1] ^ tmp[1];
        expandedKey[4*i+2] = expandedKey[(i-NK)*4+2] ^ tmp[2];
        expandedKey[4*i+3] = expandedKey[(i-NK)*4+3] ^ tmp[3];
        i++;
    }
}
// XOR state with the round key
void addRoundKey(const byte * roundKey, byte * state) {
    for (unsigned char i = 0; i < NB_BYTES; i++) {
        state[i] ^= roundKey[i];
    }
}
// Used for multiplication in galois field
byte xTimes(byte a) { // TODO: definitely optimize the flag part
    if (a & 0x80) // If most significant bit is set left shift and XOR with 0x1b
        return (a << 1) ^ 0x1b;
    return a << 1;
}

byte gf8Multiply(byte a, byte b) {
    byte out = 0x0;
    // At each step we check if b is all 0's (0 means nothing more to multiply)
    while (b) {
        if (b & 0x1) out ^= a;
        // We execute xTimes(a) together with b >> 1, because by shifting b the least significant bit in b becomes the current power of 2 that xTimes(a) produces.
        a = xTimes(a); //It probably would be faster to inline/macro xTimes
        b >>= 1;
    }
    return out;
}

// Mix the columns for Cipher
void mixColumns(byte * b) {
    byte tmp[4];
    for (unsigned char i = 0; i < 4; i++) {
        tmp[0] = b[4*i];
        tmp[1] = b[4*i+1];
        tmp[2] = b[4*i+2];
        tmp[3] = b[4*i+3];
        b[4*i] =   gf8Multiply(0x2, tmp[0]) ^ gf8Multiply(0x3, tmp[1]) ^ tmp[2]                   ^ tmp[3];
        b[4*i+1] =                   tmp[0] ^ gf8Multiply(0x2, tmp[1]) ^ gf8Multiply(0x3, tmp[2]) ^ tmp[3];
        b[4*i+2] =                   tmp[0] ^                   tmp[1] ^ gf8Multiply(0x2, tmp[2]) ^ gf8Multiply(0x3, tmp[3]);
        b[4*i+3] = gf8Multiply(0x3, tmp[0]) ^                   tmp[1] ^                   tmp[2] ^ gf8Multiply(0x2, tmp[3]);
    }
}
// Inverse mix columns for InvCipher
void invMixColumns(byte * b) {
    byte tmp[4];
    for (unsigned char i = 0; i < 4; i++) {
        tmp[0] = b[4*i];
        tmp[1] = b[4*i+1];
        tmp[2] = b[4*i+2];
        tmp[3] = b[4*i+3];
        b[4*i] =   gf8Multiply(0xe, tmp[0]) ^ gf8Multiply(0xb, tmp[1]) ^ gf8Multiply(0xd, tmp[2]) ^ gf8Multiply(0x9, tmp[3]);
        b[4*i+1] = gf8Multiply(0x9, tmp[0]) ^ gf8Multiply(0xe, tmp[1]) ^ gf8Multiply(0xb, tmp[2]) ^ gf8Multiply(0xd, tmp[3]);
        b[4*i+2] = gf8Multiply(0xd, tmp[0]) ^ gf8Multiply(0x9, tmp[1]) ^ gf8Multiply(0xe, tmp[2]) ^ gf8Multiply(0xb, tmp[3]);
        b[4*i+3] = gf8Multiply(0xb, tmp[0]) ^ gf8Multiply(0xd, tmp[1]) ^ gf8Multiply(0x9, tmp[2]) ^ gf8Multiply(0xe, tmp[3]);
    }
}

// state - 128-bit 'plaintext' to encrypt       roundKeys - the expanded AES-128 key
void cipher(byte * roundKeys, byte * state) {
    size_t round = 0;

    // Initial add round key
    addRoundKey(roundKeys, state);

    // Start encryption with 9 repeated rounds
    for (round = 1; round != NR; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(&roundKeys[16*round], state);

        #if DEBUG_PRINT == 1
            printf("%d Add round key (%d):\t", round, 16*round);
            printByteArray(state, 16);
            println();
         #endif
    }

    // Final round 10 without mixColumns
    subBytes(state);
    shiftRows(state);
    addRoundKey(&roundKeys[EXPANDED_KEY_BYTE_COUNT-16], state);
}
// Similar to cipher but with a reverse order and inverse functions
void invCipher(byte * roundKeys, byte * state) {
    size_t round = NR;

    // Initial add round key
    addRoundKey(&roundKeys[NK*4*NR], state);
    #if DEBUG_PRINT == 1
        printf("%d Add Round Key (%d):\t", round, 16*round);
        printByteArrayPretty(state, 16);
        println();
        #endif

    round = NR - 1;

    // 9 repeated rounds for decryption
    for (; round > 0; round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(&roundKeys[NK*4*round], state);
        #if DEBUG_PRINT == 1
            printf("%d Add Round Key (%d):\t", round, 16*round);
            printByteArrayPretty(state, 16);
            println();
        #endif
        invMixColumns(state);
    }

    // Final round without mixColumns
    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(roundKeys, state);
}
