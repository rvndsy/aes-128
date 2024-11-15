// Implementation of AES-128. Based on NIST FIPS-197.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "definitions.h"
#include "utils.h"
#include "aes.h"

#define NK 4    //Number of 32-bit columns for the key - 4 for AES-128, 6 for 192, 8 for 256
#define NB 4    //Number of 32-bit columns for the state/block/text - always 4
#define NR 10   //Number of rounds - 10 for AES-128, 12 for 192, 14 for 256
#define KEY_SIZE 16
#define TXT_SIZE 16
#define EXPANDED_KEY_BYTE_COUNT 4*4*(NR+1)

const byte sBox[256] = {  // x is vertical, y is horizontal
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

const byte rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }; // not using word datatype

// word rotWord(word w) { //circular rotate left by 2 bytes
//     return (w << 8) | (w >> (32 - 8));
// }

void subBytes(byte * b) {
    for (uint8_t i = 0; i < 16; i++) {
        b[i] = sBox[b[i]];
    }
}

void shiftRows(byte * b) {
    byte tmp0;
    for (uint8_t i = 1; i < 4; i++) {
        for (uint8_t j = i; j > 0; j--) {
            tmp0 = b[i];
            b[i] = b[4+i];
            b[4+i] = b[8+i];
            b[8+i] = b[12+i];
            b[12+i] = tmp0;
        }
    }
}

void keyExpansion(const byte * key, byte * expandedKey) {
    int i = 0;
    while (i <= NK - 1) {
        expandedKey[4*i] = key[4*i];
        expandedKey[4*i+1] = key[4*i+1];
        expandedKey[4*i+2] = key[4*i+2];
        expandedKey[4*i+3] = key[4*i+3];
        //printf("%d - ", i);
        //printByteArray(&expandedKey[4*i], 4);
        //println();
        i++;
    }
    byte tmp[4];
    while (i <= 4 * NR + 3) {
        tmp[0] = expandedKey[4*(i-1)];
        tmp[1] = expandedKey[4*(i-1)+1];
        tmp[2] = expandedKey[4*(i-1)+2];
        tmp[3] = expandedKey[4*(i-1)+3];
        if (i % NK == 0) {
            byte tmp0 = tmp[0];
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
        //printf("%d - %d - ", i, 4*i+3);
        //printByteArray(&expandedKey[4*i], 4);
        //println();
        i++;
    }
}

void addRoundKey(byte roundKey[16], byte * state) {
    for (uint8_t i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

byte xTimes(byte a) { // TODO: definitely optimize the flag part
    uint8_t flag = 0x0;
    if ((a & 0x80) >> 7) flag = 0x1;
    a <<= 1;
    if (flag) a ^= 0x1b; //0x1b = 11011
    return a;
}

byte gf8Multiply(byte a, byte b) {
    if (b == 0x0) return 0x0; //The following if returns 0x0 if b is 0x0, else a*0 would return a. 0*b should correctly return 0.
    byte tmp = 0x0;
    // At each step we check if b is all 0's (0 means nothing more to multiply)
    while (b) {
        if (b & 0x1) tmp ^= a;
        // We execute xTimes(a) together with b >> 1, because by shifting b the least significant bit in b becomes the current power of 2 that xTimes(a) produces.
        a = xTimes(a);
        b >>= 1;
    }
    return tmp;
}

void mixColumns(byte * b) {
    byte tmp[4];
    for (uint8_t i = 0; i < 4; i++) {
        tmp[0] = b[4*i];
        tmp[1] = b[4*i+1];
        tmp[2] = b[4*i+2];
        tmp[3] = b[4*i+3];
        b[4*i] =   gf8Multiply(0x2, tmp[0]) ^ gf8Multiply(0x3, tmp[1]) ^ tmp[2] ^ tmp[3];
        b[4*i+1] = tmp[0] ^ gf8Multiply(0x2, tmp[1]) ^ gf8Multiply(0x3, tmp[2]) ^ tmp[3];
        b[4*i+2] = tmp[0] ^ tmp[1] ^ gf8Multiply(0x2, tmp[2]) ^ gf8Multiply(0x3, tmp[3]);
        b[4*i+3] = gf8Multiply(0x3, tmp[0]) ^ tmp[1] ^ tmp[2] ^ gf8Multiply(0x2, tmp[3]);
    }
}

// returns 0 if something went wrong    returns 1 if OK
//
// plainText - text to encrypt (64-bits)     key - the AES encrypt/decrypt key (see nk variable comment)
// out - memory address to store encrypted plainText, to encrypt plainText
// version (AES version): currently only 128
int encrypt(byte * state, const byte * key, int version) {
    // TODO: Add parameter checks
    // TODO: Add failure checks - return 0
    // TODO: Add functionality to avoid malloc for expandedKey or something?
    uint8_t nr, nk, nb;
    if (version == 128) {
        nk = 4;    //Number of 32-bit columns for the key - 4 for AES-128, 6 for 192, 8 for 256
        nb = 4;    //Number of 32-bit columns for the state/block/text - always 4
        nr = 10;   //Number of rounds - 10 for AES-128, 12 for 192, 14 for 256
    } else return 0;
    byte * expandedKey = (byte*)malloc(sizeof(byte)*16*(nr+1));

    //byte * state = (byte*)malloc(sizeof(byte)*nb*16);
    //memcpy(state, plainText, sizeof(byte)*nb*16);

    // Generating expanded key
    keyExpansion(key, expandedKey);

    // Initial add round key
    addRoundKey(expandedKey, state);

    // Encryption
    for (uint8_t round = 1; round != NR; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(&expandedKey[16*round], state);

        printf("%d Add round key (%d):\t", round, 16*round);
        printByteArray(state, 16);
        println();
    }

    // Final round without mixColumns
    subBytes(state);
    shiftRows(state);
    addRoundKey(&expandedKey[EXPANDED_KEY_BYTE_COUNT-16], state);

    free(expandedKey);

    return 1;
}

int main(int argc, char** argv)  {
    int nk = NK;
    int nb = NB;
    int nr = NR;

    byte state[TXT_SIZE], key[KEY_SIZE], expandedKey[EXPANDED_KEY_BYTE_COUNT];
    byte * keyPtr = expandedKey;
    //word expandedKey[NR*4+1];

    if (argc < 3) {
        printf("aes: Too few arguments provided\n");
        return 1;
    } else if (argc > 3) {
        printf("aes: Too many arguments provided\n");
        return 1;
    }

    // Reading key and plaintext
    char tmp[2];
    for (int i = 0; i < 16; i++) {
        // Plaintext
        tmp[0] = argv[1][i*2];
        tmp[1] = argv[1][i*2+1];
        state[i] = strToHexByte(tmp);

        // Key
        tmp[0] = argv[2][i*2];
        tmp[1] = argv[2][i*2+1];
        key[i] = strToHexByte(tmp);
    }

    char textBlock[128] = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    byte * block = malloc(64*sizeof(byte));
    byte * pBlock = block;

    for (int i = 0; i < 64; i++) {
        tmp[0] = textBlock[i*2];
        tmp[1] = textBlock[i*2+1];
        block[i] = strToHexByte(tmp);
    }

    encrypt(pBlock, key, 128);
    pBlock += 16;
    encrypt(pBlock, key, 128);
    pBlock += 16;
    encrypt(pBlock, key, 128);
    pBlock += 16;
    encrypt(pBlock, key, 128);

    printByteArray(block, 64);

    free(block);

    return 0;

    keyExpansion(key, expandedKey);

    printf("Expanded Key: ");
    printByteArray(expandedKey, EXPANDED_KEY_BYTE_COUNT);
    println();

    // Initial add round key
    addRoundKey(keyPtr, state);

    printf("Initial key add:");
    printByteArray(state, 16);
    println();

    // Encryption
    for (uint8_t round = 1; round != NR; round++) {
        subBytes(state);
        printf("%d Substitution: ", round);
        printByteArray(state, TXT_SIZE);
        println();

        shiftRows(state);
        printf("%d Shift Rows:\t", round);
        printByteArray(state, TXT_SIZE);
        println();

        mixColumns(state);
        printf("%d Mix Columns:\t", round);
        printByteArray(state, TXT_SIZE);
        println();

        addRoundKey(&expandedKey[16*round], state);

        printf("%d Add round key (%d):", round, 16*round);
        printByteArray(state, 16);
        println();
        println();
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(&expandedKey[EXPANDED_KEY_BYTE_COUNT-16], state);

    printf("Encrypted:\t");
    printByteArray(state, TXT_SIZE);
    println();

    return 0;
}
