// This is designed for use with block ciphers that just need a key and a byte-array-state for execution of their respective Cipher and Inverse Cipher functions.

// Definitions:
// file block - A block of bytes that is read into the buffer, encrypted/decrypted and written to a file. One buffer is processed at a time. Block size determined by fileCtx->readFileBlockSize.
// cipher state - The size of array of bytes that the cipher can encrypt/decrypt at a time. For AES-128 it is 16 bytes.

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

// In here are definitions needed for filecrypt.c/.h, utils.c/.h, aes.c/.h and all the good places you want to use them.

typedef unsigned char byte;
//typedef uint32_t word;        //not used as of now

// TODO: Add expanded/round key to context or export it somehow to not re-generate it every round

// Cryptographic context used in crypto algorithms and file encryption that stores the key, round keys, total round key size/length in bytes, the size of the cipher state and chosen function for encryption and decryption
// aes.h provides a function to prepare the cryptographic context
typedef struct _cipher_ctx cipher_ctx;
typedef void (* cryptoFunc)(byte *, byte *);
typedef struct _cipher_ctx {
    byte * key;
    byte * roundKeys;
    cryptoFunc encryptFunc;
    cryptoFunc decryptFunc;
    unsigned int keySize;
    unsigned int totalRoundKeySize;
    unsigned int stateSize;
} cipher_ctx;

#endif // DEFINITIONS_H_
