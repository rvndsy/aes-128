// This is designed for use with block ciphers that just need a key and a byte-array-state for execution of their respective Cipher and Inverse Cipher functions.

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

// In here are definitions needed for filecrypt.c/.h, utils.c/.h, aes.c/.h and all the good places you want to use them.

typedef unsigned char byte;
//typedef uint32_t word;        //not used as of now

// TODO: Add expanded/round key to context or export it somehow to not re-generate it every round

// Cryptographic context used in crypto algorithms and file encryption that stores the key, iv, chosen function for encryption and decryption
// aes.h provides a function to prepare the cryptographic context
typedef struct _cipher_ctx cipher_ctx;
typedef void (* cryptoFunc)(const cipher_ctx *, byte *);
typedef struct _cipher_ctx {
    unsigned int keySize;
    unsigned int ivSize;
    unsigned int stateSize;
    byte * key;
    cryptoFunc encryptFunc;
    cryptoFunc decryptFunc;
} cipher_ctx;

#endif // DEFINITIONS_H_
