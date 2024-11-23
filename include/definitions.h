// Definitions needed for aes.c/.h, filecrypt.c/.h, utils.c/.h and all the good places you want to use them.
#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

typedef unsigned char byte;
//typedef uint32_t word;        //not used as of now

// TODO: Add expanded key to context or export it somehow to not re-generate it every round

// Cryptographic context used in crypto algorithms and file encryption that stores the key, iv, chosen function for encryption and decryption
// aes.h provides a function to prepare the cryptographic context
typedef struct _cipher_ctx cipher_ctx;
typedef void (* cryptoFunc)(const cipher_ctx *, byte *);
typedef struct _cipher_ctx {
    byte * key;
    unsigned int keySize;
    byte * iv;
    unsigned int ivSize;
    cryptoFunc encryptFunc;
    cryptoFunc decryptFunc;
    unsigned int stateSize;
} cipher_ctx;

#endif // DEFINITIONS_H_
