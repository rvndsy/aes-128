#ifndef AES_H_    // Guard against including twice from the same source
#define AES_H_

#include "definitions.h" //for byte, cipher_ctx

// Functions for managing AES cipher_ctx
void updateAESctx(cipher_ctx *, const byte *, unsigned int);
cipher_ctx * createAESctx(const byte *, unsigned int);
void freeAESctx(cipher_ctx *);

// Encryption and decryption function for a single state
void cipher(byte *, byte *);
void invCipher(byte *, byte *);

// Generate round keys for AES, automatically executed within updateAESctx
void keyExpansion(const byte *, byte *);

#define NB 4            //Number of 32-bit columns for the state/block/text - always 4
#define NB_BYTES 16     //Plaintext/Ciphertext/State size in bytes - always 32*NB/8
#define AES_STATE_SIZE NB_BYTES

#endif // AES_H_
