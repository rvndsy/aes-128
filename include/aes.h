#ifndef AES_H_    // Guard against including twice from the same source
#define AES_H_

#include "definitions.h" //for byte, cipher_ctx

void prepareAESctx(cipher_ctx *, const byte *, const byte *, unsigned int);

void cipher(const cipher_ctx *, byte *);
void invCipher(const cipher_ctx *, byte *);

#define NB 4            //Number of 32-bit columns for the state/block/text - always 4
#define NB_BYTES 16     //Plaintext/Ciphertext/State size in bytes - always 32*NB/8

#endif // AES_H_
